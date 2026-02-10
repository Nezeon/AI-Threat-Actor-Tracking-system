import { getPool } from '../config/database.js';
import { ThreatActor } from '../types.js';

// --- Threat Actors ---

export async function getAllActors(): Promise<ThreatActor[]> {
  const pool = getPool();
  const { rows: actors } = await pool.query('SELECT * FROM threat_actors ORDER BY created_at ASC');

  const result: ThreatActor[] = [];
  for (const actor of actors) {
    const cves = await getCvesForActor(actor.id);
    const sources = await getSourcesForActor(actor.id);
    result.push({
      id: actor.id,
      name: actor.name,
      aliases: actor.aliases,
      description: {
        summary: actor.description_summary,
        campaigns: actor.description_campaigns,
        recent: actor.description_recent,
      },
      cves,
      sources,
      lastUpdated: actor.last_updated,
    });
  }
  return result;
}

export async function getActorById(id: string): Promise<ThreatActor | null> {
  const pool = getPool();
  const { rows } = await pool.query('SELECT * FROM threat_actors WHERE id = $1', [id]);
  if (rows.length === 0) return null;

  const actor = rows[0];
  const cves = await getCvesForActor(actor.id);
  const sources = await getSourcesForActor(actor.id);

  return {
    id: actor.id,
    name: actor.name,
    aliases: actor.aliases,
    description: {
      summary: actor.description_summary,
      campaigns: actor.description_campaigns,
      recent: actor.description_recent,
    },
    cves,
    sources,
    lastUpdated: actor.last_updated,
  };
}

export async function createActor(actor: ThreatActor): Promise<ThreatActor> {
  const pool = getPool();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(
      `INSERT INTO threat_actors (id, name, aliases, description_summary, description_campaigns, description_recent, last_updated)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [actor.id, actor.name, JSON.stringify(actor.aliases), actor.description.summary, actor.description.campaigns, actor.description.recent, actor.lastUpdated]
    );

    for (const cve of actor.cves) {
      await client.query(
        `INSERT INTO actor_cves (actor_id, cve_id, description, severity, verification_reference)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (actor_id, cve_id) DO UPDATE SET description = $3, severity = $4, verification_reference = $5`,
        [actor.id, cve.id, cve.description, cve.severity, cve.verificationReference || '']
      );
    }

    for (const source of actor.sources) {
      await client.query(
        `INSERT INTO actor_sources (actor_id, title, url) VALUES ($1, $2, $3)`,
        [actor.id, source.title, source.url]
      );
    }

    await client.query('COMMIT');
    return actor;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function updateActor(id: string, actor: ThreatActor): Promise<ThreatActor> {
  const pool = getPool();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(
      `UPDATE threat_actors SET name = $2, aliases = $3, description_summary = $4, description_campaigns = $5, description_recent = $6, last_updated = $7
       WHERE id = $1`,
      [id, actor.name, JSON.stringify(actor.aliases), actor.description.summary, actor.description.campaigns, actor.description.recent, actor.lastUpdated]
    );

    // Replace CVEs
    await client.query('DELETE FROM actor_cves WHERE actor_id = $1', [id]);
    for (const cve of actor.cves) {
      await client.query(
        `INSERT INTO actor_cves (actor_id, cve_id, description, severity, verification_reference)
         VALUES ($1, $2, $3, $4, $5)`,
        [id, cve.id, cve.description, cve.severity, cve.verificationReference || '']
      );
    }

    // Replace sources
    await client.query('DELETE FROM actor_sources WHERE actor_id = $1', [id]);
    for (const source of actor.sources) {
      await client.query(
        `INSERT INTO actor_sources (actor_id, title, url) VALUES ($1, $2, $3)`,
        [id, source.title, source.url]
      );
    }

    await client.query('COMMIT');
    return actor;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function deleteActor(id: string): Promise<void> {
  const pool = getPool();
  await pool.query('DELETE FROM threat_actors WHERE id = $1', [id]);
}

async function getCvesForActor(actorId: string) {
  const pool = getPool();
  const { rows } = await pool.query('SELECT * FROM actor_cves WHERE actor_id = $1', [actorId]);
  return rows.map(r => ({
    id: r.cve_id,
    description: r.description,
    severity: r.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    verificationReference: r.verification_reference,
  }));
}

async function getSourcesForActor(actorId: string) {
  const pool = getPool();
  const { rows } = await pool.query('SELECT * FROM actor_sources WHERE actor_id = $1', [actorId]);
  return rows.map(r => ({ title: r.title, url: r.url }));
}

// --- Trusted URLs ---

export async function getTrustedUrls(actorName: string) {
  const pool = getPool();
  const normalized = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const { rows } = await pool.query(
    `SELECT * FROM trusted_urls WHERE REPLACE(LOWER(actor_name), ' ', '') LIKE $1`,
    [`%${normalized}%`]
  );
  return rows;
}

export async function addTrustedUrl(actorName: string, url: string) {
  const pool = getPool();
  const { rows } = await pool.query(
    `INSERT INTO trusted_urls (actor_name, url) VALUES ($1, $2) RETURNING id`,
    [actorName.toLowerCase(), url]
  );
  return rows[0];
}

export async function removeTrustedUrl(id: number) {
  const pool = getPool();
  await pool.query('DELETE FROM trusted_urls WHERE id = $1', [id]);
}

// --- Trusted Files ---

export async function getTrustedFiles(actorName: string) {
  const pool = getPool();
  const normalized = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const { rows } = await pool.query(
    `SELECT id, actor_name, file_name, file_type, LENGTH(content) as content_length, created_at FROM trusted_files WHERE REPLACE(LOWER(actor_name), ' ', '') LIKE $1`,
    [`%${normalized}%`]
  );
  return rows;
}

export async function getTrustedFileContents(actorName: string): Promise<{ name: string; content: string }[]> {
  const pool = getPool();
  const normalized = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const { rows } = await pool.query(
    `SELECT file_name, content FROM trusted_files WHERE REPLACE(LOWER(actor_name), ' ', '') LIKE $1`,
    [`%${normalized}%`]
  );
  return rows.map(r => ({ name: r.file_name, content: r.content }));
}

export async function addTrustedFile(actorName: string, fileName: string, fileType: string, content: string, filePath?: string) {
  const pool = getPool();
  const { rows } = await pool.query(
    `INSERT INTO trusted_files (actor_name, file_name, file_type, content, file_path)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (actor_name, file_name) DO UPDATE SET content = $4, file_path = $5
     RETURNING id`,
    [actorName.toLowerCase(), fileName, fileType, content, filePath || null]
  );
  return rows[0];
}

export async function removeTrustedFile(id: number) {
  const pool = getPool();
  await pool.query('DELETE FROM trusted_files WHERE id = $1', [id]);
}

// --- Trusted URL strings for Gemini context ---

export async function getTrustedUrlStrings(actorName: string): Promise<string[]> {
  const rows = await getTrustedUrls(actorName);
  return rows.map(r => r.url);
}

// --- Get all actor names that have trusted sources ---

export async function getAllTrustedActorNames(): Promise<string[]> {
  const pool = getPool();
  const { rows: urlActors } = await pool.query('SELECT DISTINCT actor_name FROM trusted_urls');
  const { rows: fileActors } = await pool.query('SELECT DISTINCT actor_name FROM trusted_files');
  const allNames = new Set([...urlActors.map(r => r.actor_name), ...fileActors.map(r => r.actor_name)]);
  return Array.from(allNames);
}
