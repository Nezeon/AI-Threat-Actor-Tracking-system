import pg from 'pg';
import { INITIAL_THREAT_ACTORS } from '../data/trustedData.js';

const { Pool } = pg;

let pool: pg.Pool;

export function getPool(): pg.Pool {
  if (!pool) throw new Error('Database not initialized');
  return pool;
}

/**
 * Resilient query wrapper — retries once on connection errors.
 * Handles Neon free tier suspension (cold-start) gracefully.
 */
export async function query(text: string, params?: any[]): Promise<pg.QueryResult> {
  const p = getPool();
  try {
    return await p.query(text, params);
  } catch (err: any) {
    const isConnectionError =
      err.message?.includes('Connection terminated') ||
      err.message?.includes('connection terminated') ||
      err.code === 'ECONNRESET' ||
      err.code === 'ECONNREFUSED' ||
      err.code === '57P01'; // Neon admin_shutdown

    if (isConnectionError) {
      console.warn(`DB connection lost (${err.code || err.message}), retrying query...`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      return await p.query(text, params);
    }
    throw err;
  }
}

/**
 * Resilient pool.connect() — retries once on connection errors.
 * Use this for transactional operations that need a dedicated client.
 */
export async function getClient(): Promise<pg.PoolClient> {
  const p = getPool();
  try {
    return await p.connect();
  } catch (err: any) {
    const isConnectionError =
      err.message?.includes('Connection terminated') ||
      err.message?.includes('connection terminated') ||
      err.code === 'ECONNRESET' ||
      err.code === 'ECONNREFUSED' ||
      err.code === '57P01';

    if (isConnectionError) {
      console.warn(`DB connect failed (${err.code || err.message}), retrying...`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      return await p.connect();
    }
    throw err;
  }
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS threat_actors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  first_seen TEXT NOT NULL DEFAULT '',
  aliases JSONB NOT NULL DEFAULT '[]',
  description_summary TEXT NOT NULL DEFAULT '',
  description_campaigns TEXT NOT NULL DEFAULT '',
  description_recent TEXT NOT NULL DEFAULT '',
  last_updated TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS actor_cves (
  id SERIAL PRIMARY KEY,
  actor_id TEXT NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  verification_reference TEXT DEFAULT '',
  UNIQUE(actor_id, cve_id)
);

CREATE TABLE IF NOT EXISTS actor_sources (
  id SERIAL PRIMARY KEY,
  actor_id TEXT NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_urls (
  id SERIAL PRIMARY KEY,
  actor_name TEXT NOT NULL,
  url TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(actor_name, url)
);

CREATE TABLE IF NOT EXISTS trusted_files (
  id SERIAL PRIMARY KEY,
  actor_name TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_type TEXT NOT NULL,
  content TEXT NOT NULL,
  file_path TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(actor_name, file_name)
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK(role IN ('user','model')),
  text TEXT NOT NULL,
  context TEXT,
  timestamp BIGINT NOT NULL
);
`;

export async function initializeDatabase(): Promise<void> {
  const connectionString = process.env.DATABASE_URL || 'postgresql://localhost:5432/threatintel';

  // Neon and most cloud PostgreSQL providers require SSL
  const isProduction = process.env.NODE_ENV === 'production';
  pool = new Pool({
    connectionString,
    ssl: isProduction ? { rejectUnauthorized: false } : undefined,
    max: 5,                        // Neon free tier: fewer connections
    idleTimeoutMillis: 30000,      // Close idle connections after 30s
    connectionTimeoutMillis: 10000, // Fail fast if connection takes >10s
  });

  // Handle background pool errors (e.g., Neon suspending idle connections).
  // Without this, an unhandled 'error' event on the pool can crash the process.
  pool.on('error', (err) => {
    console.error('Unexpected database pool error:', err.message);
  });

  // Test connection
  try {
    await pool.query('SELECT NOW()');
    console.log('Connected to PostgreSQL');
  } catch (err) {
    console.error('Failed to connect to PostgreSQL:', err);
    throw err;
  }

  // Create schema
  await pool.query(SCHEMA_SQL);

  // Migration: add first_seen column if it doesn't exist (for existing databases)
  await pool.query(`ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS first_seen TEXT NOT NULL DEFAULT ''`);

  console.log('Database schema initialized');

  // Seed initial data if empty
  const { rows } = await pool.query('SELECT COUNT(*) as count FROM threat_actors');
  if (parseInt(rows[0].count) === 0) {
    console.log('Seeding initial threat actors...');
    await seedInitialData();
  }
}

async function seedInitialData(): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const actor of INITIAL_THREAT_ACTORS) {
      await client.query(
        `INSERT INTO threat_actors (id, name, first_seen, aliases, description_summary, description_campaigns, description_recent, last_updated)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO NOTHING`,
        [actor.id, actor.name, actor.first_seen || '', JSON.stringify(actor.aliases), actor.description.summary, actor.description.campaigns, actor.description.recent, actor.lastUpdated]
      );

      for (const cve of actor.cves) {
        await client.query(
          `INSERT INTO actor_cves (actor_id, cve_id, description, severity, verification_reference)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (actor_id, cve_id) DO NOTHING`,
          [actor.id, cve.id, cve.description, cve.severity, cve.verificationReference || '']
        );
      }

      for (const source of actor.sources) {
        await client.query(
          `INSERT INTO actor_sources (actor_id, title, url)
           VALUES ($1, $2, $3)`,
          [actor.id, source.title, source.url]
        );
      }
    }

    await client.query('COMMIT');
    console.log('Seeded initial data successfully');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error seeding data:', err);
    throw err;
  } finally {
    client.release();
  }
}
