/**
 * MITRE ATT&CK Integration Service
 *
 * Fetches and caches MITRE ATT&CK Enterprise data from the public GitHub repo.
 * Provides authoritative alias lookups and source URLs for threat actors.
 */

interface MitreIntrusion {
  type: string;
  name: string;
  aliases?: string[];
  first_seen?: string;
  external_references?: {
    source_name: string;
    external_id?: string;
    url?: string;
    description?: string;
  }[];
}

interface MitreActorInfo {
  aliases: string[];
  mitreUrl: string | null;
  firstSeen: string | null;
}

// In-memory cache
let cachedIntrusions: MitreIntrusion[] | null = null;
let cacheTimestamp = 0;
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

const MITRE_DATA_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

/**
 * Fetch MITRE ATT&CK enterprise data and cache in memory.
 */
async function fetchMitreData(): Promise<MitreIntrusion[]> {
  if (cachedIntrusions && Date.now() - cacheTimestamp < CACHE_TTL) {
    return cachedIntrusions;
  }

  try {
    console.log('Fetching MITRE ATT&CK enterprise data...');
    const response = await fetch(MITRE_DATA_URL);

    if (!response.ok) {
      throw new Error(`MITRE fetch failed: ${response.status}`);
    }

    const bundle: any = await response.json();
    cachedIntrusions = bundle.objects.filter(
      (obj: any) => obj.type === 'intrusion-set' && !obj.revoked
    ) as MitreIntrusion[];

    cacheTimestamp = Date.now();
    console.log(`Cached ${cachedIntrusions.length} MITRE intrusion sets`);
    return cachedIntrusions;
  } catch (error) {
    console.error('Failed to fetch MITRE data:', error);
    // Return cached data if available, even if stale
    if (cachedIntrusions) return cachedIntrusions;
    return [];
  }
}

/**
 * Normalize a string for fuzzy matching.
 */
function normalize(str: string): string {
  return str.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Find a MITRE intrusion set by name or alias.
 * Uses fuzzy matching: normalizes both input and MITRE names.
 */
async function findMitreActor(actorName: string): Promise<MitreIntrusion | null> {
  const intrusions = await fetchMitreData();
  const normalizedInput = normalize(actorName);

  for (const intrusion of intrusions) {
    const allNames = [intrusion.name, ...(intrusion.aliases || [])];
    const match = allNames.some(n => {
      const normalizedName = normalize(n);
      return normalizedName === normalizedInput ||
             normalizedName.includes(normalizedInput) ||
             normalizedInput.includes(normalizedName);
    });

    if (match) {
      return intrusion;
    }
  }

  return null;
}

/**
 * Get comprehensive actor info from MITRE: aliases, ATT&CK URL, and first_seen date.
 */
export async function getMitreActorInfo(actorName: string): Promise<MitreActorInfo | null> {
  const intrusion = await findMitreActor(actorName);
  if (!intrusion) return null;

  // Extract MITRE ATT&CK page URL from external references
  let mitreUrl: string | null = null;
  if (intrusion.external_references) {
    const mitreRef = intrusion.external_references.find(
      ref => ref.source_name === 'mitre-attack' && ref.url
    );
    if (mitreRef?.url) {
      mitreUrl = mitreRef.url;
    }
  }

  // Extract first_seen year from STIX field
  let firstSeen: string | null = null;
  if (intrusion.first_seen) {
    // STIX format: "2008-01-01T00:00:00.000Z" → extract year
    const year = intrusion.first_seen.substring(0, 4);
    if (year && !isNaN(parseInt(year))) {
      firstSeen = year;
    }
  }

  return {
    aliases: intrusion.aliases || [],
    mitreUrl,
    firstSeen,
  };
}

/**
 * Get just the aliases for an actor from MITRE.
 */
export async function getMitreAliases(actorName: string): Promise<string[]> {
  const info = await getMitreActorInfo(actorName);
  return info?.aliases || [];
}
