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
let cachedMalwareNames: Set<string> | null = null;
let cacheTimestamp = 0;
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Recent malware families not yet in the MITRE STIX bundle
const KNOWN_MALWARE_FAMILIES = new Set([
  'warlock', 'catb', 'horus', 'bestcrypt',
  'cobaltstrike', 'beacon', 'mimikatz', 'bloodhound', 'rubeus',
].map(s => s.toLowerCase().replace(/[^a-z0-9]/g, '')));

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

    // Extract malware + tool names for alias rejection
    const malwareAndTools = bundle.objects.filter(
      (obj: any) => (obj.type === 'malware' || obj.type === 'tool') && !obj.revoked
    );
    cachedMalwareNames = new Set<string>();
    for (const obj of malwareAndTools) {
      cachedMalwareNames.add(normalize(obj.name));
      if (obj.x_mitre_aliases) {
        for (const alias of obj.x_mitre_aliases) {
          cachedMalwareNames.add(normalize(alias));
        }
      }
    }

    cacheTimestamp = Date.now();
    console.log(`Cached ${cachedIntrusions.length} MITRE intrusion sets, ${cachedMalwareNames.size} malware/tool names`);
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
export function normalize(str: string): string {
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

/**
 * Check if a name is a known malware family or tool (not a threat actor alias).
 * Uses MITRE STIX malware/tool objects + hardcoded recent families.
 */
export async function isMitreMalwareOrTool(name: string): Promise<boolean> {
  await fetchMitreData(); // Ensure cache is populated
  const normalized = normalize(name);
  return (cachedMalwareNames?.has(normalized) || false) || KNOWN_MALWARE_FAMILIES.has(normalized);
}

/**
 * Build a complete map of normalized alias → MITRE actor name.
 * Used for bulk alias cross-validation to detect misattributed aliases.
 */
export async function getAllMitreAliasMap(): Promise<Map<string, string>> {
  const intrusions = await fetchMitreData();
  const map = new Map<string, string>();

  for (const intrusion of intrusions) {
    const allNames = [intrusion.name, ...(intrusion.aliases || [])];
    for (const name of allNames) {
      map.set(normalize(name), intrusion.name);
    }
  }

  return map;
}
