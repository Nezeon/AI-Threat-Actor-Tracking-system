/**
 * URL Validation Service
 *
 * Validates source URLs via HTTP HEAD requests and provides
 * pattern matching for known-stable URL structures.
 */

// URL patterns that are structurally stable and unlikely to break
const STABLE_URL_PATTERNS = [
  /^https:\/\/attack\.mitre\.org\/groups\/G\d+\/?$/,                     // MITRE ATT&CK group pages
  /^https:\/\/attack\.mitre\.org\/software\/S\d+\/?$/,                   // MITRE ATT&CK software pages
  /^https:\/\/malpedia\.caad\.fkie\.fraunhofer\.de\/actor\//,            // Malpedia actor pages
  /^https:\/\/www\.cisa\.gov\//,                                          // CISA pages
  /^https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-/,                       // NVD CVE detail pages
  /^https:\/\/www\.google\.com\/search\?q=/,                              // Google search fallbacks
  /^https:\/\/socradar\.io\/apt-profile-/,                               // SOCRadar apt profiles
  /^https:\/\/www\.mandiant\.com\//,                                     // Mandiant pages
  /^https:\/\/www\.crowdstrike\.com\//,                                  // CrowdStrike pages
  /^https:\/\/cloud\.google\.com\/blog\/topics\/threat-intelligence\//,  // Google threat intel
];

/**
 * Check if a URL matches a known-stable pattern.
 * These URLs are structural (e.g., MITRE ATT&CK group pages) and unlikely to 404.
 */
export function isKnownStableUrl(url: string): boolean {
  return STABLE_URL_PATTERNS.some(pattern => pattern.test(url));
}

/**
 * Validate a list of source URLs by sending HTTP HEAD requests.
 * Returns only the URLs that respond with a 2xx or 3xx status.
 *
 * Features:
 * - 5-second timeout per URL
 * - Concurrent validation via Promise.allSettled
 * - Known-stable URLs skip validation (always pass)
 */
export async function validateUrls(
  sources: { title: string; url: string }[]
): Promise<{ title: string; url: string }[]> {
  if (sources.length === 0) return [];

  const results = await Promise.allSettled(
    sources.map(async (source) => {
      // Known-stable URLs pass without network check
      if (isKnownStableUrl(source.url)) {
        return { ...source, valid: true };
      }

      // Google search URLs always pass
      if (source.url.includes('google.com/search')) {
        return { ...source, valid: true };
      }

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(source.url, {
          method: 'HEAD',
          signal: controller.signal,
          redirect: 'follow',
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; ThreatIntel/1.0)',
          },
        });
        clearTimeout(timeout);

        // Accept 2xx and 3xx status codes
        return {
          ...source,
          valid: response.status < 400,
        };
      } catch {
        // Network error, timeout, or aborted — try GET as fallback
        // Some servers block HEAD but allow GET
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 5000);

          const response = await fetch(source.url, {
            method: 'GET',
            signal: controller.signal,
            redirect: 'follow',
            headers: {
              'User-Agent': 'Mozilla/5.0 (compatible; ThreatIntel/1.0)',
              'Range': 'bytes=0-0', // Minimize data transfer
            },
          });
          clearTimeout(timeout);

          return {
            ...source,
            valid: response.status < 400,
          };
        } catch {
          return { ...source, valid: false };
        }
      }
    })
  );

  const validated: { title: string; url: string }[] = [];
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (result.status === 'fulfilled' && result.value.valid) {
      validated.push({ title: sources[i].title, url: sources[i].url });
    } else {
      console.log(`URL validation failed: ${sources[i].url}`);
    }
  }

  return validated;
}
