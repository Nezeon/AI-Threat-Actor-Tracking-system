/**
 * NVD (National Vulnerability Database) Service
 *
 * Validates CVE IDs against the free NVD REST API.
 * Rate limit: 5 requests per 30 seconds (without API key).
 */

interface NvdCveResponse {
  totalResults: number;
  vulnerabilities: {
    cve: {
      id: string;
      descriptions: { lang: string; value: string }[];
      metrics?: {
        cvssMetricV31?: { cvssData: { baseSeverity: string } }[];
      };
    };
  }[];
}

// Rate limiter: ~5 requests per 30s = 6.5s between requests
let lastRequestTime = 0;
const MIN_REQUEST_INTERVAL = 6500;

async function rateLimitedFetch(url: string): Promise<Response> {
  const now = Date.now();
  const timeSinceLastRequest = now - lastRequestTime;

  if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
    await new Promise(resolve => setTimeout(resolve, MIN_REQUEST_INTERVAL - timeSinceLastRequest));
  }

  lastRequestTime = Date.now();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ThreatIntelPlatform/1.0' },
    });
    clearTimeout(timeout);
    return response;
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

/**
 * Validate a batch of CVEs against NVD.
 * Removes CVEs that don't exist and corrects severity from CVSS data.
 * Caps at 10 CVEs to stay within rate limits (~65s max).
 */
export async function validateCveBatch(
  cves: { id: string; description: string; severity: string; verificationReference: string }[],
  actorName: string
): Promise<{
  validated: typeof cves;
  removed: { id: string; reason: string }[];
}> {
  const validated: typeof cves = [];
  const removed: { id: string; reason: string }[] = [];

  const toValidate = cves.slice(0, 10);

  for (const cve of toValidate) {
    // Format check
    if (!/^CVE-\d{4}-\d{4,}$/.test(cve.id)) {
      removed.push({ id: cve.id, reason: 'Invalid CVE ID format' });
      continue;
    }

    try {
      const response = await rateLimitedFetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve.id)}`
      );

      if (!response.ok) {
        // NVD error — keep CVE but don't validate (fail-open)
        validated.push(cve);
        continue;
      }

      const data = await response.json() as NvdCveResponse;

      if (data.totalResults === 0) {
        removed.push({ id: cve.id, reason: 'CVE not found in NVD' });
        continue;
      }

      // CVE exists — correct severity from CVSS if available
      const nvdCve = data.vulnerabilities[0].cve;
      let correctedSeverity = cve.severity;
      if (nvdCve.metrics?.cvssMetricV31?.[0]) {
        correctedSeverity = nvdCve.metrics.cvssMetricV31[0].cvssData.baseSeverity;
      }

      validated.push({
        ...cve,
        severity: correctedSeverity,
        verificationReference: cve.verificationReference ||
          `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      });
    } catch (error) {
      // Network error — keep CVE (fail-open)
      console.error(`NVD validation failed for ${cve.id}:`, error);
      validated.push(cve);
    }
  }

  // Include remaining CVEs beyond the validation limit
  for (const cve of cves.slice(10)) {
    validated.push(cve);
  }

  if (removed.length > 0) {
    console.log(`NVD validation: Removed ${removed.length} invalid CVEs for "${actorName}":`);
    for (const r of removed) {
      console.log(`  - ${r.id}: ${r.reason}`);
    }
  }

  return { validated, removed };
}
