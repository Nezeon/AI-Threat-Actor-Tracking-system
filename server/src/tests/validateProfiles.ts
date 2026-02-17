/**
 * Profile Validation Test Script
 *
 * Generates threat actor profiles and validates them against ground truth expectations.
 * Run with: npx tsx server/src/tests/validateProfiles.ts [actorName]
 *
 * Examples:
 *   npx tsx server/src/tests/validateProfiles.ts                    # Test all actors
 *   npx tsx server/src/tests/validateProfiles.ts "Static Tundra"    # Test one actor
 */

import '../env.js';
import { generateActorProfile } from '../services/geminiService.js';

// ============================================================
// Ground Truth Expectations
// ============================================================

interface ExpectedProfile {
  name: string;
  first_seen: string;
  requiredAliases: string[];
  forbiddenAliases: string[];
  requiredCves: string[];
  forbiddenCves: string[];
  minSources: number;
  requiredSourceDomains: string[];
  forbiddenSourcePatterns: string[];
  descriptionMustContain: string[];
  descriptionMustNotContain: string[];
}

const EXPECTED_PROFILES: ExpectedProfile[] = [
  {
    name: "Static Tundra",
    first_seen: "2010",
    requiredAliases: [
      "Dragonfly", "Energetic Bear", "Berserk Bear", "Crouching Yeti",
      "Ghost Blizzard", "IRON LIBERTY", "DYMALLOY", "Group 24"
    ],
    forbiddenAliases: ["APT28", "Fancy Bear", "Sandworm", "APT29"],
    requiredCves: ["CVE-2018-0171"],
    forbiddenCves: ["CVE-2025-55182"],
    minSources: 3,
    requiredSourceDomains: ["blog.talosintelligence.com", "attack.mitre.org"],
    forbiddenSourcePatterns: [],
    descriptionMustContain: ["Russia", "Cisco", "network", "FSB"],
    descriptionMustNotContain: ["DYNOWIPER", "LazyWiper", "Polish energy"],
  },
  {
    name: "ShadyPanda",
    first_seen: "2018",
    requiredAliases: ["nuggetsno15"],
    forbiddenAliases: ["DarkSpectre", "APT41", "Fancy Bear"],
    requiredCves: [],
    forbiddenCves: ["CVE-2025-55182"],
    minSources: 3,
    requiredSourceDomains: ["koi.ai"],
    forbiddenSourcePatterns: [],
    descriptionMustContain: ["browser", "extension", "4.3 million"],
    descriptionMustNotContain: ["state-sponsored", "8.8 million"],
  },
  {
    name: "Earth Baxia",
    first_seen: "2024",
    requiredAliases: [],
    forbiddenAliases: ["APT41", "Winnti", "SHADOW-EARTH-045"],
    requiredCves: ["CVE-2024-36401"],
    forbiddenCves: [],
    minSources: 3,
    requiredSourceDomains: ["trendmicro.com"],
    forbiddenSourcePatterns: [],
    descriptionMustContain: ["China", "GeoServer", "EAGLEDOOR", "Cobalt Strike"],
    descriptionMustNotContain: [],
  },
];

// ============================================================
// Scoring Functions
// ============================================================

interface ScoreResult {
  score: number;
  maxScore: number;
  details: string[];
}

function scoreAliases(profile: any, expected: ExpectedProfile): ScoreResult {
  const aliases: string[] = profile.aliases || [];
  const aliasesLower = aliases.map((a: string) => a.toLowerCase());
  const details: string[] = [];
  let score = 0;
  const maxScore = expected.requiredAliases.length + expected.forbiddenAliases.length;

  for (const req of expected.requiredAliases) {
    if (aliasesLower.includes(req.toLowerCase())) {
      score++;
      details.push(`  PASS: "${req}" found`);
    } else {
      details.push(`  FAIL: "${req}" MISSING`);
    }
  }

  for (const forbidden of expected.forbiddenAliases) {
    if (!aliasesLower.includes(forbidden.toLowerCase())) {
      score++;
      details.push(`  PASS: "${forbidden}" correctly absent`);
    } else {
      details.push(`  FAIL: "${forbidden}" should NOT be present`);
    }
  }

  return { score, maxScore: maxScore || 1, details };
}

function scoreCves(profile: any, expected: ExpectedProfile): ScoreResult {
  const cves: any[] = profile.cves || [];
  const cveIds = cves.map((c: any) => c.id?.toUpperCase());
  const details: string[] = [];
  let score = 0;
  const maxScore = expected.requiredCves.length + expected.forbiddenCves.length;

  for (const req of expected.requiredCves) {
    if (cveIds.includes(req.toUpperCase())) {
      score++;
      details.push(`  PASS: ${req} found`);
    } else {
      details.push(`  FAIL: ${req} MISSING`);
    }
  }

  for (const forbidden of expected.forbiddenCves) {
    if (!cveIds.includes(forbidden.toUpperCase())) {
      score++;
      details.push(`  PASS: ${forbidden} correctly absent`);
    } else {
      details.push(`  FAIL: ${forbidden} should NOT be present (false attribution)`);
    }
  }

  // If no required/forbidden CVEs, check that empty trusted data results in empty CVEs
  if (expected.requiredCves.length === 0 && expected.forbiddenCves.length > 0 && cves.length === 0) {
    details.push(`  PASS: No CVEs (correct for this actor)`);
  }

  return { score, maxScore: maxScore || 1, details };
}

function scoreFirstSeen(profile: any, expected: ExpectedProfile): ScoreResult {
  const details: string[] = [];
  const actual = String(profile.first_seen || '').trim();
  const match = actual.includes(expected.first_seen);

  if (match) {
    details.push(`  PASS: first_seen = "${actual}" (expected: "${expected.first_seen}")`);
  } else {
    details.push(`  FAIL: first_seen = "${actual}" (expected: "${expected.first_seen}")`);
  }

  // Check narrative consistency: description should mention the correct year
  const summaryText = (profile.description?.summary || '').toLowerCase();
  if (summaryText.includes(expected.first_seen)) {
    details.push(`  PASS: Description mentions first_seen year "${expected.first_seen}"`);
  } else {
    details.push(`  WARN: Description may not mention first_seen year "${expected.first_seen}" — check narrative`);
  }

  return { score: match ? 1 : 0, maxScore: 1, details };
}

function scoreSources(profile: any, expected: ExpectedProfile): ScoreResult {
  const sources: any[] = profile.sources || [];
  const details: string[] = [];
  let score = 0;
  let maxScore = 1 + expected.requiredSourceDomains.length + expected.forbiddenSourcePatterns.length;

  // Minimum sources check
  if (sources.length >= expected.minSources) {
    score++;
    details.push(`  PASS: ${sources.length} sources (min: ${expected.minSources})`);
  } else {
    details.push(`  FAIL: ${sources.length} sources (min: ${expected.minSources})`);
  }

  // Required domains
  for (const domain of expected.requiredSourceDomains) {
    const found = sources.some((s: any) => s.url?.includes(domain));
    if (found) {
      score++;
      details.push(`  PASS: Source from ${domain} found`);
    } else {
      details.push(`  FAIL: No source from ${domain}`);
    }
  }

  // Forbidden patterns
  for (const pattern of expected.forbiddenSourcePatterns) {
    const found = sources.some((s: any) => s.url?.includes(pattern));
    if (!found) {
      score++;
      details.push(`  PASS: No source matching "${pattern}"`);
    } else {
      details.push(`  FAIL: Source matching "${pattern}" should not be primary`);
    }
  }

  // Bonus: list all source URLs
  for (const s of sources) {
    details.push(`  INFO: ${s.title} -> ${s.url}`);
  }

  return { score, maxScore: maxScore || 1, details };
}

function scoreDescription(profile: any, expected: ExpectedProfile): ScoreResult {
  const desc = profile.description;
  const fullText = [
    desc?.summary || '',
    desc?.campaigns || '',
    desc?.recent || '',
  ].join(' ').toLowerCase();

  const details: string[] = [];
  let score = 0;
  const maxScore = expected.descriptionMustContain.length + expected.descriptionMustNotContain.length;

  for (const keyword of expected.descriptionMustContain) {
    if (fullText.includes(keyword.toLowerCase())) {
      score++;
      details.push(`  PASS: Description contains "${keyword}"`);
    } else {
      details.push(`  FAIL: Description missing "${keyword}"`);
    }
  }

  for (const keyword of expected.descriptionMustNotContain) {
    if (!fullText.includes(keyword.toLowerCase())) {
      score++;
      details.push(`  PASS: Description does not contain "${keyword}"`);
    } else {
      details.push(`  FAIL: Description should not contain "${keyword}"`);
    }
  }

  return { score, maxScore: maxScore || 1, details };
}

// ============================================================
// Main Test Runner
// ============================================================

async function validateProfile(expected: ExpectedProfile): Promise<{
  name: string;
  totalScore: number;
  maxScore: number;
  percentage: number;
  passed: boolean;
  sections: Record<string, ScoreResult>;
}> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`GENERATING: ${expected.name}`);
  console.log('='.repeat(60));

  const startTime = Date.now();
  let profile: any;

  try {
    profile = await generateActorProfile(expected.name, [], []);
  } catch (error) {
    console.error(`GENERATION FAILED for ${expected.name}:`, error);
    return {
      name: expected.name,
      totalScore: 0,
      maxScore: 100,
      percentage: 0,
      passed: false,
      sections: {},
    };
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`Generated in ${elapsed}s\n`);

  // Output full narrative for manual review
  console.log('--- GENERATED PROFILE NARRATIVE ---');
  console.log(`Name: ${profile.name}`);
  console.log(`First Seen: ${profile.first_seen}`);
  console.log(`Aliases: ${(profile.aliases || []).join(', ') || '(none)'}`);
  console.log(`\nSummary:\n${profile.description?.summary || '(empty)'}`);
  console.log(`\nCampaigns:\n${profile.description?.campaigns || '(empty)'}`);
  console.log(`\nRecent Activity:\n${profile.description?.recent || '(empty)'}`);
  console.log(`\nCVEs: ${(profile.cves || []).map((c: any) => c.id).join(', ') || '(none)'}`);
  console.log('--- END NARRATIVE ---\n');

  // Score each section
  const sections: Record<string, ScoreResult> = {
    aliases: scoreAliases(profile, expected),
    cves: scoreCves(profile, expected),
    first_seen: scoreFirstSeen(profile, expected),
    sources: scoreSources(profile, expected),
    description: scoreDescription(profile, expected),
  };

  // Weighted scoring
  const weights: Record<string, number> = {
    aliases: 25,
    cves: 20,
    first_seen: 10,
    sources: 20,
    description: 25,
  };

  let totalScore = 0;
  const maxScore = 100;

  for (const [section, result] of Object.entries(sections)) {
    const weight = weights[section] || 0;
    const sectionPct = (result.score / result.maxScore) * weight;
    totalScore += sectionPct;

    const pct = ((result.score / result.maxScore) * 100).toFixed(0);
    const status = result.score === result.maxScore ? 'PASS' : 'PARTIAL';
    console.log(`[${status}] ${section.toUpperCase()} (${pct}% — ${result.score}/${result.maxScore}, weight: ${weight}%)`);
    for (const detail of result.details) {
      console.log(detail);
    }
    console.log();
  }

  const percentage = Math.round(totalScore);
  const passed = percentage >= 80;

  console.log('-'.repeat(60));
  console.log(`RESULT: ${expected.name} — ${percentage}% ${passed ? 'PASSED' : 'FAILED'}`);
  console.log('-'.repeat(60));

  return { name: expected.name, totalScore, maxScore, percentage, passed, sections };
}

async function main() {
  const targetActor = process.argv[2];
  const profilesToTest = targetActor
    ? EXPECTED_PROFILES.filter(p => p.name.toLowerCase() === targetActor.toLowerCase())
    : EXPECTED_PROFILES;

  if (profilesToTest.length === 0) {
    console.error(`No expected profile found for "${targetActor}".`);
    console.error(`Available: ${EXPECTED_PROFILES.map(p => p.name).join(', ')}`);
    process.exit(1);
  }

  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║        THREAT ACTOR PROFILE VALIDATION SUITE            ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`Testing ${profilesToTest.length} actor(s)...`);

  const results = [];
  for (const expected of profilesToTest) {
    const result = await validateProfile(expected);
    results.push(result);
  }

  // Summary
  console.log('\n\n' + '═'.repeat(60));
  console.log('                    SUMMARY');
  console.log('═'.repeat(60));
  console.log();

  let allPassed = true;
  for (const r of results) {
    const icon = r.passed ? 'PASS' : 'FAIL';
    console.log(`  [${icon}] ${r.name.padEnd(20)} ${r.percentage}%`);
    if (!r.passed) allPassed = false;
  }

  console.log();
  console.log(allPassed ? 'All tests PASSED.' : 'Some tests FAILED.');
  console.log('═'.repeat(60));

  process.exit(allPassed ? 0 : 1);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
