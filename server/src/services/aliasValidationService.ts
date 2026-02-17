/**
 * Alias Cross-Validation Service
 *
 * Validates AI-generated aliases against the full MITRE ATT&CK dataset.
 * Rejects aliases that are confirmed to belong to a DIFFERENT threat actor.
 */

import { getAllMitreAliasMap, normalize, isMitreMalwareOrTool } from './mitreService.js';

interface AliasValidationResult {
  validAliases: string[];
  rejectedAliases: { alias: string; reason: string; belongsTo?: string }[];
}

/**
 * Validate AI-generated aliases against MITRE ATT&CK.
 * Rejects aliases that:
 * 1. Belong to a DIFFERENT MITRE-tracked actor
 * 2. Contain "(overlap)" or "(related)" qualifiers (not real aliases)
 * 3. Are tool/malware names mistakenly included as aliases
 */
export async function validateAliases(
  actorName: string,
  aiAliases: string[],
  mitreAliases: string[]
): Promise<AliasValidationResult> {
  const aliasMap = await getAllMitreAliasMap();

  // Build a set of normalized names that belong to THIS actor
  const ownNames = new Set<string>();
  ownNames.add(normalize(actorName));
  for (const a of mitreAliases) {
    ownNames.add(normalize(a));
  }

  const valid: string[] = [];
  const rejected: { alias: string; reason: string; belongsTo?: string }[] = [];

  for (const alias of aiAliases) {
    const normalizedAlias = normalize(alias);

    // Reject aliases with relationship qualifiers
    if (alias.includes('(overlap)') || alias.includes('(related)') || alias.includes('(possible)')) {
      rejected.push({
        alias,
        reason: 'Relationship qualifier is not a valid alias format',
      });
      continue;
    }

    // Reject aliases that are actually malware/tool names
    if (await isMitreMalwareOrTool(alias)) {
      rejected.push({
        alias,
        reason: 'This is a malware/tool name, not a threat actor alias',
      });
      continue;
    }

    // Check if this alias is claimed by a MITRE actor
    const ownerActorName = aliasMap.get(normalizedAlias);

    if (ownerActorName) {
      const ownerNormalized = normalize(ownerActorName);

      if (ownNames.has(ownerNormalized)) {
        // This alias belongs to our actor — keep it
        valid.push(alias);
      } else {
        // This alias belongs to a DIFFERENT MITRE actor — REJECT
        rejected.push({
          alias,
          reason: `MITRE attributes this to "${ownerActorName}", not "${actorName}"`,
          belongsTo: ownerActorName,
        });
      }
    } else {
      // Not in MITRE — keep it (unverified but not provably wrong)
      valid.push(alias);
    }
  }

  if (rejected.length > 0) {
    console.log(`Alias validation: Rejected ${rejected.length} aliases for "${actorName}":`);
    for (const r of rejected) {
      console.log(`  - "${r.alias}": ${r.reason}`);
    }
  }

  return { validAliases: valid, rejectedAliases: rejected };
}
