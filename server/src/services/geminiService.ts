import { GoogleGenAI, Type, Schema } from "@google/genai";
import { ThreatActor, NewsItem, GenerationLog, GenerationLogEntry } from '../types.js';
import { TRUSTED_THREAT_DATA } from '../data/trustedData.js';
import { getMitreActorInfo } from './mitreService.js';
import { isKnownStableUrl, validateUrls, isEphemeralUrl } from './urlValidation.js';
import { validateAliases } from './aliasValidationService.js';
import { validateCveBatch } from './nvdService.js';
import * as db from '../models/db.js';

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });
const GEMINI_TIMEOUT_MS = 90_000; // 90 seconds per Gemini API call

// ============================================================
// Helper: Extract grounding metadata URLs from Gemini response
// ============================================================
function extractGroundingUrls(response: any): { title: string; url: string }[] {
  const groundedUrls: { title: string; url: string }[] = [];
  try {
    const candidate = response.candidates?.[0];
    if (candidate?.groundingMetadata?.groundingChunks) {
      for (const chunk of candidate.groundingMetadata.groundingChunks) {
        if (chunk.web?.uri && chunk.web?.title) {
          groundedUrls.push({
            title: chunk.web.title,
            url: chunk.web.uri,
          });
        }
      }
    }
  } catch {
    // Grounding metadata extraction is best-effort
  }
  return groundedUrls;
}

// ============================================================
// Helper: Merge aliases from multiple sources (deduped)
// ============================================================
function mergeAliases(
  aiAliases: string[],
  trustedAliases: string[],
  mitreAliases: string[],
  primaryName: string
): string[] {
  const allAliases = new Set<string>([
    ...aiAliases,
    ...trustedAliases,
    ...mitreAliases,
  ]);

  // Remove the actor's primary name from aliases to avoid duplication
  const normalizedPrimary = primaryName.toLowerCase();
  return Array.from(allAliases).filter(
    a => a.toLowerCase() !== normalizedPrimary && a.trim().length > 0
  );
}

// ============================================================
// Helper: Assemble verified sources from multiple inputs
// ============================================================
function assembleVerifiedSources(
  groundedUrls: { title: string; url: string }[],
  aiSources: { title: string; url: string }[],
  trustedSources: { title: string; url: string }[],
  mitreUrl: string | null,
  actorName: string
): { title: string; url: string }[] {
  const seenUrls = new Set<string>();
  const result: { title: string; url: string }[] = [];
  const googleFallbacks: { title: string; url: string }[] = [];

  const isGoogleSearch = (url: string) => url.includes('google.com/search');

  const addSource = (source: { title: string; url: string }) => {
    const normalized = source.url.replace(/\/$/, '');
    if (seenUrls.has(normalized)) return;
    seenUrls.add(normalized);

    // Separate Google search URLs as low-priority fallbacks
    if (isGoogleSearch(source.url)) {
      googleFallbacks.push(source);
    } else {
      result.push(source);
    }
  };

  // 1. Trusted sources first (highest priority)
  for (const src of trustedSources) {
    addSource(src);
  }

  // 2. MITRE ATT&CK page
  if (mitreUrl) {
    addSource({ title: `MITRE ATT&CK - ${actorName}`, url: mitreUrl });
  }

  // 3. Grounded URLs from Gemini's search (real URLs it actually visited)
  for (const src of groundedUrls) {
    if (!isEphemeralUrl(src.url)) {
      addSource(src);
    }
  }

  // 4. AI-generated sources, but ONLY if they match known-stable patterns and aren't ephemeral
  for (const src of aiSources) {
    if (isKnownStableUrl(src.url) && !isEphemeralUrl(src.url)) {
      addSource(src);
    }
  }

  // 5. Only add Google search fallbacks if we have fewer than 3 real sources
  if (result.length < 3) {
    for (const src of googleFallbacks) {
      result.push(src);
    }
  }

  return result;
}


// ============================================================
// Helper: Attempt to repair truncated JSON from Gemini
// ============================================================
function tryRepairJson(text: string): any {
  // Strategy 1: Maybe it's already valid
  try { return JSON.parse(text); } catch { /* continue */ }

  let repaired = text.trimEnd();

  // Strategy 2: Remove trailing incomplete key-value pairs
  // Common pattern: truncation in the middle of a string value
  // e.g., "title": "MITRE ATT&CK: Lazarus
  repaired = repaired.replace(/,\s*"[^"]*":\s*"[^"]*$/, '');   // trailing "key": "incomplete_value
  repaired = repaired.replace(/,\s*"[^"]*":\s*$/, '');           // trailing "key":
  repaired = repaired.replace(/,\s*"[^"]*$/, '');                // trailing "incomplete_key
  repaired = repaired.replace(/,\s*$/, '');                       // trailing comma

  // Strategy 3: If truncated inside an array of objects (most common for CVEs/sources),
  // remove the last incomplete object from the array
  const lastCompleteObject = repaired.lastIndexOf('},');
  const lastOpenBrace = repaired.lastIndexOf('{');
  if (lastOpenBrace > lastCompleteObject && lastCompleteObject > 0) {
    repaired = repaired.substring(0, lastCompleteObject + 1);
    repaired = repaired.replace(/,\s*$/, '');
  }

  // Strategy 4: Close unclosed strings (balanced quote count)
  const quoteCount = (repaired.match(/(?<!\\)"/g) || []).length;
  if (quoteCount % 2 !== 0) repaired += '"';

  // Strategy 5: Balance brackets and braces
  const openBrackets = (repaired.match(/\[/g) || []).length - (repaired.match(/\]/g) || []).length;
  const openBraces = (repaired.match(/\{/g) || []).length - (repaired.match(/\}/g) || []).length;
  for (let i = 0; i < openBrackets; i++) repaired += ']';
  for (let i = 0; i < openBraces; i++) repaired += '}';

  // Strategy 6: Remove trailing commas before closing brackets/braces (invalid JSON)
  repaired = repaired.replace(/,\s*\]/g, ']');
  repaired = repaired.replace(/,\s*\}/g, '}');

  return JSON.parse(repaired);
}

// ============================================================
// System instruction used for all profile generation
// ============================================================
const SYSTEM_INSTRUCTION = `You are an elite Threat Intelligence Auditor working for a VERIFIED intelligence platform.

CARDINAL RULES (NEVER VIOLATE):
1. IDENTITY INTEGRITY: Never merge, conflate, or confuse two different threat actors. If actors share infrastructure or tooling, describe the RELATIONSHIP in the description, but do NOT list the other group's name as an alias.
2. ALIAS PRECISION: An alias is ONLY a name given to THIS EXACT actor by a security vendor. "APT41 (overlap)" is NOT an alias. Tool names (Cobalt Strike), malware families, and campaign names are NOT aliases. Never use parenthetical qualifiers like "(overlap)" or "(related)".
3. CVE ATTRIBUTION: Only include CVEs that THIS actor has been DIRECTLY observed exploiting. If a CVE was exploited by a RELATED but DIFFERENT group, do NOT include it.
4. TEMPORAL ACCURACY: "first_seen" means the EARLIEST date any security vendor DOCUMENTED this specific actor's activity. Not when the parent organization was founded.
5. SOURCE QUALITY: Never return vertexaisearch.cloud.google.com URLs. Never fabricate URLs. Always prefer REAL vendor blog post URLs, MITRE ATT&CK pages, and Malpedia actor pages over Google Search query URLs. Only use a Google Search query URL as a LAST RESORT when you cannot find any real URL for a source.
6. UNCERTAINTY: If you are less than 80% confident about a fact, omit it rather than include it. However, facts documented by multiple authoritative sources (FBI, CISA, MITRE, named vendor reports) ARE above this threshold — do not omit well-sourced facts.
7. CONTESTED ATTRIBUTION: When an activity, campaign, or CVE is attributed to a CLUSTER NAME different from the requested actor (e.g., Storm-xxxx vs APTxx), you MUST use hedged language in the description: "assessed with moderate confidence", "technical overlaps suggest", "tentatively linked". Do NOT present cluster-based or overlap-based attributions as confirmed facts. If a CVE exploitation is attributed only to an overlapping cluster and not directly to the requested actor, OMIT it from the CVEs list entirely. CRITICAL: If the MAJORITY of the intelligence community (e.g., 2+ major vendors) attributes an event to a DIFFERENT actor, do NOT include that event in this actor's Recent Activity section — even if one source attributes it to this actor. Only include events where this actor is the primary or consensus attribution.
8. ALIAS HIERARCHY: Aliases must be names for THIS SAME operational entity, assigned by different vendors.
   - INCLUDE cross-vendor names: If "Static Tundra" (Cisco Talos) IS the same operational cluster as "Berserk Bear" (CrowdStrike), list them as aliases.
   - EXCLUDE parent umbrella names when this actor is a distinct sub-campaign (e.g., do NOT list "DarkSpectre" as an alias of "ShadyPanda" if ShadyPanda is a campaign WITHIN DarkSpectre).
   - EXCLUDE temporary/unconfirmed designations (SHADOW-xxx, DEV-xxx, TEMP.xxx) unless the vendor confirms identity.
   - For publisher/developer accounts (Chrome Web Store IDs, GitHub handles): include them ONLY if they are widely cited as the actor's primary known identifiers and no traditional vendor aliases exist.
   Describe hierarchical relationships (parent group, sub-campaigns) in the description, not in aliases.
9. MOTIVATION ACCURACY: Do not assume state sponsorship from country attribution alone. If an actor's activities are primarily financial (affiliate fraud, ad fraud, crypto mining, ransomware), describe them as "financially motivated" even if based in a state-associated country. Only use "state-sponsored" when government backing is documented by authoritative sources.
10. VENDOR ATTRIBUTION: When naming which research organization discovered, tracked, or named an actor or campaign, cite ONLY the specific organization confirmed in the original report. Do not guess or fabricate vendor attributions. If Koi Security published the research, say "Koi Security" — not another vendor.
11. TEMPORAL CONSISTENCY: The first_seen year in the JSON output and the "first observed" statement in the description MUST match. If MITRE or trusted data says an actor was first seen in a specific year, use that year in BOTH the structured field AND the narrative text.`;


// ============================================================
// 1. Generate New Threat Actor Profile (Two-Pass Architecture)
// ============================================================
export const generateActorProfile = async (
  actorName: string,
  trustedUrls: string[],
  trustedFiles: { name: string; content: string }[]
): Promise<{ profile: Omit<ThreatActor, 'id' | 'lastUpdated'>; log: GenerationLog }> => {
  const model = 'gemini-3-flash-preview';

  const log: GenerationLog = {
    actorName,
    totalDurationMs: 0,
    groundingUrls: [],
    approvedSources: [],
    trustedFiles: [],
    steps: [],
  };
  const logStart = Date.now();
  let lastStepTime = logStart;

  function addStep(step: string, label: string, description: string): void {
    const now = Date.now();
    log.steps.push({ step, label, description, durationMs: now - lastStepTime });
    lastStepTime = now;
  }

  const cleanInput = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');

  const trustedCsvKey = Object.keys(TRUSTED_THREAT_DATA).find(k => {
    const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    return cleanInput.includes(cleanKey) || cleanKey.includes(cleanInput);
  });

  const trustedCsvData = trustedCsvKey ? TRUSTED_THREAT_DATA[trustedCsvKey] : null;
  const hasUserUrls = trustedUrls.length > 0;
  const hasUserFiles = trustedFiles.length > 0;
  const hasTrustedContext = hasUserUrls || hasUserFiles;

  // Capture user-approved sources for the generation log
  if (hasUserUrls) {
    log.approvedSources.push(...trustedUrls.map(url => ({ title: 'Approved Source', url })));
  }
  if (hasUserFiles) {
    log.trustedFiles = trustedFiles.map(f => f.name);
  }

  // ============================================================
  // PRE-GENERATION: Fetch MITRE context BEFORE calling Gemini
  // ============================================================
  let mitreInfo: Awaited<ReturnType<typeof getMitreActorInfo>> = null;
  try {
    mitreInfo = await getMitreActorInfo(actorName);
  } catch (err) {
    console.error('Pre-generation MITRE lookup failed (non-fatal):', err);
  }

  let mitreContext = '';
  if (mitreInfo) {
    console.log(`Pre-generation: MITRE data found for "${actorName}" — ${mitreInfo.aliases.length} aliases`);
    mitreContext = `
**AUTHORITATIVE MITRE ATT&CK DATA (DO NOT CONTRADICT)**:
- MITRE Registered Name: ${mitreInfo.aliases[0] || actorName}
- MITRE Aliases: [${mitreInfo.aliases.join(', ')}]
- MITRE First Seen: ${mitreInfo.firstSeen || 'Not specified'}
- MITRE ATT&CK URL: ${mitreInfo.mitreUrl || 'N/A'}

CRITICAL CONSTRAINT: The aliases above are CONFIRMED by MITRE ATT&CK.
- Do NOT add aliases that belong to a DIFFERENT MITRE intrusion set.
- Do NOT confuse infrastructure overlaps, shared tooling, or campaign names with aliases.
- You may add aliases NOT in MITRE if you find them in a primary vendor report, but do NOT add any that MITRE attributes to a different group.
`;
  } else {
    console.log(`Pre-generation: "${actorName}" is NOT in MITRE ATT&CK`);
    mitreContext = `
**MITRE ATT&CK STATUS**: This actor is NOT currently tracked in MITRE ATT&CK.
- Be EXTRA conservative with all claims since less authoritative data is available.
- Do NOT fabricate MITRE Group IDs (Gxxxx) or Proofpoint IDs (TAxxx) unless found in a PRIMARY SOURCE during search.
- If you are unsure whether an alias belongs to this actor or a different one, OMIT it.
`;
  }

  addStep('pre_mitre', 'MITRE ATT&CK Lookup',
    mitreInfo
      ? `Found in MITRE ATT&CK: ${mitreInfo.aliases.length} known aliases, first seen ${mitreInfo.firstSeen || 'N/A'}`
      : `"${actorName}" is not tracked in MITRE ATT&CK`
  );

  if (mitreInfo?.mitreUrl) {
    log.approvedSources.push({ title: `MITRE ATT&CK - ${actorName}`, url: mitreInfo.mitreUrl });
  }

  // ============================================================
  // PASS 1: Research — gather raw intelligence with Google Search
  // ============================================================
  console.log(`Pass 1: Researching "${actorName}"...`);

  let researchPrompt = `You are a threat intelligence researcher. Search for ALL available information about the threat actor "${actorName}".

${mitreContext}

RESEARCH OBJECTIVES:
1. Find the EARLIEST documented report of this actor's activity. WHO published it and WHEN?
2. List every vendor-assigned name (alias) you can find, WITH the vendor that assigned each name. Check: Trend Micro (Earth/Water prefixes), Microsoft (Storm/Typhoon/Blizzard/Sleet), CrowdStrike (animal names), Mandiant (APT/UNC), Proofpoint (TA numbers), ESET, Kaspersky, and Malpedia. Even if only one vendor tracks this actor, include that tracking name.
3. List every CVE this actor has been DIRECTLY observed exploiting, WITH the source that documents it.
4. Summarize their major campaigns, tools, and recent activity.
5. Find stable reference URLs (MITRE ATT&CK, Malpedia, CISA, vendor profile pages).
6. HIERARCHICAL CONTEXT: Determine if this actor is a sub-cluster of a larger group, or if it IS the umbrella group. Note parent/child/sibling relationships explicitly. Example: "Static Tundra is a sub-cluster of Energetic Bear (FSB Center 16)" or "DarkSpectre is the parent operation encompassing ShadyPanda, GhostPoster, and Zoom Stealer."
7. For EACH source URL you cite, prefer primary vendor blog posts (Cisco Talos, Trend Micro, ESET, Mandiant, CrowdStrike, etc.). Avoid citing only Google search URLs.

ANTI-CONTAMINATION PROTOCOL:
- Before writing ANY fact, verify: "Is this about ${actorName} specifically, or about a different actor?"
- Common confusion patterns to AVOID:
  * Chinese groups: APT41/Winnti is DISTINCT from APT10/Stone Panda, APT27/Emissary Panda, etc.
  * Russian groups: APT28/Fancy Bear is DISTINCT from APT29/Cozy Bear, Sandworm, Gamaredon, Cadet Blizzard, etc.
  * If "${actorName}" is not well-documented, say so. Do NOT fill gaps with data from better-known actors.
- Each alias must be a vendor-assigned name for THIS EXACT actor. Never include: "(overlap)", "(related)", tool names, or campaign names as aliases.
- Each CVE must have a published report specifically naming "${actorName}" as the exploiting actor.
- CONTESTED ATTRIBUTIONS: If you find activity attributed to a different cluster name (e.g., Storm-xxxx, DEV-xxxx, UNC-xxxx) that has "technical overlaps" with "${actorName}" but is NOT confirmed to be the same actor, clearly mark this in your notes as "CONTESTED" and explain the basis for the linkage. Do NOT treat overlapping clusters as confirmed aliases.
- HIERARCHY MATTERS: If "${actorName}" is a sub-cluster of a larger group, do NOT list the parent group's name as an alias. Instead, note the relationship: "${actorName} is a sub-cluster of [Parent Group]."
- If "${actorName}" is an umbrella group, do NOT list its sub-campaigns as aliases.
- Publisher accounts, GitHub handles, and developer names used to distribute malware are NOT aliases — they are operational identifiers. Note them separately from aliases.
- DATA SCOPE: When an actor is part of a larger operation, report statistics for THIS SPECIFIC actor only. Do not conflate parent-operation totals with sub-campaign numbers. Example: If ShadyPanda affected 4.3M users but the parent DarkSpectre operation affected 8.8M total across 3 campaigns, use 4.3M for ShadyPanda.

OUTPUT FORMAT: Detailed research notes with inline source citations. Be thorough and precise.`;

  if (trustedCsvData) {
    const ids = trustedCsvData.cves.map(c => c.id).join(", ");
    researchPrompt += `\n\nGROUND TRUTH (INTERNAL DB): Verified CVEs for this actor: [${ids}]. Acknowledge these in your research.`;
  }

  if (hasUserFiles) {
    researchPrompt += `\n\nTRUSTED FILE CONTEXT:\n${trustedFiles.map((f, i) => `--- FILE ${i+1}: ${f.name} ---\n${f.content.substring(0, 500000)}\n--- END FILE ---`).join('\n\n')}`;
  }

  if (hasTrustedContext && trustedUrls.length > 0) {
    researchPrompt += `\n\nAPPROVED URLS:\n${trustedUrls.map(u => `- ${u}`).join('\n')}`;
  }

  const researchResponse = await ai.models.generateContent({
    model,
    contents: researchPrompt,
    config: {
      tools: [{ googleSearch: {} }],
      maxOutputTokens: 8192,
      temperature: 0,
      systemInstruction: "You are a meticulous threat intelligence researcher. Your job is ONLY to gather facts, not generate structured output. Cite sources for every claim. Never confuse one threat actor with another.",
      httpOptions: { timeout: GEMINI_TIMEOUT_MS },
    }
  });

  const researchNotes = researchResponse.text || '';
  const researchGroundedUrls = extractGroundingUrls(researchResponse);
  console.log(`Pass 1 complete: ${researchNotes.length} chars, ${researchGroundedUrls.length} grounded URLs`);

  addStep('pass1_research', 'Pass 1: AI Research',
    `Gathered ${researchNotes.length} chars of research notes from ${researchGroundedUrls.length} web sources`
  );

  // ============================================================
  // PASS 2: Structure — convert research into validated JSON
  // ============================================================
  console.log(`Pass 2: Structuring profile for "${actorName}"...`);

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      name: { type: Type.STRING },
      first_seen: {
        type: Type.STRING,
        description: "Year first observed. Format: 'YYYY' or 'at least YYYY'."
      },
      aliases: { type: Type.ARRAY, items: { type: Type.STRING } },
      description: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING, description: "MUST include: country of origin/attribution, first observed date, capability, motive, targeting pattern. Always name the country." },
          campaigns: { type: Type.STRING, description: "Campaigns, tool sets, TTPs, malwares, collaborations. Name specific CVEs exploited and specific tools used." },
          recent: { type: Type.STRING, description: "Latest campaign, recent operational/behavioral changes." }
        },
        required: ["summary", "campaigns", "recent"]
      },
      cves: {
        type: Type.ARRAY,
        items: {
          type: Type.OBJECT,
          properties: {
            id: { type: Type.STRING },
            description: { type: Type.STRING },
            severity: { type: Type.STRING, enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
            verificationReference: { type: Type.STRING }
          },
          required: ["id", "description", "severity", "verificationReference"]
        }
      },
      sources: {
        type: Type.ARRAY,
        items: {
          type: Type.OBJECT,
          properties: {
            title: { type: Type.STRING },
            url: { type: Type.STRING }
          },
          required: ["title", "url"]
        }
      }
    },
    required: ["name", "first_seen", "aliases", "description", "cves", "sources"]
  };

  let structurePrompt = `Based on the following VERIFIED RESEARCH NOTES, generate a structured threat actor profile for "${actorName}".

--- RESEARCH NOTES ---
${researchNotes}
--- END RESEARCH NOTES ---

${mitreContext}

STRICT RULES:
1. Use ONLY facts that appear in the research notes above.
2. Do NOT add information not present in the notes.
3. For aliases: include only vendor-assigned names. No tool names, campaign names, or "(overlap)" qualifiers.
4. For CVEs: include only those with clear attribution to "${actorName}" in the notes.
5. For sources: prefer MITRE ATT&CK, Malpedia, CISA, and vendor profile page URLs.
6. Do NOT include any vertexaisearch.cloud.google.com URLs.
7. The first sentence of 'summary' MUST state the "First Observed" year/date.
8. CONTESTED ACTIVITY: If the research notes mark any activity as "CONTESTED" or attributed to an overlapping cluster (not confirmed same actor), use hedged language like "assessed with moderate confidence" or "tentatively attributed" in the description. Do NOT include contested CVEs in the cves array.
9. ALIAS HIERARCHY: Include cross-vendor names for THIS SAME entity (e.g., if this actor IS known as Berserk Bear by CrowdStrike, include it). Do NOT include:
   a. Parent umbrella names when this actor is a distinct sub-campaign
   b. Temporary intrusion set IDs (SHADOW-xxx, DEV-xxx) unless confirmed same actor
   c. Sub-campaign names below the actor level
   Include publisher/developer accounts ONLY when they are the primary known identifiers.
10. SOURCE DIVERSITY: Include at least 3-5 source URLs. Prefer vendor research blog posts (Cisco Talos, Trend Micro, ESET, Mandiant, CrowdStrike, etc.) over generic search URLs. Include the Malpedia actor page URL if it exists.`;

  if (!mitreInfo) {
    structurePrompt += `\n\nIMPORTANT: This actor is NOT in MITRE ATT&CK. Extract ALL vendor-assigned names mentioned in the research notes as aliases. Look for names from: Trend Micro (Earth/Water prefixes), Microsoft (Storm/Typhoon/Blizzard), CrowdStrike (animal names), Mandiant (APT/UNC numbers), and any other vendor tracking names found in the notes.`;
  }

  if (hasTrustedContext && trustedUrls.length > 0) {
    structurePrompt += `\n\nAPPROVED URLS (include in sources):\n${trustedUrls.map(u => `- ${u}`).join('\n')}`;
  }

  try {
    // Pass 2 with retry: first attempt at 32k tokens, retry at 64k if truncated
    let parsedData: any = null;
    let allGroundedUrls = [...researchGroundedUrls];
    let lastTruncatedText = '';

    for (const attempt of [{ tokens: 32768, label: '1st' }, { tokens: 65536, label: 'retry' }]) {
      const structuredResponse = await ai.models.generateContent({
        model,
        contents: structurePrompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: schema,
          maxOutputTokens: attempt.tokens,
          temperature: 0,
          systemInstruction: SYSTEM_INSTRUCTION,
          httpOptions: { timeout: GEMINI_TIMEOUT_MS },
        }
      });

      const text = structuredResponse.text;
      if (!text) throw new Error("No response from AI");

      const structuredGroundedUrls = extractGroundingUrls(structuredResponse);
      allGroundedUrls = [...researchGroundedUrls, ...structuredGroundedUrls];
      console.log(`Pass 2 (${attempt.label}): ${allGroundedUrls.length} grounded URLs, ${text.length} chars`);

      try {
        parsedData = JSON.parse(text);
        break; // Success — exit retry loop
      } catch (parseError) {
        console.warn(`Pass 2 (${attempt.label}): JSON parse failed, ${attempt.label === 'retry' ? 'attempting repair' : 'retrying with higher token limit'}...`);
        lastTruncatedText = text;
        if (attempt.label === 'retry') {
          // Last attempt — try to repair truncated JSON mechanically
          try {
            parsedData = tryRepairJson(text);
            console.log('Pass 2: JSON repair succeeded');
            break;
          } catch {
            console.error('Pass 2: JSON repair also failed. Truncated response:', text.substring(text.length - 200));
            // Fall through to Gemini completion fallback below
          }
        }
      }
    }

    // Fallback: Ask Gemini to complete the truncated JSON
    if (!parsedData && lastTruncatedText) {
      console.log('Pass 2 fallback: Asking Gemini to complete truncated JSON...');
      try {
        const completionResponse = await ai.models.generateContent({
          model,
          contents: `The following JSON was truncated mid-generation. Complete it by closing any open strings, arrays, and objects. Return ONLY valid JSON — do not add new data, just close the structure properly.\n\nTruncated JSON:\n${lastTruncatedText.substring(0, 30000)}`,
          config: {
            responseMimeType: "application/json",
            maxOutputTokens: 8192,
            temperature: 0,
            httpOptions: { timeout: GEMINI_TIMEOUT_MS },
          }
        });
        const completedText = completionResponse.text;
        if (completedText) {
          parsedData = JSON.parse(completedText);
          console.log('Pass 2 fallback: Gemini JSON completion succeeded');
        }
      } catch (completionError) {
        console.error('Pass 2 fallback: Gemini JSON completion also failed:', completionError);
      }
    }

    if (!parsedData) throw new Error("Failed to parse structured response after all retries and repair attempts");

    log.groundingUrls = allGroundedUrls.filter(u => !isEphemeralUrl(u.url));
    addStep('pass2_structure', 'Pass 2: Structure Profile',
      `Parsed structured JSON. ${allGroundedUrls.length} total grounding URLs collected across both passes.`
    );

    // ============================================================
    // POST-GENERATION VALIDATION PIPELINE
    // ============================================================

    // --- Step 1: Trusted CSV data overrides ---
    if (trustedCsvData) {
      console.log(`Step 1: Applying trusted CSV validation for ${actorName}`);

      parsedData.cves = trustedCsvData.cves.map(trustedCve => {
        const aiFound = parsedData.cves.find((aiCve: any) => aiCve.id === trustedCve.id);
        return {
          id: trustedCve.id,
          description: aiFound?.description || "Vulnerability confirmed via Trusted Intelligence CSV.",
          severity: aiFound?.severity || "HIGH",
          verificationReference: trustedCve.verificationReference
        };
      });

      if (trustedCsvData.first_seen) {
        parsedData.first_seen = trustedCsvData.first_seen;
      }

      if (trustedCsvData.aliases) {
        parsedData.aliases = mergeAliases(
          parsedData.aliases || [],
          trustedCsvData.aliases,
          [],
          parsedData.name
        );
      }

      // Remove forbidden aliases (parent groups, misattributed names)
      if (trustedCsvData.forbiddenAliases && trustedCsvData.forbiddenAliases.length > 0) {
        const forbiddenSet = new Set(trustedCsvData.forbiddenAliases.map(a => a.toLowerCase()));
        const before = parsedData.aliases?.length || 0;
        parsedData.aliases = (parsedData.aliases || []).filter(
          (a: string) => !forbiddenSet.has(a.toLowerCase())
        );
        const removed = before - (parsedData.aliases?.length || 0);
        if (removed > 0) {
          console.log(`Step 1: Removed ${removed} forbidden alias(es) for ${actorName}`);
        }
      }
      addStep('step1_csv', 'Step 1: Trusted Data Override',
        `Applied ground-truth: ${trustedCsvData.cves.length} CVEs, ${trustedCsvData.aliases?.length ?? 0} aliases, first_seen=${trustedCsvData.first_seen || 'unchanged'}`
      );
      if (trustedCsvData.sources) {
        for (const src of trustedCsvData.sources) {
          if (!log.approvedSources.some(s => s.url === src.url)) {
            log.approvedSources.push(src);
          }
        }
      }
    } else if (hasTrustedContext) {
      const existingUrls = new Set(parsedData.sources.map((s: any) => s.url));
      trustedUrls.forEach(url => {
        if (!existingUrls.has(url)) {
          parsedData.sources.unshift({ title: 'Approved Platform Source', url: url });
        }
      });
      addStep('step1_csv', 'Step 1: Trusted Sources',
        `No CSV ground-truth. Added ${trustedUrls.length} user-approved URLs as priority sources.`
      );
    } else {
      addStep('step1_csv', 'Step 1: Trusted Data Override', 'No trusted data available for this actor. Skipped.');
    }

    // --- Step 2: MITRE ATT&CK enrichment + alias cross-validation ---
    if (mitreInfo) {
      console.log(`Step 2: MITRE enrichment — ${mitreInfo.aliases.length} aliases, URL: ${mitreInfo.mitreUrl}`);

      // Cross-validate AI aliases against MITRE before merging
      // Include trusted aliases as "own" names alongside MITRE aliases
      const { validAliases, rejectedAliases } = await validateAliases(
        actorName,
        parsedData.aliases || [],
        [...mitreInfo.aliases, ...(trustedCsvData?.aliases || [])]
      );

      parsedData.aliases = mergeAliases(
        validAliases,
        trustedCsvData?.aliases || [],
        mitreInfo.aliases,
        parsedData.name
      );

      if (!trustedCsvData?.first_seen && mitreInfo.firstSeen) {
        parsedData.first_seen = mitreInfo.firstSeen;
      }

      parsedData.sources = assembleVerifiedSources(
        allGroundedUrls,
        parsedData.sources || [],
        trustedCsvData?.sources || [],
        mitreInfo.mitreUrl,
        parsedData.name
      );

      addStep('step2_mitre', 'Step 2: MITRE Enrichment',
        `Merged ${mitreInfo.aliases.length} MITRE aliases. Cross-validation: ${validAliases.length} valid, ${rejectedAliases.length} rejected.`
      );
    } else {
      console.log(`Step 2: No MITRE data — validating aliases against MITRE to catch misattributions`);

      // Even without MITRE match for this actor, validate aliases against full MITRE dataset
      // Pass trusted aliases as "own" names so they aren't rejected by cross-validation
      const { validAliases, rejectedAliases } = await validateAliases(
        actorName,
        parsedData.aliases || [],
        trustedCsvData?.aliases || []
      );
      parsedData.aliases = validAliases.filter(
        a => a.toLowerCase() !== parsedData.name.toLowerCase() && a.trim().length > 0
      );

      if (allGroundedUrls.length > 0) {
        parsedData.sources = assembleVerifiedSources(
          allGroundedUrls,
          parsedData.sources || [],
          trustedCsvData?.sources || [],
          null,
          parsedData.name
        );
      } else if (trustedCsvData?.sources) {
        const existingUrls = new Set(parsedData.sources.map((s: any) => s.url));
        const newSources = trustedCsvData.sources.filter(s => !existingUrls.has(s.url));
        parsedData.sources = [...newSources, ...parsedData.sources];
      }

      addStep('step2_mitre', 'Step 2: Alias Validation',
        `No MITRE match. Cross-validated aliases: ${validAliases.length} valid, ${rejectedAliases.length} rejected.`
      );
    }

    // --- Step 2.5: CVE validation via NVD ---
    if (!trustedCsvData && parsedData.cves && parsedData.cves.length > 0) {
      try {
        console.log(`Step 2.5: Validating ${parsedData.cves.length} CVEs against NVD...`);
        const cveCountBefore = parsedData.cves.length;
        const { validated, removed } = await validateCveBatch(parsedData.cves, actorName);
        parsedData.cves = validated;
        if (removed.length > 0) {
          console.log(`NVD validation removed ${removed.length} CVEs`);
        }
        addStep('step2_5_nvd', 'Step 2.5: NVD CVE Validation',
          `Checked ${cveCountBefore} CVEs against NVD. ${validated.length} confirmed, ${removed.length} removed.`
        );
      } catch (nvdError) {
        console.error('NVD validation failed (non-fatal):', nvdError);
        addStep('step2_5_nvd', 'Step 2.5: NVD CVE Validation', 'NVD validation failed (non-fatal). CVEs kept as-is.');
      }
    } else if (trustedCsvData) {
      addStep('step2_5_nvd', 'Step 2.5: NVD CVE Validation', 'Skipped — using trusted CSV CVEs.');
    } else {
      addStep('step2_5_nvd', 'Step 2.5: NVD CVE Validation', 'Skipped — no CVEs to validate.');
    }

    // --- Step 3: URL validation (remove dead links) ---
    const urlCountBefore = parsedData.sources?.length ?? 0;
    try {
      const validatedSources = await validateUrls(parsedData.sources || []);
      parsedData.sources = validatedSources;
      addStep('step3_urls', 'Step 3: URL Validation',
        `Tested ${urlCountBefore} source URLs. ${validatedSources.length} alive, ${urlCountBefore - validatedSources.length} removed.`
      );
    } catch (validationError) {
      console.error('URL validation failed (non-fatal):', validationError);
      addStep('step3_urls', 'Step 3: URL Validation', 'URL validation failed (non-fatal). Sources kept as-is.');
    }

    // --- Step 4: Ensure minimum sources ---
    const sourcesBeforeStep4 = parsedData.sources?.length ?? 0;
    if (!parsedData.sources || parsedData.sources.length < 3) {
      parsedData.sources = parsedData.sources || [];
      const existingUrls = new Set(parsedData.sources.map((s: any) => s.url));

      // Add Malpedia actor page
      const malpediaUrl = `https://malpedia.caad.fkie.fraunhofer.de/actor/${actorName.toLowerCase().replace(/\s+/g, '_')}`;
      if (!existingUrls.has(malpediaUrl)) {
        parsedData.sources.push({ title: `Malpedia: ${actorName}`, url: malpediaUrl });
      }

      // Add Google search fallback
      const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(actorName)}+threat+intelligence`;
      if (!existingUrls.has(googleUrl)) {
        parsedData.sources.push({ title: `Search - ${actorName} threat intelligence`, url: googleUrl });
      }
    }

    addStep('step4_sources', 'Step 4: Minimum Sources',
      sourcesBeforeStep4 >= 3
        ? `${parsedData.sources.length} sources. Minimum threshold met.`
        : `Only ${sourcesBeforeStep4} sources — added fallbacks to reach ${parsedData.sources.length}.`
    );

    if (!parsedData.first_seen) {
      parsedData.first_seen = 'Unknown';
    }

    log.totalDurationMs = Date.now() - logStart;

    return { profile: parsedData, log };
  } catch (error) {
    console.error("Error generating profile:", error);
    throw error;
  }
};

// ============================================================
// 2. Granular Refresh (with MITRE pre-injection + validation)
// ============================================================
export const refreshActorSection = async (
  actorName: string,
  section: 'ALIASES' | 'DESCRIPTION' | 'CVES'
): Promise<any> => {
  const model = 'gemini-3-flash-preview';

  // --- Pre-fetch MITRE context and trusted data ---
  let mitreInfo: Awaited<ReturnType<typeof getMitreActorInfo>> = null;
  try {
    mitreInfo = await getMitreActorInfo(actorName);
  } catch {
    // MITRE lookup failure is non-fatal
  }

  let mitreContext = '';
  if (mitreInfo) {
    mitreContext = `
**AUTHORITATIVE MITRE ATT&CK DATA (DO NOT CONTRADICT)**:
- MITRE Registered Name: ${mitreInfo.aliases[0] || actorName}
- MITRE Aliases: [${mitreInfo.aliases.join(', ')}]
- MITRE First Seen: ${mitreInfo.firstSeen || 'Not specified'}
- MITRE ATT&CK URL: ${mitreInfo.mitreUrl || 'N/A'}

CRITICAL: Do NOT add aliases belonging to a DIFFERENT MITRE intrusion set. Do NOT confuse overlapping infrastructure with identity.
`;
  } else {
    mitreContext = `
**MITRE ATT&CK STATUS**: "${actorName}" is NOT currently tracked in MITRE ATT&CK.
- Be EXTRA conservative. Do NOT fabricate MITRE Group IDs (Gxxxx) or Proofpoint IDs (TAxxx) unless found in a primary source.
- If unsure whether an alias belongs to this actor or a different one, OMIT it.
`;
  }

  const cleanInput = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const trustedCsvKey = Object.keys(TRUSTED_THREAT_DATA).find(k => {
    const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    return cleanInput.includes(cleanKey) || cleanKey.includes(cleanInput);
  });
  const trustedCsvData = trustedCsvKey ? TRUSTED_THREAT_DATA[trustedCsvKey] : null;

  // --- Build section-specific prompt and schema ---
  let prompt = `Focus exclusively on the "${section}" for threat actor: "${actorName}".

${mitreContext}

ANTI-CONTAMINATION: Before writing ANY fact, verify it is about "${actorName}" specifically, not a different actor.
`;
  let schema: Schema = { type: Type.OBJECT, properties: {}, required: [] };

  if (section === 'ALIASES') {
    prompt += `
Task: Perform a deep search on MITRE, Malpedia, CISA, and vendor blogs (Microsoft, CrowdStrike, FireEye, Secureworks).

OBJECTIVE: List ALL known aliases (vendor-assigned names for THIS EXACT actor).

MAPPING GUIDE:
- Microsoft: Weather/Sleet/Typhoon names (e.g. Midnight Blizzard, Volt Typhoon)
- CrowdStrike: Animal names (e.g. Fancy Bear, Wicked Panda)
- Mandiant: APTxx, UNCxxxx
- Proofpoint: TAxxx

CRITICAL EXCLUSION RULES:
1. DO NOT include tools or malware names (e.g. Cobalt Strike, Mimikatz).
2. DO NOT include parent organizations (e.g. GRU, MSS) unless used as the actor name.
3. DO NOT include "(overlap)", "(related)", or any parenthetical qualifiers.
4. Each alias must be a name assigned to THIS EXACT actor by a security vendor.

Return a simple array of unique strings.`;

    schema = {
      type: Type.OBJECT,
      properties: {
        aliases: { type: Type.ARRAY, items: { type: Type.STRING } }
      },
      required: ["aliases"]
    };
  } else if (section === 'DESCRIPTION') {
    prompt += `
Task: Re-evaluate the threat profile history and tactics for "${actorName}".
1. Summary: **MANDATORY**: State "First observed in [Year]" at the start. Confirm this date across multiple vendors.
2. Campaigns: List major historical campaigns and toolsets used by THIS actor.
3. Recent: Focus on activity within the last 12 months.

CRITICAL: Do NOT include campaigns or TTPs from a different actor, even if they are related.`;

    schema = {
      type: Type.OBJECT,
      properties: {
        first_seen: {
          type: Type.STRING,
          description: "Year first observed. Format: 'YYYY' or 'at least YYYY'."
        },
        description: {
          type: Type.OBJECT,
          properties: {
            summary: { type: Type.STRING },
            campaigns: { type: Type.STRING },
            recent: { type: Type.STRING }
          },
          required: ["summary", "campaigns", "recent"]
        }
      },
      required: ["first_seen", "description"]
    };
  } else if (section === 'CVES') {
    prompt += `
Task: Find ALL CVEs that "${actorName}" has been DIRECTLY observed exploiting.
- Search for CISA advisories, vendor reports, and threat intelligence publications.
- Only include CVEs with a published report specifically naming "${actorName}" as the exploiting actor.
- Do NOT include CVEs exploited by a RELATED but DIFFERENT group.
- **VERIFICATION**: Provide a valid reference URL. If a direct report link is unstable, use a Google Search Query URL (e.g., "https://www.google.com/search?q=${actorName}+CVE-xxxx-xxxx").`;

    schema = {
      type: Type.OBJECT,
      properties: {
        cves: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              id: { type: Type.STRING },
              description: { type: Type.STRING },
              severity: { type: Type.STRING, enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
              verificationReference: { type: Type.STRING }
            },
            required: ["id", "description", "severity", "verificationReference"]
          }
        }
      },
      required: ["cves"]
    };
  }

  try {
    const response = await ai.models.generateContent({
      model,
      contents: prompt,
      config: {
        tools: [{ googleSearch: {} }],
        responseMimeType: "application/json",
        responseSchema: schema,
        temperature: 0,
        systemInstruction: SYSTEM_INSTRUCTION,
        httpOptions: { timeout: GEMINI_TIMEOUT_MS },
      }
    });

    const parsed = JSON.parse(response.text || "{}");

    // --- Post-processing for ALIASES section ---
    if (section === 'ALIASES' && parsed.aliases) {
      const trustedAliases = trustedCsvData?.aliases || [];

      // Cross-validate AI aliases against MITRE to catch misattributions
      const { validAliases } = await validateAliases(
        actorName,
        parsed.aliases,
        mitreInfo?.aliases || []
      );

      parsed.aliases = mergeAliases(
        validAliases,
        trustedAliases,
        mitreInfo?.aliases || [],
        actorName
      );
    }

    // --- Post-processing for DESCRIPTION section ---
    if (section === 'DESCRIPTION') {
      // Override first_seen with ground truth if available
      if (trustedCsvData?.first_seen) {
        parsed.first_seen = trustedCsvData.first_seen;
      } else if (mitreInfo?.firstSeen) {
        parsed.first_seen = mitreInfo.firstSeen;
      }
    }

    // --- Post-processing for CVES section ---
    if (section === 'CVES' && parsed.cves) {
      // Use grounding URLs for verification references
      const groundedUrls = extractGroundingUrls(response);
      if (groundedUrls.length > 0) {
        for (const cve of parsed.cves) {
          const matchingUrl = groundedUrls.find(g =>
            g.url.toLowerCase().includes(cve.id.toLowerCase().replace(/-/g, '')) ||
            g.title.toLowerCase().includes(cve.id.toLowerCase())
          );
          if (matchingUrl) {
            cve.verificationReference = matchingUrl.url;
          }
        }
      }

      // Override with trusted CSV CVEs if available
      if (trustedCsvData) {
        parsed.cves = trustedCsvData.cves.map(trustedCve => {
          const aiFound = parsed.cves.find((aiCve: any) => aiCve.id === trustedCve.id);
          return {
            id: trustedCve.id,
            description: aiFound?.description || "Vulnerability confirmed via Trusted Intelligence CSV.",
            severity: aiFound?.severity || "HIGH",
            verificationReference: trustedCve.verificationReference
          };
        });
      } else {
        // Validate CVEs against NVD
        try {
          console.log(`Refresh CVES: Validating ${parsed.cves.length} CVEs against NVD...`);
          const { validated, removed } = await validateCveBatch(parsed.cves, actorName);
          parsed.cves = validated;
          if (removed.length > 0) {
            console.log(`Refresh CVES: NVD removed ${removed.length} invalid CVEs`);
          }
        } catch (nvdError) {
          console.error('Refresh CVES: NVD validation failed (non-fatal):', nvdError);
        }
      }
    }

    return parsed;
  } catch (error) {
    console.error(`Error refreshing section ${section}:`, error);
    throw error;
  }
};

// ============================================================
// 3. Chat Functionality
// ============================================================
export const chatWithAI = async (message: string, context?: string): Promise<string> => {
  const model = 'gemini-3-flash-preview';

  // Retrieve trusted context from database
  const allActorNames = await db.getAllTrustedActorNames();
  const foundContexts: string[] = [];

  for (const actorName of allActorNames) {
    if (message.toLowerCase().includes(actorName.toLowerCase())) {
      const urls = await db.getTrustedUrlStrings(actorName);
      const files = await db.getTrustedFileContents(actorName);

      if (urls.length > 0 || files.length > 0) {
        let ctx = `\n--- APPROVED INTELLIGENCE FOR: ${actorName.toUpperCase()} ---`;
        if (urls.length > 0) {
          ctx += `\n[TRUSTED URLs]:\n${urls.map(u => `- ${u}`).join('\n')}`;
        }
        if (files.length > 0) {
          ctx += `\n[TRUSTED DOCUMENTS]:\n${files.map(f => `FILE: ${f.name}\nCONTENT START:\n${f.content.substring(0, 15000)}...\nCONTENT END`).join('\n\n')}`;
        }
        foundContexts.push(ctx);
      }
    }
  }

  const trustedContext = foundContexts.join('\n\n');

  let systemInstruction = context
    ? `You are HivePro's Expert AI Analyst. The user is analyzing: ${context}.`
    : "You are HivePro's Expert AI Analyst. Answer cybersecurity questions with high accuracy.";

  systemInstruction += `\nRULES:
       1. Provide precise, evidence-based answers.
       2. If you don't know, state "I cannot verify this information currently."
       3. Use Google Search to validate any specific claims about CVEs or Attacks.`;

  if (trustedContext) {
    systemInstruction += `\n\n*** CRITICAL: TRUSTED SOURCES DETECTED ***
    The user has provided Trusted Intelligence Sources (Files/URLs) for the entities mentioned in the query.
    You MUST prioritize the information below over general knowledge or search results.

    ${trustedContext}

    INSTRUCTION:
    - Use the data above as the primary truth.
    - If the answer is in the documents/URLs, cite them.
    `;
  }

  try {
    const response = await ai.models.generateContent({
      model,
      contents: message,
      config: {
        tools: [{ googleSearch: {} }],
        systemInstruction,
        temperature: 0,
        httpOptions: { timeout: GEMINI_TIMEOUT_MS },
      }
    });
    return response.text || "I couldn't generate a response.";
  } catch (error) {
    console.error("Chat error:", error);
    return "Error communicating with AI service.";
  }
};

// ============================================================
// 4. Live News Feed
// ============================================================
export const getLiveCyberNews = async (): Promise<NewsItem[]> => {
  const model = 'gemini-3-flash-preview';

  const prompt = `Act as a Critical News Aggregator.
  1. Search for CONFIRMED cybersecurity incidents from the last 7 days.
  2. Focus on:
     - Confirmed Data Breaches (verified by victim or reputable journalist).
     - Active exploitation of Critical CVEs (CISA KEV).
     - New APT campaigns with technical reports.
  3. Filter out: Speculation, marketing fluff, and unverified rumors.
  4. Return a summarized list with valid source URLs.`;

  try {
    const response = await ai.models.generateContent({
      model,
      contents: prompt,
      config: {
        tools: [{ googleSearch: {} }],
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING },
              summary: { type: Type.STRING },
              source: { type: Type.STRING },
              url: { type: Type.STRING },
              date: { type: Type.STRING }
            },
            required: ["title", "summary", "source", "url"]
          }
        },
        temperature: 0.1,
        httpOptions: { timeout: GEMINI_TIMEOUT_MS },
      }
    });

    const text = response.text;
    if (!text) return [];

    const parsed = JSON.parse(text);

    // For news, also try to use grounded URLs
    if (Array.isArray(parsed)) {
      const groundedUrls = extractGroundingUrls(response);
      if (groundedUrls.length > 0) {
        // Replace news URLs with grounded ones where titles match
        for (const item of parsed) {
          const matchingGrounded = groundedUrls.find(g =>
            g.title.toLowerCase().includes(item.title.substring(0, 20).toLowerCase()) ||
            item.title.toLowerCase().includes(g.title.substring(0, 20).toLowerCase())
          );
          if (matchingGrounded) {
            item.url = matchingGrounded.url;
          }
        }
      }
      return parsed;
    }

    return [];
  } catch (error) {
    console.error("News fetch error:", error);
    return [];
  }
};
