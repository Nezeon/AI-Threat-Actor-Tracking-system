import { GoogleGenAI, Type, Schema } from "@google/genai";
import { ThreatActor, NewsItem } from '../types.js';
import { TRUSTED_THREAT_DATA } from '../data/trustedData.js';
import { getMitreActorInfo } from './mitreService.js';
import { isKnownStableUrl, validateUrls } from './urlValidation.js';
import * as db from '../models/db.js';

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });

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

  const addSource = (source: { title: string; url: string }) => {
    const normalized = source.url.replace(/\/$/, '');
    if (!seenUrls.has(normalized)) {
      seenUrls.add(normalized);
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
    addSource(src);
  }

  // 4. AI-generated sources, but ONLY if they match known-stable patterns
  for (const src of aiSources) {
    if (isKnownStableUrl(src.url)) {
      addSource(src);
    }
  }

  return result;
}


// ============================================================
// 1. Generate New Threat Actor Profile
// ============================================================
export const generateActorProfile = async (
  actorName: string,
  trustedUrls: string[],
  trustedFiles: { name: string; content: string }[]
): Promise<Omit<ThreatActor, 'id' | 'lastUpdated'>> => {
  const model = 'gemini-3-flash-preview';

  const cleanInput = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');

  const trustedCsvKey = Object.keys(TRUSTED_THREAT_DATA).find(k => {
    const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    return cleanInput.includes(cleanKey) || cleanKey.includes(cleanInput);
  });

  const trustedCsvData = trustedCsvKey ? TRUSTED_THREAT_DATA[trustedCsvKey] : null;
  const hasUserUrls = trustedUrls.length > 0;
  const hasUserFiles = trustedFiles.length > 0;
  const hasTrustedContext = hasUserUrls || hasUserFiles;

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      name: { type: Type.STRING },
      first_seen: {
        type: Type.STRING,
        description: "Year first observed. Format: 'YYYY' or 'at least YYYY'. Cross-reference MITRE ATT&CK, Mandiant, and CrowdStrike."
      },
      aliases: { type: Type.ARRAY, items: { type: Type.STRING } },
      description: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING, description: "Origin, first observed date (MUST be accurate), capability, motive, targeting pattern." },
          campaigns: { type: Type.STRING, description: "Campaigns, tool sets, TTPs, malwares, collaborations." },
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

  let prompt = `Conduct a forensic cybersecurity audit on the threat actor: "${actorName}".`;

  if (trustedCsvData) {
    const ids = trustedCsvData.cves.map(c => c.id).join(", ");
    prompt += `\n\n**CRITICAL VALIDATION PROTOCOL (INTERNAL DB)**:
    The user has provided a VERIFIED CSV dataset for this actor containing these CVEs: [${ids}].
    1. You MUST acknowledge these CVEs in your analysis.
    2. Do NOT hallucinate other CVEs unless you have 100% certainty from a Google Search result.`;
  }

  if (hasUserFiles) {
    prompt += `\n\n**TRUSTED FILE CONTEXT**:
    The user has uploaded the following trusted documents. You must parse these documents COMPLETELY.
    Treat every piece of technical data in them as absolute fact.

    ${trustedFiles.map((f, i) => `--- FILE ${i+1}: ${f.name} ---\n${f.content.substring(0, 1000000)}\n--- END FILE ---`).join('\n\n')}
    `;
  }

  if (hasTrustedContext) {
    prompt += `\n\n**STRICT EXTRACTION PROTOCOL (ALLOWLIST MODE)**:
    You are operating in STRICT VALIDATION mode.

    APPROVED URLS:
    ${trustedUrls.map(u => `- ${u}`).join('\n')}

    CRITICAL INSTRUCTIONS:
    1. **MANDATORY EXTRACTION**: You MUST extract EVERY SINGLE CVE ID (Pattern: CVE-YYYY-NNNN+) found in the "TRUSTED FILE CONTEXT" or associated with the "APPROVED URLS".
    2. **NO FILTERING**: Do not omit any CVE found in the trusted files, regardless of age, severity, or status. If it is in the file, it MUST be in the output list.
    3. **VERIFICATION SOURCE**:
       - For CVEs found in the uploaded text, set verificationReference to "Source: File [Filename]".
       - For CVEs found via Approved URLs, set verificationReference to the specific URL.
    4. **EXCLUSIVITY**: Do not include CVEs found via Google Search that are NOT present in the Trusted Files/URLs, unless no Trusted Files/URLs were provided.
    `;
  }

  prompt += `\n\nMISSION:
  Generate a Threat Profile with EXHAUSTIVE and 100% VERIFIED data.

  STRICT IDENTITY & ACCURACY RULES:

  1.  **TIMELINE ACCURACY (FIRST SEEN)**:
      - Explicitly search for "earliest activity" or "first observed" dates for "${actorName}".
      - Cross-reference Mandiant, CrowdStrike, and Microsoft reports.
      - **CRITICAL**: The 'first_seen' field MUST contain the year of first observation (e.g., "2008" or "at least 2013").
      - The first sentence of the 'summary' MUST also state the "First Observed" year/date.

  2.  **ALIASES (EXHAUSTIVE MAPPING)**:
      - Perform a deep search for aliases across ALL major naming schemes:
        * **Microsoft**: (Weather/Elements/Sleets, e.g., "Midnight Blizzard", "Diamond Sleet").
        * **CrowdStrike**: (Animals, e.g., "Cozy Bear", "Panda").
        * **Mandiant/FireEye**: (APTxx, UNCxxxx).
        * **Secureworks**: (Elements, e.g., "Iron Hemlock").
        * **Proofpoint**: (TAxxx).
      - List ALL discovered aliases. Do not truncate.
      - **EXCLUDE**: Tools (e.g., Cobalt Strike) and Parent Orgs (e.g., GRU) unless used as the primary identifier.

  3.  **LINK SAFETY & SOURCES**:
      - **NO BROKEN LINKS**: Do NOT generate deep-links to specific blog posts (e.g., "site.com/blog/2021/analysis") unless you are 100% certain they are live.
      - **PREFERRED SOURCES**: In the 'sources' array, prioritze stable "Profile" pages:
         - MITRE ATT&CK Group Page.
         - Malpedia Actor Page.
         - CISA AA (Alerts).
         - Vendor "Adversary Universe" or "Threat Library" main pages.
      - **FALLBACK**: If a stable URL is unavailable, use a high-quality Google Search Query URL (e.g., "https://www.google.com/search?q=${actorName}+threat+intelligence").

  4.  **CVE VERIFICATION**:
      - For 'verificationReference', if you cannot find a stable, direct advisory URL, use a Google Search Query: "https://www.google.com/search?q=${actorName}+exploiting+${'CVE-ID'}".
      - Do NOT guess specific PDF URLs.

  DATA STRUCTURE:
  - **first_seen**: Year of first observation (e.g., "2008").
  - **Summary**: Origin, **First Observed Date**, Motivation, Target Sectors.
  - **Campaigns**: Named campaigns, Tools.
  - **Recent**: Activity in the last 12-24 months.
  - **Sources**: General list of high-level sources used (MITRE, Malpedia, etc.).

  Execute the search now. Verify attribution. Generate the JSON.`;

  try {
    const response = await ai.models.generateContent({
      model,
      contents: prompt,
      config: {
        tools: [{ googleSearch: {} }],
        responseMimeType: "application/json",
        responseSchema: schema,
        maxOutputTokens: 8192,
        temperature: 0,
        systemInstruction: "You are an elite Threat Intelligence Auditor. You prioritize accuracy over quantity. You strictly adhere to the requested Threat Actor identity. You verify all URLs before including them.",
      }
    });

    const text = response.text;
    if (!text) throw new Error("No response from AI");

    // Extract grounding metadata (real URLs Gemini's search tool found)
    const groundedUrls = extractGroundingUrls(response);
    console.log(`Extracted ${groundedUrls.length} grounded URLs from Gemini search`);

    const parsedData = JSON.parse(text);

    // ============================================================
    // POST-GENERATION VALIDATION PIPELINE
    // ============================================================

    // --- Step 1: Trusted CSV data overrides ---
    if (trustedCsvData) {
      console.log(`Applying trusted CSV validation for ${actorName}`);

      // Override CVEs with trusted data
      parsedData.cves = trustedCsvData.cves.map(trustedCve => {
        const aiFound = parsedData.cves.find((aiCve: any) => aiCve.id === trustedCve.id);
        return {
          id: trustedCve.id,
          description: aiFound?.description || "Vulnerability confirmed via Trusted Intelligence CSV.",
          severity: aiFound?.severity || "HIGH",
          verificationReference: trustedCve.verificationReference
        };
      });

      // Override first_seen from ground truth
      if (trustedCsvData.first_seen) {
        parsedData.first_seen = trustedCsvData.first_seen;
      }

      // Merge aliases: AI + ground truth
      if (trustedCsvData.aliases) {
        parsedData.aliases = mergeAliases(
          parsedData.aliases || [],
          trustedCsvData.aliases,
          [],
          parsedData.name
        );
      }
    } else if (hasTrustedContext) {
      const existingUrls = new Set(parsedData.sources.map((s: any) => s.url));
      trustedUrls.forEach(url => {
        if (!existingUrls.has(url)) {
          parsedData.sources.unshift({ title: 'Approved Platform Source', url: url });
        }
      });
    }

    // --- Step 2: MITRE ATT&CK enrichment ---
    try {
      const mitreInfo = await getMitreActorInfo(actorName);

      if (mitreInfo) {
        console.log(`MITRE ATT&CK data found: ${mitreInfo.aliases.length} aliases, URL: ${mitreInfo.mitreUrl}`);

        // Merge MITRE aliases
        parsedData.aliases = mergeAliases(
          parsedData.aliases || [],
          trustedCsvData?.aliases || [],
          mitreInfo.aliases,
          parsedData.name
        );

        // Use MITRE first_seen if no ground truth override
        if (!trustedCsvData?.first_seen && mitreInfo.firstSeen) {
          parsedData.first_seen = mitreInfo.firstSeen;
        }

        // Assemble verified sources
        parsedData.sources = assembleVerifiedSources(
          groundedUrls,
          parsedData.sources || [],
          trustedCsvData?.sources || [],
          mitreInfo.mitreUrl,
          parsedData.name
        );
      } else {
        console.log(`No MITRE ATT&CK data found for "${actorName}"`);

        // Still replace AI sources with grounded URLs if available
        if (groundedUrls.length > 0) {
          parsedData.sources = assembleVerifiedSources(
            groundedUrls,
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
      }
    } catch (mitreError) {
      console.error('MITRE enrichment failed (non-fatal):', mitreError);
      // Fall back to grounded URLs + trusted sources only
      if (groundedUrls.length > 0) {
        parsedData.sources = assembleVerifiedSources(
          groundedUrls,
          parsedData.sources || [],
          trustedCsvData?.sources || [],
          null,
          parsedData.name
        );
      }
    }

    // --- Step 3: URL validation (remove dead links) ---
    try {
      const validatedSources = await validateUrls(parsedData.sources || []);
      parsedData.sources = validatedSources;
    } catch (validationError) {
      console.error('URL validation failed (non-fatal):', validationError);
      // Keep sources as-is if validation fails
    }

    // --- Step 4: Ensure minimum sources ---
    if (!parsedData.sources || parsedData.sources.length < 2) {
      parsedData.sources = parsedData.sources || [];
      parsedData.sources.push({
        title: `Search - ${actorName} threat intelligence`,
        url: `https://www.google.com/search?q=${encodeURIComponent(actorName)}+threat+intelligence`
      });
    }

    // Ensure first_seen has a value
    if (!parsedData.first_seen) {
      parsedData.first_seen = 'Unknown';
    }

    return parsedData;
  } catch (error) {
    console.error("Error generating profile:", error);
    throw error;
  }
};

// ============================================================
// 2. Granular Refresh
// ============================================================
export const refreshActorSection = async (
  actorName: string,
  section: 'ALIASES' | 'DESCRIPTION' | 'CVES'
): Promise<any> => {
  const model = 'gemini-3-flash-preview';
  let prompt = `Focus exclusively on the "${section}" for threat actor: "${actorName}".`;
  let schema: Schema = { type: Type.OBJECT, properties: {}, required: [] };

  if (section === 'ALIASES') {
    prompt += `\nTask: Perform a deep search on MITRE, Malpedia, CISA, and Vendor blogs (Microsoft, CrowdStrike, FireEye, Secureworks).

    OBJECTIVE: List ALL known aliases (Vendor-assigned names).

    MAPPING GUIDE:
    - Microsoft: Weather/Sleet/Typhoon names (e.g. Midnight Blizzard, Volt Typhoon)
    - CrowdStrike: Animal names (e.g. Fancy Bear, Wicked Panda)
    - Mandiant: APTxx, UNCxxxx
    - Proofpoint: TAxxx

    CRITICAL EXCLUSION RULES:
    1. DO NOT include Tools or Malware names (e.g. Cobalt Strike, Mimikatz).
    2. DO NOT include Parent Organizations (e.g. GRU, MSS) unless used as the actor name.

    Return a simple array of unique strings.`;

    schema = {
      type: Type.OBJECT,
      properties: {
        aliases: { type: Type.ARRAY, items: { type: Type.STRING } }
      },
      required: ["aliases"]
    };
  } else if (section === 'DESCRIPTION') {
    prompt += `\nTask: Re-evaluate the threat profile history and tactics.
    1. Summary: **MANDATORY**: Search for and explicitly state "First observed in [Year]" at the start. Confirm this date via search across multiple vendors.
    2. Campaigns: List major historical campaigns and toolsets.
    3. Recent: Focus on activity within the last 12 months.
    `;

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
    prompt += `\nTask: Find ALL CVEs exploited by this actor.
    - Search for recent CISA advisories and vendor reports.
    - **VERIFICATION**: Provide a valid URL. If a direct report link is unstable, construct a Google Search Query URL (e.g., "https://www.google.com/search?q=${actorName}+CVE-xxxx-xxxx").
    `;
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
        systemInstruction: "You are a specialized Threat Intel component. Focus only on the requested section. Prioritize accuracy of Dates, Names, and URLs."
      }
    });

    const parsed = JSON.parse(response.text || "{}");

    // --- Post-processing for ALIASES section ---
    if (section === 'ALIASES' && parsed.aliases) {
      // Look up ground truth and MITRE data
      const cleanInput = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
      const trustedCsvKey = Object.keys(TRUSTED_THREAT_DATA).find(k => {
        const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
        return cleanInput.includes(cleanKey) || cleanKey.includes(cleanInput);
      });
      const trustedAliases = trustedCsvKey ? TRUSTED_THREAT_DATA[trustedCsvKey]?.aliases || [] : [];

      try {
        const mitreInfo = await getMitreActorInfo(actorName);
        parsed.aliases = mergeAliases(
          parsed.aliases,
          trustedAliases,
          mitreInfo?.aliases || [],
          actorName
        );
      } catch {
        parsed.aliases = mergeAliases(parsed.aliases, trustedAliases, [], actorName);
      }
    }

    // --- Post-processing for DESCRIPTION section ---
    if (section === 'DESCRIPTION' && parsed.first_seen) {
      // Override with ground truth if available
      const cleanInput = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
      const trustedCsvKey = Object.keys(TRUSTED_THREAT_DATA).find(k => {
        const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
        return cleanInput.includes(cleanKey) || cleanKey.includes(cleanInput);
      });
      const trustedFirstSeen = trustedCsvKey ? TRUSTED_THREAT_DATA[trustedCsvKey]?.first_seen : null;
      if (trustedFirstSeen) {
        parsed.first_seen = trustedFirstSeen;
      } else {
        try {
          const mitreInfo = await getMitreActorInfo(actorName);
          if (mitreInfo?.firstSeen) {
            parsed.first_seen = mitreInfo.firstSeen;
          }
        } catch {
          // Keep AI value
        }
      }
    }

    // --- Post-processing for CVES section: use grounding for verification URLs ---
    if (section === 'CVES' && parsed.cves) {
      const groundedUrls = extractGroundingUrls(response);
      if (groundedUrls.length > 0) {
        // For each CVE, try to find a grounded URL that mentions the CVE ID
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
        temperature: 0
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
        temperature: 0.1
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
