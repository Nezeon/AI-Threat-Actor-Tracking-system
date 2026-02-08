import { GoogleGenAI, Type, Schema } from "@google/genai";
import { ThreatActor, NewsItem } from '../types';
import { TRUSTED_THREAT_DATA } from '../constants';

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

const getLocalStorageItem = <T>(key: string): T | null => {
  if (typeof window === 'undefined') return null;
  try {
    const store = localStorage.getItem(key);
    return store ? JSON.parse(store) : null;
  } catch {
    return null;
  }
};

const getTrustedSources = (actorName: string) => {
  const sources = getLocalStorageItem<Record<string, string[]>>('hivepro_trusted_sources');
  if (!sources) return [];
  const normalizedName = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const key = Object.keys(sources).find(k => {
    const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    return normalizedName.includes(cleanKey) || cleanKey.includes(normalizedName);
  });
  return key ? sources[key] : [];
};

const getTrustedFiles = (actorName: string) => {
  const files = getLocalStorageItem<Record<string, {name: string, content: string}[]>>('hivepro_trusted_files');
  if (!files) return [];
  const normalizedName = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const key = Object.keys(files).find(k => {
    const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    return normalizedName.includes(cleanKey) || cleanKey.includes(normalizedName);
  });
  return key ? files[key] : [];
};

// Helper: Scan message for actor names and retrieve combined context
const getRelevantContextForChat = (message: string): string => {
  const sourcesStore = getLocalStorageItem<Record<string, string[]>>('hivepro_trusted_sources') || {};
  const filesStore = getLocalStorageItem<Record<string, {name: string, content: string}[]>>('hivepro_trusted_files') || {};
  
  const allActorNames = new Set([...Object.keys(sourcesStore), ...Object.keys(filesStore)]);
  const foundContexts: string[] = [];

  allActorNames.forEach(actorName => {
    // Check if the actor name appears in the user message (case-insensitive)
    if (message.toLowerCase().includes(actorName.toLowerCase())) {
        const urls = sourcesStore[actorName] || [];
        const files = filesStore[actorName] || [];
        
        if (urls.length > 0 || files.length > 0) {
            let context = `\n--- APPROVED INTELLIGENCE FOR: ${actorName.toUpperCase()} ---`;
            
            if (urls.length > 0) {
                context += `\n[TRUSTED URLs]:\n${urls.map(u => `- ${u}`).join('\n')}`;
            }
            
            if (files.length > 0) {
                // Truncate file content to prevent token overflow in chat, prioritizing the beginning
                context += `\n[TRUSTED DOCUMENTS]:\n${files.map(f => `FILE: ${f.name}\nCONTENT START:\n${f.content.substring(0, 15000)}...\nCONTENT END`).join('\n\n')}`;
            }
            
            foundContexts.push(context);
        }
    }
  });

  return foundContexts.join('\n\n');
};

// 1. Generate New Threat Actor Profile
export const generateActorProfile = async (actorName: string): Promise<Omit<ThreatActor, 'id' | 'lastUpdated'>> => {
  const model = 'gemini-3-flash-preview';
  
  // Normalize: remove special chars and lowercase to increase match hit rate with Trusted CSV
  const cleanInput = actorName.toLowerCase().replace(/[^a-z0-9]/g, '');
  
  const trustedCsvKey = Object.keys(TRUSTED_THREAT_DATA).find(k => {
    const cleanKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    return cleanInput.includes(cleanKey) || cleanKey.includes(cleanInput);
  });
  
  const trustedCsvData = trustedCsvKey ? TRUSTED_THREAT_DATA[trustedCsvKey] : null;
  const userApprovedUrls = getTrustedSources(actorName);
  const userApprovedFiles = getTrustedFiles(actorName);
  
  const hasUserUrls = userApprovedUrls.length > 0;
  const hasUserFiles = userApprovedFiles.length > 0;
  const hasTrustedContext = hasUserUrls || hasUserFiles;

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      name: { type: Type.STRING },
      aliases: { type: Type.ARRAY, items: { type: Type.STRING } },
      description: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING, description: "Origin, first observed date, capability, motive, targeting pattern." },
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
    required: ["name", "aliases", "description", "cves", "sources"]
  };

  // Construct a prompt
  let prompt = `Conduct a forensic cybersecurity audit on the threat actor: "${actorName}".`;

  // 1. HARDCODED CSV LOGIC
  if (trustedCsvData) {
    const ids = trustedCsvData.cves.map(c => c.id).join(", ");
    prompt += `\n\n**CRITICAL VALIDATION PROTOCOL (INTERNAL DB)**: 
    The user has provided a VERIFIED CSV dataset for this actor containing these CVEs: [${ids}].
    1. You MUST acknowledge these CVEs in your analysis.
    2. Do NOT hallucinate other CVEs unless you have 100% certainty from a Google Search result.`;
  } 
  
  // 2. USER UPLOADED FILES LOGIC
  if (hasUserFiles) {
    prompt += `\n\n**TRUSTED FILE CONTEXT**:
    The user has uploaded the following trusted documents. You must parse these documents COMPLETELY. 
    Treat every piece of technical data in them as absolute fact.
    
    ${userApprovedFiles.map((f, i) => `--- FILE ${i+1}: ${f.name} ---\n${f.content.substring(0, 1000000)}\n--- END FILE ---`).join('\n\n')}
    `;
  }

  // 3. ALLOWLIST LOGIC (URLS + FILES)
  if (hasTrustedContext) {
    prompt += `\n\n**STRICT EXTRACTION PROTOCOL (ALLOWLIST MODE)**:
    You are operating in STRICT VALIDATION mode.
    
    APPROVED URLS:
    ${userApprovedUrls.map(u => `- ${u}`).join('\n')}
    
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
  
  STRICT IDENTITY & VALIDATION RULES:
  1.  **IDENTITY LOCK**: You are analyzing "${actorName}". 
      - **FIRST SEEN**: You MUST explicitly state the year this actor was FIRST observed in the 'summary'.
      - **ALIASES (STRICT)**: 
         - **INCLUDE ONLY**: Official Vendor names (e.g., "Midnight Blizzard", "Cozy Bear"), Industry Designators (e.g., "APT29"), or Common Names.
         - **EXCLUDE**: 
            - Tools (e.g., "Cobalt Strike" is a tool, not an alias).
            - Malware Families (e.g., "Mimikatz").
            - Parent Organizations (e.g., "SVR" or "PLA" - unless used synonymously).
            - Campaigns (unless used as the primary actor name).
      - **LINKS**: Ensure all URLs in 'sources' and 'verificationReference' are VALID, DIRECT deep-links to reports. If a direct link is unstable, use a Google Search query URL.
  
  2.  **Exhaustive Search**: Search for '"${actorName}" exploited CVEs' and '"${actorName}" first seen'.
  
  3.  **Proof Required**: For EVERY single CVE you list, you MUST provide a verification link.

  4.  **LINK SAFETY (CRITICAL)**: 
      - ${hasTrustedContext ? 'Use the Source URL or File Name as the reference.' : 'You MUST generate a Google Search Query URL for the verificationReference IF you cannot find a direct report link.'}
      - ${hasTrustedContext ? '' : `Format for fallback: "https://www.google.com/search?q=" + '"' + ActorName + '"' + "+exploiting+" + CVE_ID`}
  
  5.  **No Proof = No Entry**: If you cannot find a connection between the actor and the CVE, OMIT IT.

  DATA STRUCTURE:
  - **Summary**: Origin, First Observed Date, Motivation, Target Sectors.
  - **Campaigns**: Named campaigns, Tools.
  - **Recent**: Activity in the last 12-24 months.
  - **Sources**: General list of high-level sources used.

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
        temperature: 0, // Deterministic output
        systemInstruction: "You are an elite Threat Intelligence Auditor. You prioritize accuracy over quantity. You strictly adhere to the requested Threat Actor identity. You strictly separate the Actor's Identity from their Tools and Parent Organizations.",
      }
    });

    const text = response.text;
    if (!text) throw new Error("No response from AI");
    
    const parsedData = JSON.parse(text);

    // *** DETERMINISTIC VALIDATION LOGIC ***
    // Logic 1: CSV Override (Highest Priority)
    if (trustedCsvData) {
      console.log(`Applying trusted CSV validation for ${actorName}`);
      
      parsedData.cves = trustedCsvData.cves.map(trustedCve => {
          const aiFound = parsedData.cves.find((aiCve: any) => aiCve.id === trustedCve.id);
          return {
              id: trustedCve.id,
              description: aiFound?.description || "Vulnerability confirmed via Trusted Intelligence CSV.",
              severity: aiFound?.severity || "HIGH", 
              verificationReference: trustedCve.verificationReference 
          };
      });

      if (trustedCsvData.sources) {
          const existingUrls = new Set(parsedData.sources.map((s: any) => s.url));
          const newSources = trustedCsvData.sources.filter(s => !existingUrls.has(s.url));
          parsedData.sources = [...newSources, ...parsedData.sources];
      }
    }
    // Logic 2: User URL/File Override
    else if (hasTrustedContext) {
        // Ensure sources list contains the manual entries
        const existingUrls = new Set(parsedData.sources.map((s: any) => s.url));
        userApprovedUrls.forEach(url => {
            if (!existingUrls.has(url)) {
                parsedData.sources.unshift({ title: 'Approved Platform Source', url: url });
            }
        });
        userApprovedFiles.forEach(file => {
             // We can't link to a local file easily in the sources list without a Blob URL which persists,
             // so we just add it as a textual reference if needed, or rely on the AI putting it in 'verificationReference'
        });
    }

    return parsedData;
  } catch (error) {
    console.error("Error generating profile:", error);
    throw error;
  }
};

// 4. Granular Refresh
export const refreshActorSection = async (actorName: string, section: 'ALIASES' | 'DESCRIPTION' | 'CVES'): Promise<any> => {
   const model = 'gemini-3-flash-preview';
   let prompt = `Focus exclusively on the "${section}" for threat actor: "${actorName}".`;
   let schema: Schema = { type: Type.OBJECT, properties: {}, required: [] };

   if (section === 'ALIASES') {
      prompt += `\nTask: Perform a deep search on MITRE, Malpedia, CISA, and Vendor blogs (Microsoft, CrowdStrike, FireEye).
      List ALL known aliases (Vendor-assigned names).
      
      CRITICAL EXCLUSION RULES:
      1. DO NOT include Tools or Malware names (e.g. Cobalt Strike, Mimikatz).
      2. DO NOT include Parent Organizations (e.g. GRU, MSS) unless used as the actor name.
      3. DO NOT include Campaign names unless they are synonymous with the actor.
      
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
      1. Summary: MUST strictly state "First observed in [Year]" at the start. Confirm this date via search.
      2. Campaigns: List major historical campaigns and toolsets.
      3. Recent: Focus on activity within the last 12 months.
      `;
      
      schema = {
         type: Type.OBJECT,
         properties: {
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
         required: ["description"]
      };
   } else if (section === 'CVES') {
      prompt += `\nTask: Find ALL CVEs exploited by this actor.
      - Search for recent CISA advisories and vendor reports.
      - Provide a verification link for each.
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
            systemInstruction: "You are a specialized Threat Intel component. Focus only on the requested section. Strictly separate Actor Aliases from Tools and Malware."
         }
      });
      
      return JSON.parse(response.text || "{}");
   } catch (error) {
      console.error(`Error refreshing section ${section}:`, error);
      throw error;
   }
};

// 2. Chat Functionality
export const chatWithAI = async (message: string, context?: string) => {
  const model = 'gemini-3-flash-preview';
  
  // 1. Identify and Retrieve Trusted Context
  const trustedContext = getRelevantContextForChat(message);

  let systemInstruction = context 
    ? `You are HivePro's Expert AI Analyst. The user is analyzing: ${context}.` 
    : "You are HivePro's Expert AI Analyst. Answer cybersecurity questions with high accuracy.";
       
  systemInstruction += `\nRULES: 
       1. Provide precise, evidence-based answers. 
       2. If you don't know, state "I cannot verify this information currently." 
       3. Use Google Search to validate any specific claims about CVEs or Attacks.`;

  // 2. Inject Context if Found
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
        temperature: 0 // Deterministic answers
      }
    });
    return response.text || "I couldn't generate a response.";
  } catch (error) {
    console.error("Chat error:", error);
    return "Error communicating with AI service.";
  }
};

// 3. Live News Feed (Grounding)
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
        temperature: 0.1 // Low temperature for factual news
      }
    });

    const text = response.text;
    if (!text) return [];
    
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error("News fetch error:", error);
    return [];
  }
};