export interface CVE {
  id: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  verificationReference?: string; // URL confirming the actor exploited this specific CVE
}

export interface Source {
  title: string;
  url: string;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: {
    summary: string; // Para 1: Origin, capability, motive
    campaigns: string; // Para 2: TTPs, tools, collaborations
    recent: string; // Para 3: Latest campaign, tactical changes
  };
  cves: CVE[];
  sources: Source[];
  lastUpdated: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  text: string;
  timestamp: number;
}

export interface NewsItem {
  title: string;
  summary: string;
  source: string;
  url: string;
  date: string;
}

export enum ViewState {
  THREAT_ACTORS = 'THREAT_ACTORS',
  CHAT = 'CHAT',
  LIVE_FEED = 'LIVE_FEED',
  TRUSTED_SOURCES = 'TRUSTED_SOURCES',
}