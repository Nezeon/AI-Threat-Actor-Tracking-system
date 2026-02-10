export interface CVE {
  id: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  verificationReference?: string;
}

export interface Source {
  title: string;
  url: string;
}

export interface ThreatActor {
  id: string;
  name: string;
  first_seen: string;
  aliases: string[];
  description: {
    summary: string;
    campaigns: string;
    recent: string;
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

export interface TrustedFile {
  id?: number;
  name: string;
  type: string;
  content: string;
  timestamp?: number;
}
