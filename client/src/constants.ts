import { ThreatActor } from './types';

export const INITIAL_THREAT_ACTORS: ThreatActor[] = [
  {
    id: '1',
    name: 'APT29 (Cozy Bear)',
    first_seen: '2008',
    aliases: ['The Dukes', 'CozyDuke', 'Nobelium', 'Midnight Blizzard', 'Yttrium', 'Iron Hemlock', 'Grizzly Steppe', 'UNC2452', 'Dark Halo', 'StellarParticle', 'Blue Kitsune', 'ATK7', 'ITG11', 'TA421', 'BlueBravo'],
    description: {
      summary: 'APT29, widely known as Cozy Bear or Nobelium, is a cyber espionage group attributed to Russia\'s Foreign Intelligence Service (SVR). Active since at least 2008, their primary mission is collecting intelligence in support of Russian foreign policy. They target government networks, think tanks, healthcare, and energy sectors across NATO members and Western nations. They are characterized by extreme stealth, patience, and operational security.',
      campaigns: 'The group is infamous for the SolarWinds supply chain compromise (Sunburst) and attacks on the Democratic National Committee (DNC). They utilize a mix of custom malware (WellMess, GoldFinder) and legitimate tools (PowerShell, WMI) to maintain persistent access. Recent TTPs involve compromising cloud service providers, abusing trust relationships, and "access mining" to resell access or pivot into high-value targets.',
      recent: 'In 2023-2024, APT29 has heavily focused on cloud environments, specifically targeting Microsoft 365 tenants and Azure Active Directory. They have been observed conducting password spray attacks, exploiting the JetBrains TeamCity vulnerability (CVE-2023-42793), and targeting diplomatic entities in Europe. They have shifted towards identity-based attacks to bypass traditional perimeter defenses.'
    },
    cves: [
      { id: 'CVE-2023-42793', description: 'JetBrains TeamCity Authentication Bypass', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2023-42793+JetBrains' },
      { id: 'CVE-2023-38831', description: 'WinRAR Remote Code Execution', severity: 'HIGH', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2023-38831+WinRAR' },
      { id: 'CVE-2021-40444', description: 'MSHTML Remote Code Execution', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2021-40444' },
      { id: 'CVE-2020-1472', description: 'Netlogon Elevation of Privilege (Zerologon)', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2020-1472+Zerologon' },
      { id: 'CVE-2019-19781', description: 'Citrix ADC/Gateway Arbitrary Code Execution', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2019-19781+Citrix' },
      { id: 'CVE-2021-26084', description: 'Confluence OGNL Injection', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2021-26084+Confluence' },
      { id: 'CVE-2023-20198', description: 'Cisco IOS XE Privilege Escalation', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2023-20198+Cisco' },
      { id: 'CVE-2018-13379', description: 'Fortinet FortiOS Path Traversal', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2018-13379+Fortinet' },
      { id: 'CVE-2024-21413', description: 'Microsoft Outlook Remote Code Execution (MonikerLink)', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22APT29%22+exploiting+CVE-2024-21413+Outlook' }
    ],
    sources: [
        { title: 'MITRE ATT&CK - APT29', url: 'https://attack.mitre.org/groups/G0016/' },
        { title: 'CISA Alert - APT29 SVR Activities', url: 'https://www.cisa.gov/uscert/ncas/alerts/aa21-148a' },
        { title: 'Mandiant - APT29', url: 'https://www.mandiant.com/resources/insights/apt-groups/apt29' }
    ],
    lastUpdated: new Date().toISOString()
  },
  {
    id: '2',
    name: 'Lazarus Group',
    first_seen: '2009',
    aliases: ['Hidden Cobra', 'Guardians of Peace', 'Whois Team', 'Diamond Sleet', 'Zinc', 'Labyrinth Chollima', 'Nickel Academy', 'UNC577', 'Bureau 121', 'Appleworm', 'APT-C-26', 'Group 77'],
    description: {
      summary: 'Lazarus Group is a state-sponsored cyber threat group attributed to the Reconnaissance General Bureau of North Korea. Active since 2009, they possess a unique hybrid motivation of espionage and financial crime (to circumvent sanctions). They are known for high-profile destructive attacks as well as sophisticated bank heists and cryptocurrency theft.',
      campaigns: 'Major operations include the 2014 Sony Pictures hack, the 2016 Bangladesh Bank heist, and the global WannaCry ransomware outbreak in 2017. Their toolset includes the Manuscrypt, NukeSped, and Dtrack malware families. They frequently use social engineering on platforms like LinkedIn to target employees in defense and crypto sectors, delivering trojanized open-source tools.',
      recent: 'Recently, Lazarus has aggressively targeted the DeFi and blockchain industry, responsible for the Harmony Horizon Bridge and Ronin Bridge hacks. They have exploited zero-days in supply chain software like 3CX and have been observed utilizing the "MagicLine4NX" zero-click exploit. They continue to weaponize legitimate software updates to distribute malware.'
    },
    cves: [
      { id: 'CVE-2021-44228', description: 'Log4j Remote Code Execution (Log4Shell)', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22Lazarus+Group%22+exploiting+CVE-2021-44228+Log4j' },
      { id: 'CVE-2022-4135', description: 'Chrome Heap Buffer Overflow', severity: 'HIGH', verificationReference: 'https://www.google.com/search?q=%22Lazarus+Group%22+exploiting+CVE-2022-4135+Chrome' },
      { id: 'CVE-2020-1472', description: 'Netlogon Elevation of Privilege', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22Lazarus+Group%22+exploiting+CVE-2020-1472' },
      { id: 'CVE-2017-0144', description: 'SMB Remote Code Execution (EternalBlue)', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22Lazarus+Group%22+exploiting+CVE-2017-0144+WannaCry' },
      { id: 'CVE-2023-4863', description: 'libwebp Heap Buffer Overflow', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22Lazarus+Group%22+exploiting+CVE-2023-4863+libwebp' },
      { id: 'CVE-2022-30190', description: 'MSDT Remote Code Execution (Follina)', severity: 'HIGH', verificationReference: 'https://www.google.com/search?q=%22Lazarus+Group%22+exploiting+CVE-2022-30190+Follina' },
      { id: 'CVE-2020-0601', description: 'Windows CryptoAPI Spoofing', severity: 'CRITICAL', verificationReference: 'https://www.google.com/search?q=%22North+Korea+Cyber%22+exploiting+CVE-2020-0601' }
    ],
    sources: [
        { title: 'MITRE ATT&CK - Lazarus Group', url: 'https://attack.mitre.org/groups/G0032/' },
        { title: 'CISA Alert - Hidden Cobra', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a' }
    ],
    lastUpdated: new Date().toISOString()
  }
];
