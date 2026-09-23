/**
 * Aegis Threat Intelligence & IP Reputation Service
 * 
 * Provides:
 * - Threat intelligence feed correlation (Tor exit nodes, C2 trackers, scanners)
 * - Transparent IP Reputation Scoring (0-100 scale, where < 30 = severe threat)
 * - Country / ASN enrichment
 */

import { ThreatIntelEntry } from '../../types/aegis';

export class ThreatIntelService {
  private threatDb: Map<string, ThreatIntelEntry> = new Map();

  constructor() {
    this.seedThreatFeeds();
  }

  private seedThreatFeeds() {
    const feeds: ThreatIntelEntry[] = [
      {
        ipOrCidr: '185.220.101.5',
        threatType: 'TOR_EXIT',
        confidence: 96,
        country: 'DE',
        asn: 'AS208323 (Zwiebelfreunde e.V.)',
        reportedIncidents: 1420,
        lastSeen: Date.now() - 3600000,
      },
      {
        ipOrCidr: '198.51.100.77',
        threatType: 'BRUTE_FORCE',
        confidence: 91,
        country: 'NL',
        asn: 'AS49981 (WorldStream B.V.)',
        reportedIncidents: 840,
        lastSeen: Date.now() - 1800000,
      },
      {
        ipOrCidr: '203.0.113.19',
        threatType: 'BOTNET_C2',
        confidence: 99,
        country: 'RU',
        asn: 'AS48287 (Global Telemetry Net)',
        reportedIncidents: 4210,
        lastSeen: Date.now() - 900000,
      },
      {
        ipOrCidr: '45.154.255.89',
        threatType: 'SCANNER',
        confidence: 88,
        country: 'SC',
        asn: 'AS51852 (Private Layer)',
        reportedIncidents: 950,
        lastSeen: Date.now() - 7200000,
      },
    ];

    feeds.forEach(f => this.threatDb.set(f.ipOrCidr, f));
  }

  public lookupIp(ip: string): {
    isMalicious: boolean;
    reputationScore: number; // 0 (hostile) to 100 (clean)
    entry?: ThreatIntelEntry;
    riskBoost: number;
    description: string;
  } {
    const cleanIp = ip.split('/')[0].trim();
    const entry = this.threatDb.get(cleanIp);

    if (entry) {
      const reputation = Math.max(5, 100 - entry.confidence);
      return {
        isMalicious: true,
        reputationScore: reputation,
        entry,
        riskBoost: entry.confidence > 90 ? 30 : 20,
        description: `Threat Intelligence Match: ${entry.threatType} (Confidence: ${entry.confidence}%, ASN: ${entry.asn})`,
      };
    }

    // Default clean/unknown score
    return {
      isMalicious: false,
      reputationScore: 85,
      riskBoost: 0,
      description: 'No known malicious indicators in current threat intelligence cache.',
    };
  }

  public getKnownThreats(): ThreatIntelEntry[] {
    return Array.from(this.threatDb.values());
  }

  public addThreatIndicator(entry: ThreatIntelEntry) {
    this.threatDb.set(entry.ipOrCidr, entry);
  }
}

export const threatIntelService = new ThreatIntelService();
