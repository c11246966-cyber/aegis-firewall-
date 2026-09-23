/**
 * Aegis Transparent Risk Calculation Engine
 * 
 * Computes an itemized 0-100 risk score with an auditable factor ledger.
 * Every point added or deducted is tied to an explicit security factor:
 * - Source reputation & threat intelligence
 * - Connection frequency & velocity
 * - Failed authentication attempts (RDP / SSH)
 * - Port diversity (horizontal/vertical scan)
 * - Protocol anomalies (malformed payloads / injection)
 * - Traffic bursts & volumetric spikes
 * - Repeated alerts & cluster velocity
 * - Process context (abnormal child processes / reverse shells)
 * - DNS anomalies (tunneling, length, entropy)
 */

import { RiskFactor, RiskReport, SecurityEvent, SecurityAlert } from '../../types/aegis';

export class RiskEngine {
  public calculateRisk(
    recentEvents: SecurityEvent[],
    activeAlerts: SecurityAlert[],
    trafficPps: number
  ): RiskReport {
    const factors: RiskFactor[] = [];
    let currentScore = 12; // Baseline network chatter floor

    factors.push({
      factor: 'Baseline Network Activity',
      score: 12,
      category: 'PROTOCOL',
      description: 'Nominal baseline ingress traffic across monitored network interfaces.',
    });

    // 1. Port Diversity & Scanning Analysis
    const scannedPorts = new Set(recentEvents.filter(e => e.vector === 'PORT_SCAN').map(e => e.destPort));
    if (scannedPorts.size > 3) {
      const portScore = Math.min(25, scannedPorts.size * 5);
      currentScore += portScore;
      factors.push({
        factor: 'High Port Diversity / Active Port Sweep',
        score: portScore,
        category: 'VELOCITY',
        description: `Source swept across ${scannedPorts.size} distinct ports within evaluation window.`,
      });
    }

    // 2. Failed Authentication Bursts (RDP 3389 / SSH 22)
    const authAttempts = recentEvents.filter(e => e.vector === 'SSH_BRUTE_FORCE' || e.vector === 'RDP_BRUTE_FORCE');
    if (authAttempts.length > 0) {
      const authScore = Math.min(30, authAttempts.length * 6);
      currentScore += authScore;
      factors.push({
        factor: 'Failed Credential Stuffing / Brute-Force Burst',
        score: authScore,
        category: 'AUTH',
        description: `Detected ${authAttempts.length} rapid failed logon bursts targeting Windows RDP / SSH daemons.`,
      });
    }

    // 3. Threat Intelligence / Source Reputation Match
    const threatMatches = recentEvents.filter(e => e.threatIntelMatch);
    if (threatMatches.length > 0) {
      currentScore += 25;
      factors.push({
        factor: 'Threat Intelligence / Malicious IP Match',
        score: 25,
        category: 'REPUTATION',
        description: `Correlated with known malicious indicator (${threatMatches[0].threatIntelMatch}).`,
      });
    }

    // 4. Process Context & Suspicious Outbound (e.g. cmd.exe or powershell.exe)
    const processEvents = recentEvents.filter(e => e.vector === 'OUTBOUND_BEACON' || e.vector === 'PROCESS_CORRELATION');
    if (processEvents.length > 0) {
      currentScore += 22;
      factors.push({
        factor: 'Suspicious Process Network Correlation',
        score: 22,
        category: 'PROCESS',
        description: `Windows process network correlation flagged (${processEvents[0].processName || 'cmd.exe'} outbound beacon).`,
      });
    }

    // 5. DNS Anomalies & Tunneling
    const dnsEvents = recentEvents.filter(e => e.vector === 'DNS_ANOMALY');
    if (dnsEvents.length > 0) {
      currentScore += 18;
      factors.push({
        factor: 'DNS Tunneling / High-Entropy Query Anomaly',
        score: 18,
        category: 'DNS',
        description: 'Abnormal DNS TXT record volume and query entropy characteristic of data exfiltration.',
      });
    }

    // 6. Traffic Burst & Flooding
    if (trafficPps > 10000) {
      currentScore += 25;
      factors.push({
        factor: 'Volumetric Ingress Traffic Spike',
        score: 25,
        category: 'BURST',
        description: `Traffic velocity surged to ${trafficPps.toLocaleString()} pps exceeding threshold.`,
      });
    }

    // 7. Repeated Unacknowledged Critical Alerts
    const criticalAlerts = activeAlerts.filter(a => !a.acknowledged && (a.severity === 'CRITICAL' || a.severity === 'HIGH'));
    if (criticalAlerts.length > 0) {
      const alertScore = Math.min(20, criticalAlerts.length * 5);
      currentScore += alertScore;
      factors.push({
        factor: 'Unacknowledged High-Severity Alerts',
        score: alertScore,
        category: 'VELOCITY',
        description: `${criticalAlerts.length} unresolved high/critical security alerts pending SOC investigation.`,
      });
    }

    // Clamp score to 0 - 100
    const clampedScore = Math.min(100, Math.max(0, currentScore));

    // Determine DEFCON Level
    let threatLevel: RiskReport['threatLevel'] = 'DEFCON 5 (NORMAL)';
    let threatColor = '#10b981'; // emerald

    if (clampedScore >= 85) {
      threatLevel = 'DEFCON 1 (CRITICAL)';
      threatColor = '#ef4444'; // red
    } else if (clampedScore >= 65) {
      threatLevel = 'DEFCON 2 (HIGH)';
      threatColor = '#f97316'; // orange
    } else if (clampedScore >= 45) {
      threatLevel = 'DEFCON 3 (ELEVATED)';
      threatColor = '#eab308'; // yellow
    } else if (clampedScore >= 25) {
      threatLevel = 'DEFCON 4 (GUARDED)';
      threatColor = '#06b6d4'; // cyan
    }

    // Vector breakdown
    const portScanCount = recentEvents.filter(e => e.vector === 'PORT_SCAN').length;
    const authCount = recentEvents.filter(e => e.vector === 'SSH_BRUTE_FORCE' || e.vector === 'RDP_BRUTE_FORCE').length;
    const httpCount = recentEvents.filter(e => e.vector === 'HTTP_ANOMALY').length;
    const floodCount = recentEvents.filter(e => e.vector === 'NETWORK_FLOOD' || e.vector === 'SYN_FLOOD' || e.vector === 'UDP_FLOOD').length;
    const dnsCount = recentEvents.filter(e => e.vector === 'DNS_ANOMALY').length;
    const beaconCount = recentEvents.filter(e => e.vector === 'OUTBOUND_BEACON').length;

    return {
      currentScore: clampedScore,
      threatLevel,
      threatColor,
      vectorBreakdown: {
        portScan: portScanCount,
        sshRdpBruteForce: authCount,
        httpAnomaly: httpCount,
        networkFlood: floodCount,
        dnsAnomaly: dnsCount,
        outboundBeacon: beaconCount,
      },
      factors,
      activeThreatsCount: criticalAlerts.length,
      blockedAttemptsCount: recentEvents.filter(e => e.actionTaken === 'BLOCKED' || e.actionTaken === 'QUARANTINED').length,
      recentTrend: clampedScore > 50 ? 'UP' : 'STABLE',
    };
  }
}

export const riskEngine = new RiskEngine();
