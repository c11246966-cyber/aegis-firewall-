/**
 * Aegis Policy & Containment Engine
 * 
 * Enforces:
 * - Operating mode decisions (MONITOR, SIMULATION, ENFORCEMENT)
 * - Allowlist & Trusted Management protection
 * - Rate limiting (sliding window token bucket)
 * - Alert deduplication (clustering repeated alerts)
 * - Alert flood protection (circuit breaker)
 * - Automated containment action generation
 */

import { 
  OperatingMode, 
  SecurityEvent, 
  SecurityAlert, 
  FirewallAction,
  SeverityLevel
} from '../../types/aegis';
import { validateIpOrCidr, DEFAULT_TRUSTED_MANAGEMENT_IPS } from '../../utils/ipValidator';

export interface PolicyDecision {
  shouldAlert: boolean;
  shouldContain: boolean;
  targetIp: string;
  recommendedAction: FirewallAction;
  ttlSeconds: number;
  reason: string;
  isDeduplicated: boolean;
  clusterCount: number;
  isFloodSuppressed: boolean;
}

export class PolicyEngine {
  private mode: OperatingMode = 'SIMULATION';
  private alertHistory: Map<string, { lastAlertTime: number; count: number }> = new Map();
  private recentAlertWindow: number[] = [];
  private allowlist: Set<string> = new Set(['192.168.1.1', '192.168.1.100', '10.0.0.1']);
  private trustedManagementIps: Set<string> = new Set(DEFAULT_TRUSTED_MANAGEMENT_IPS);

  public setMode(mode: OperatingMode) {
    this.mode = mode;
  }

  public getMode(): OperatingMode {
    return this.mode;
  }

  public isAllowlisted(ip: string): boolean {
    return this.allowlist.has(ip) || this.trustedManagementIps.has(ip);
  }

  public evaluateEvent(event: SecurityEvent): PolicyDecision {
    const now = Date.now();
    const val = validateIpOrCidr(event.sourceIp, Array.from(this.trustedManagementIps));

    // 1. Allowlist / Trusted Management Protection Check
    if (this.isAllowlisted(event.sourceIp) || val.isTrustedManagement) {
      return {
        shouldAlert: false,
        shouldContain: false,
        targetIp: event.sourceIp,
        recommendedAction: 'ALLOW',
        ttlSeconds: 0,
        reason: 'Protected by Allowlist / Trusted Management Policy',
        isDeduplicated: false,
        clusterCount: 1,
        isFloodSuppressed: false,
      };
    }

    // 2. Alert Flood Protection (Circuit Breaker: > 50 alerts in 10s)
    this.recentAlertWindow.push(now);
    this.recentAlertWindow = this.recentAlertWindow.filter(t => now - t < 10000);
    const isFloodSuppressed = this.recentAlertWindow.length > 50;

    // 3. Alert Deduplication (Cluster key: sourceIp + vector)
    const clusterKey = `${event.sourceIp}:${event.vector}`;
    const previous = this.alertHistory.get(clusterKey);
    let isDeduplicated = false;
    let clusterCount = 1;

    if (previous && (now - previous.lastAlertTime < 15000)) {
      // Repeat within 15 seconds -> deduplicate
      isDeduplicated = true;
      previous.count += 1;
      previous.lastAlertTime = now;
      clusterCount = previous.count;
    } else {
      this.alertHistory.set(clusterKey, { lastAlertTime: now, count: 1 });
    }

    // 4. Containment Decision based on Severity & Mode
    const isCritical = event.severity === 'CRITICAL' || event.severity === 'HIGH';
    const shouldContain = isCritical && this.mode === 'ENFORCEMENT';

    let ttlSeconds = 900; // 15 min default
    if (event.severity === 'CRITICAL') ttlSeconds = 1800; // 30 min

    return {
      shouldAlert: !isFloodSuppressed,
      shouldContain,
      targetIp: event.sourceIp,
      recommendedAction: 'DROP',
      ttlSeconds,
      reason: `Automated Containment: ${event.signature}`,
      isDeduplicated,
      clusterCount,
      isFloodSuppressed,
    };
  }
}

export const policyEngine = new PolicyEngine();
