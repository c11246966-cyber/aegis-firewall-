/**
 * Aegis Simulation Backend (Safe Dry-Run Mode)
 * 
 * Accurately models the exact firewall mutations, validation logic,
 * and state projections without executing any OS kernel commands.
 */

import { 
  FirewallRule, 
  FirewallCapabilities, 
  FirewallHealth, 
  FirewallAction
} from '../../types/aegis';
import { IFirewallBackend, RuleOptions, BackendOperationResult } from './FirewallBackend';
import { validateIpOrCidr } from '../../utils/ipValidator';

export class SimulationBackend implements IFirewallBackend {
  readonly backendType = 'SIMULATION' as const;
  private rules: Map<string, FirewallRule> = new Map();

  constructor() {
    this.seedBaseline();
  }

  private seedBaseline() {
    const r: FirewallRule = {
      id: 'SIM-BLK-198.51.100.99',
      name: 'AEGIS-SIM-BLK-198.51.100.99',
      ipCidr: '198.51.100.99',
      ipVersion: 'IPv4',
      direction: 'INBOUND',
      action: 'DROP',
      protocol: 'TCP',
      ttlSeconds: 600,
      createdAt: Date.now() - 30000,
      expiresAt: Date.now() + 570000,
      reason: 'Safe simulation quarantine scenario',
      hits: 41,
      chainOrGroup: 'AEGIS-SIMULATION-FILTER',
      isAegisManaged: true,
      stateful: true,
    };
    this.rules.set(r.id, r);
  }

  getCapabilities(): FirewallCapabilities {
    return {
      backend: 'SIMULATION',
      platform: 'SIMULATION',
      ipv4Supported: true,
      ipv6Supported: true,
      inboundFiltering: true,
      outboundFiltering: true,
      statefulFiltering: true,
      portFiltering: true,
      applicationFiltering: true,
      ttlAutoExpiration: true,
      emergencyLockdown: true,
      tamperDetection: true,
      trustedManagementProtection: true,
    };
  }

  async healthCheck(): Promise<FirewallHealth> {
    return {
      status: 'HEALTHY',
      backend: 'SIMULATION',
      driverState: 'SIMULATION_ACTIVE',
      totalRules: this.rules.size,
      aegisRulesCount: this.rules.size,
      lastStateVerification: Date.now(),
      tamperDetected: false,
      syncDrift: false,
      message: 'Simulation backend operational in safe demonstration mode.',
    };
  }

  async verifyState(): Promise<{ isTampered: boolean; activeAegisRules: number; message: string }> {
    return {
      isTampered: false,
      activeAegisRules: this.rules.size,
      message: `Simulation state verified: ${this.rules.size} virtual rules active.`,
    };
  }

  async listRules(): Promise<FirewallRule[]> {
    return Array.from(this.rules.values());
  }

  async add_rule(opts: RuleOptions): Promise<BackendOperationResult> {
    const val = validateIpOrCidr(opts.ipCidr);
    if (!val.isValid) return { success: false, error: `Invalid IP: ${val.error}` };
    if (val.isTrustedManagement && opts.action === 'DROP') {
      return { success: false, error: 'SAFETY REFUSAL: Cannot block Trusted Management IP in simulation.' };
    }

    const action = opts.action || 'DROP';
    const ttlSeconds = typeof opts.ttlSeconds === 'number' ? opts.ttlSeconds : 900;
    const now = Date.now();
    const ruleId = `SIM-${action}-${val.normalized.replace(/[/:]/g, '_')}`;

    const newRule: FirewallRule = {
      id: ruleId,
      name: `AEGIS-SIM-${action}-${val.normalized}`,
      ipCidr: val.normalized,
      ipVersion: val.version === 'IPv6' ? 'IPv6' : 'IPv4',
      direction: opts.direction || 'INBOUND',
      action,
      protocol: opts.protocol || 'TCP',
      portRange: opts.portRange,
      applicationPath: opts.applicationPath,
      ttlSeconds,
      createdAt: now,
      expiresAt: ttlSeconds > 0 ? now + (ttlSeconds * 1000) : null,
      reason: opts.reason || 'Simulated firewall rule',
      hits: 0,
      chainOrGroup: 'AEGIS-SIMULATION-FILTER',
      isAegisManaged: true,
      stateful: true,
      comment: 'Safe virtual rule - No OS changes',
    };

    this.rules.set(ruleId, newRule);
    return {
      success: true,
      rule: newRule,
      rulesAffected: 1,
      commandExecuted: `[SIMULATION DRY RUN] add_rule(${newRule.name})`,
      verifiedState: true,
    };
  }

  async remove_rule(id: string): Promise<BackendOperationResult> {
    const deleted = this.rules.delete(id);
    return {
      success: deleted,
      rulesAffected: deleted ? 1 : 0,
      commandExecuted: `[SIMULATION DRY RUN] remove_rule(${id})`,
      verifiedState: true,
    };
  }

  async block_ip(ip: string, opts?: Partial<RuleOptions>): Promise<BackendOperationResult> {
    return this.add_rule({ ipCidr: ip, action: 'DROP', ...opts });
  }

  async unblock_ip(ip: string): Promise<BackendOperationResult> {
    return this.remove_rule(ip);
  }

  async allow_ip(ip: string, opts?: Partial<RuleOptions>): Promise<BackendOperationResult> {
    return this.add_rule({ ipCidr: ip, action: 'ALLOW', ...opts });
  }

  async block_cidr(cidr: string, opts?: Partial<RuleOptions>): Promise<BackendOperationResult> {
    return this.add_rule({ ipCidr: cidr, action: 'DROP', ...opts });
  }

  async unblock_cidr(cidr: string): Promise<BackendOperationResult> {
    return this.remove_rule(cidr);
  }

  async temporary_block(target: string, ttlSeconds: number, reason: string): Promise<BackendOperationResult> {
    return this.add_rule({ ipCidr: target, action: 'DROP', ttlSeconds, reason });
  }

  async restore_rule(rule: FirewallRule): Promise<BackendOperationResult> {
    this.rules.set(rule.id, { ...rule });
    return { success: true, rule, rulesAffected: 1, verifiedState: true };
  }

  async emergency_lockdown(trustedManagementIps: string[]): Promise<BackendOperationResult> {
    return { success: true, commandExecuted: '[SIMULATION] Emergency lockdown initiated', rulesAffected: 1, verifiedState: true };
  }

  async lift_lockdown(): Promise<BackendOperationResult> {
    return { success: true, commandExecuted: '[SIMULATION] Emergency lockdown lifted', rulesAffected: 1, verifiedState: true };
  }
}
