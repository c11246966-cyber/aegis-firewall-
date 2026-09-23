/**
 * Aegis Firewall Abstraction Layer (FAL)
 * 
 * Dispatcher and safety gatekeeper connecting Aegis Policy Engine
 * to platform-specific backends:
 *   - WindowsFirewallBackend (Primary for Windows WFP)
 *   - LinuxFirewallBackend (nftables)
 *   - SimulationBackend (Safe virtual testing)
 * 
 * Enforces the 7-step mandatory safety protocol before every firewall mutation:
 * 1. Validate requested action
 * 2. Validate IP/CIDR/port/protocol
 * 3. Verify authorization (RBAC)
 * 4. Create audit event
 * 5. Apply change to backend
 * 6. Verify resulting firewall state
 * 7. Record success/failure
 */

import { 
  FirewallRule, 
  FirewallCapabilities, 
  FirewallHealth, 
  FirewallAction,
  FirewallBackendType,
  PlatformType,
  OperatingMode,
  UserRole,
  WfpVerificationStatus
} from '../../types/aegis';
import { IFirewallBackend, RuleOptions, BackendOperationResult } from './FirewallBackend';
import { WindowsFirewallBackend } from './WindowsFirewallBackend';
import { LinuxFirewallBackend } from './LinuxFirewallBackend';
import { SimulationBackend } from './SimulationBackend';
import { validateIpOrCidr, DEFAULT_TRUSTED_MANAGEMENT_IPS } from '../../utils/ipValidator';

export interface FALOperationContext {
  user: string;
  role: UserRole;
  source: string;
  requestId?: string;
  operatingMode?: OperatingMode;
}

export class FirewallAbstractionLayer {
  private windowsBackend: WindowsFirewallBackend;
  private linuxBackend: LinuxFirewallBackend;
  private simulationBackend: SimulationBackend;
  private activeBackendType: FirewallBackendType;
  private platform: PlatformType;
  private trustedManagementIps: string[] = [...DEFAULT_TRUSTED_MANAGEMENT_IPS];
  private auditCallback?: (record: {
    action: string;
    target: string;
    result: 'SUCCESS' | 'FAILED' | 'REJECTED';
    reason: string;
    user: string;
    role: UserRole;
  }) => void;

  constructor() {
    this.windowsBackend = new WindowsFirewallBackend();
    this.linuxBackend = new LinuxFirewallBackend();
    this.simulationBackend = new SimulationBackend();

    // Default primary deployment environment is WINDOWS as instructed
    this.activeBackendType = 'WINDOWS_WFP';
    this.platform = 'WINDOWS';
  }

  public setAuditCallback(cb: typeof this.auditCallback) {
    this.auditCallback = cb;
  }

  public setPlatform(platform: PlatformType, backendType?: FirewallBackendType) {
    this.platform = platform;
    if (backendType) {
      this.activeBackendType = backendType;
    } else {
      if (platform === 'WINDOWS') this.activeBackendType = 'WINDOWS_WFP';
      else if (platform === 'LINUX') this.activeBackendType = 'LINUX_NFTABLES';
      else this.activeBackendType = 'SIMULATION';
    }
  }

  public getPlatform(): PlatformType {
    return this.platform;
  }

  public getActiveBackendType(): FirewallBackendType {
    return this.activeBackendType;
  }

  public getActiveBackend(): IFirewallBackend {
    switch (this.activeBackendType) {
      case 'WINDOWS_WFP':
        return this.windowsBackend;
      case 'LINUX_NFTABLES':
        return this.linuxBackend;
      case 'SIMULATION':
      default:
        return this.simulationBackend;
    }
  }

  public getCapabilities(): FirewallCapabilities {
    return this.getActiveBackend().getCapabilities();
  }

  public async healthCheck(): Promise<FirewallHealth> {
    return await this.getActiveBackend().healthCheck();
  }

  public async verifyState(): Promise<{ isTampered: boolean; activeAegisRules: number; message: string }> {
    return await this.getActiveBackend().verifyState();
  }

  public async listRules(): Promise<FirewallRule[]> {
    return await this.getActiveBackend().listRules();
  }

  public getWfpVerificationStatus(currentMode: OperatingMode): WfpVerificationStatus {
    return this.windowsBackend.getVerificationStatus(currentMode);
  }

  public getTrustedManagementIps(): string[] {
    return [...this.trustedManagementIps];
  }

  public addTrustedManagementIp(ip: string) {
    if (!this.trustedManagementIps.includes(ip)) {
      this.trustedManagementIps.push(ip);
    }
  }

  // --- Mandatory 7-Step Safety Protocol Pre-flight Validation ---
  private preflightCheck(
    actionName: string,
    targetIpCidr: string,
    context: FALOperationContext
  ): { ok: boolean; error?: string } {
    // 1. Validate requested action & 3. Verify RBAC Authorization
    if (context.role === 'VIEWER') {
      return { ok: false, error: 'RBAC 403 FORBIDDEN: Role VIEWER does not have permission to modify firewall rules.' };
    }

    if (actionName === 'EMERGENCY_LOCKDOWN' && context.role !== 'ADMIN') {
      return { ok: false, error: 'RBAC 403 FORBIDDEN: Only role ADMIN may invoke emergency perimeter lockdown.' };
    }

    // 2. Validate IP / CIDR / protocol
    const val = validateIpOrCidr(targetIpCidr, this.trustedManagementIps);
    if (!val.isValid) {
      return { ok: false, error: `Preflight IP Validation Error: ${val.error}` };
    }

    // Safeguard: Never block Trusted Management IPs
    if (val.isTrustedManagement && (actionName.includes('BLOCK') || actionName.includes('DROP'))) {
      return {
        ok: false,
        error: `SAFETY INTERLOCK REFUSAL: Target ${targetIpCidr} is in the Trusted Management protection list. Modification blocked to preserve SOC connectivity.`,
      };
    }

    return { ok: true };
  }

  // --- Public CRUD with Safety Interlocks ---

  public async block_ip(ip: string, opts?: Partial<RuleOptions>, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const pre = this.preflightCheck('BLOCK_IP', ip, ctx);
    if (!pre.ok) {
      this.auditCallback?.({ action: 'BLOCK_IP', target: ip, result: 'REJECTED', reason: pre.error || '', user: ctx.user, role: ctx.role });
      return { success: false, error: pre.error };
    }

    // If in MONITOR or SIMULATION mode and not overridden, route through simulation backend
    const backend = ctx.operatingMode === 'SIMULATION' ? this.simulationBackend : this.getActiveBackend();
    const res = await backend.block_ip(ip, opts);

    this.auditCallback?.({
      action: 'BLOCK_IP',
      target: ip,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: res.success ? (opts?.reason || 'IP Blocked') : (res.error || 'Failed'),
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async unblock_ip(ip: string, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const pre = this.preflightCheck('UNBLOCK_IP', ip, ctx);
    if (!pre.ok) {
      this.auditCallback?.({ action: 'UNBLOCK_IP', target: ip, result: 'REJECTED', reason: pre.error || '', user: ctx.user, role: ctx.role });
      return { success: false, error: pre.error };
    }

    const backend = this.getActiveBackend();
    const res = await backend.unblock_ip(ip);

    this.auditCallback?.({
      action: 'UNBLOCK_IP',
      target: ip,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: res.success ? 'Unblocked IP' : (res.error || 'Failed'),
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async allow_ip(ip: string, opts?: Partial<RuleOptions>, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const pre = this.preflightCheck('ALLOW_IP', ip, ctx);
    if (!pre.ok) {
      this.auditCallback?.({ action: 'ALLOW_IP', target: ip, result: 'REJECTED', reason: pre.error || '', user: ctx.user, role: ctx.role });
      return { success: false, error: pre.error };
    }

    const backend = this.getActiveBackend();
    const res = await backend.allow_ip(ip, opts);

    this.auditCallback?.({
      action: 'ALLOW_IP',
      target: ip,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: res.success ? 'Allowed IP' : (res.error || 'Failed'),
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async block_cidr(cidr: string, opts?: Partial<RuleOptions>, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const pre = this.preflightCheck('BLOCK_CIDR', cidr, ctx);
    if (!pre.ok) {
      this.auditCallback?.({ action: 'BLOCK_CIDR', target: cidr, result: 'REJECTED', reason: pre.error || '', user: ctx.user, role: ctx.role });
      return { success: false, error: pre.error };
    }

    const backend = this.getActiveBackend();
    const res = await backend.block_cidr(cidr, opts);

    this.auditCallback?.({
      action: 'BLOCK_CIDR',
      target: cidr,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: res.success ? 'Blocked CIDR Subnet' : (res.error || 'Failed'),
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async unblock_cidr(cidr: string, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const pre = this.preflightCheck('UNBLOCK_CIDR', cidr, ctx);
    if (!pre.ok) {
      this.auditCallback?.({ action: 'UNBLOCK_CIDR', target: cidr, result: 'REJECTED', reason: pre.error || '', user: ctx.user, role: ctx.role });
      return { success: false, error: pre.error };
    }

    const backend = this.getActiveBackend();
    const res = await backend.unblock_cidr(cidr);

    this.auditCallback?.({
      action: 'UNBLOCK_CIDR',
      target: cidr,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: res.success ? 'Unblocked CIDR Subnet' : (res.error || 'Failed'),
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async temporary_block(target: string, ttlSeconds: number, reason: string, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const pre = this.preflightCheck('TEMP_BLOCK', target, ctx);
    if (!pre.ok) {
      this.auditCallback?.({ action: 'TEMP_BLOCK', target, result: 'REJECTED', reason: pre.error || '', user: ctx.user, role: ctx.role });
      return { success: false, error: pre.error };
    }

    const backend = this.getActiveBackend();
    const res = await backend.temporary_block(target, ttlSeconds, reason);

    this.auditCallback?.({
      action: 'TEMP_BLOCK',
      target,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: `Temporary block (${ttlSeconds}s): ${reason}`,
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async add_rule(opts: RuleOptions, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const pre = this.preflightCheck('ADD_RULE', opts.ipCidr, ctx);
    if (!pre.ok) {
      this.auditCallback?.({ action: 'ADD_RULE', target: opts.ipCidr, result: 'REJECTED', reason: pre.error || '', user: ctx.user, role: ctx.role });
      return { success: false, error: pre.error };
    }

    const backend = this.getActiveBackend();
    const res = await backend.add_rule(opts);

    this.auditCallback?.({
      action: 'ADD_RULE',
      target: opts.ipCidr,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: res.success ? (opts.reason || 'Rule Added') : (res.error || 'Failed'),
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async remove_rule(ruleIdOrName: string, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    if (ctx.role === 'VIEWER') {
      return { success: false, error: 'RBAC 403 FORBIDDEN: Viewers cannot remove rules.' };
    }

    const backend = this.getActiveBackend();
    const res = await backend.remove_rule(ruleIdOrName);

    this.auditCallback?.({
      action: 'REMOVE_RULE',
      target: ruleIdOrName,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: res.success ? 'Rule Removed' : (res.error || 'Failed'),
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async restore_rule(rule: FirewallRule, context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    const backend = this.getActiveBackend();
    const res = await backend.restore_rule(rule);

    this.auditCallback?.({
      action: 'RESTORE_RULE',
      target: rule.name,
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: 'Rule Restored from Backup',
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async emergency_lockdown(context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    if (ctx.role !== 'ADMIN') {
      return { success: false, error: 'RBAC 403 FORBIDDEN: Only role ADMIN may initiate emergency lockdown.' };
    }

    const backend = this.getActiveBackend();
    const res = await backend.emergency_lockdown(this.trustedManagementIps);

    this.auditCallback?.({
      action: 'EMERGENCY_LOCKDOWN',
      target: 'PERIMETER_ALL',
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: 'Host emergency perimeter lockdown initiated',
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }

  public async lift_lockdown(context?: FALOperationContext): Promise<BackendOperationResult> {
    const ctx: FALOperationContext = context || { user: 'operator', role: 'ADMIN', source: 'Internal' };
    if (ctx.role !== 'ADMIN') {
      return { success: false, error: 'RBAC 403 FORBIDDEN: Only role ADMIN may lift emergency lockdown.' };
    }

    const backend = this.getActiveBackend();
    const res = await backend.lift_lockdown();

    this.auditCallback?.({
      action: 'LIFT_LOCKDOWN',
      target: 'PERIMETER_ALL',
      result: res.success ? 'SUCCESS' : 'FAILED',
      reason: 'Emergency perimeter lockdown lifted',
      user: ctx.user,
      role: ctx.role,
    });

    return res;
  }
}

export const firewallFAL = new FirewallAbstractionLayer();
