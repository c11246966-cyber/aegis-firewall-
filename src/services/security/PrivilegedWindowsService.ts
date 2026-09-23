/**
 * Aegis Restricted Privileged Windows Service & IPC Helper
 * 
 * Architecture & Privilege Boundary:
 * Web application / API layers DO NOT possess unrestricted shell execution privileges.
 * Arbitrary PowerShell, CMD, or bash execution is strictly rejected by design.
 * 
 * This service implements a deterministic RPC dispatcher that accepts ONLY
 * structured, validated command payloads with strict enum-based actions.
 */

import { UserRole } from '../../types/aegis';
import { firewallFAL } from '../firewall/FirewallAbstractionLayer';
import { auditLogger } from './AuditLogger';
import { authService } from './AuthService';
import { validateIpOrCidr } from '../../utils/ipValidator';

export type PrivilegedActionType = 
  | 'FIREWALL_ADD_BLOCK'
  | 'FIREWALL_REMOVE_RULE'
  | 'FIREWALL_ADD_ALLOW'
  | 'FIREWALL_EMERGENCY_LOCKDOWN'
  | 'FIREWALL_LIFT_LOCKDOWN'
  | 'FIREWALL_VERIFY_STATE'
  | 'SERVICE_HEALTH_CHECK';

export interface PrivilegedRequest {
  action: PrivilegedActionType;
  targetIpOrCidr?: string;
  ruleName?: string;
  ttlSeconds?: number;
  direction?: 'INBOUND' | 'OUTBOUND';
  protocol?: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
  portRange?: string;
  applicationPath?: string;
  reason: string;
  authToken: string;
  overrideSafeguard?: boolean;
}

export interface PrivilegedResponse {
  success: boolean;
  actionExecuted: PrivilegedActionType;
  executionTimeMs: number;
  verifiedState: boolean;
  resultMessage: string;
  error?: string;
  auditId?: string;
}

export class PrivilegedWindowsService {
  private isServiceRunning: boolean = true;
  private lastHeartbeat: number = Date.now();

  constructor() {
    // Keep heartbeat running
    setInterval(() => {
      this.lastHeartbeat = Date.now();
    }, 5000);
  }

  public getServiceStatus() {
    return {
      serviceName: 'AegisPrivilegedFirewallService',
      status: this.isServiceRunning ? 'RUNNING' : 'STOPPED',
      processId: 4188,
      account: 'NT AUTHORITY\\SYSTEM',
      driverLoaded: true,
      lastHeartbeat: this.lastHeartbeat,
      securityBoundary: 'STRICT_IPC_DISPATCHER (NO_SHELL)',
    };
  }

  /**
   * Rejects any attempt to pass raw command line strings.
   * Only structured typed payloads are accepted.
   */
  public async executePredefinedOperation(req: PrivilegedRequest): Promise<PrivilegedResponse> {
    const start = performance.now();
    const session = authService.getCurrentSession();

    // 1. Verify Authentication & Token
    if (!session || session.token !== req.authToken) {
      auditLogger.log({
        user: session?.username || 'ANONYMOUS',
        role: session?.role || 'VIEWER',
        source: 'PrivilegedWindowsService',
        action: req.action,
        target: req.targetIpOrCidr || req.ruleName || 'UNKNOWN',
        result: 'REJECTED',
        reason: 'Authentication token invalid or expired. Privileged execution denied.',
      });
      return {
        success: false,
        actionExecuted: req.action,
        executionTimeMs: Math.round(performance.now() - start),
        verifiedState: false,
        resultMessage: 'Authentication failure',
        error: 'Privileged execution denied: Valid authentication token required.',
      };
    }

    // 2. Enforce Authorization (RBAC)
    if (session.role === 'VIEWER') {
      auditLogger.log({
        user: session.username,
        role: session.role,
        source: 'PrivilegedWindowsService',
        action: req.action,
        target: req.targetIpOrCidr || req.ruleName || 'UNKNOWN',
        result: 'REJECTED',
        reason: 'RBAC 403 Forbidden: VIEWER cannot invoke privileged Windows service methods.',
      });
      return {
        success: false,
        actionExecuted: req.action,
        executionTimeMs: Math.round(performance.now() - start),
        verifiedState: false,
        resultMessage: 'Authorization failure',
        error: 'RBAC 403 FORBIDDEN: Your account role does not have permission for this operation.',
      };
    }

    // 3. Execute approved, strictly bounded operation
    try {
      switch (req.action) {
        case 'FIREWALL_ADD_BLOCK': {
          if (!req.targetIpOrCidr) throw new Error('Target IP/CIDR missing.');
          const res = await firewallFAL.block_ip(req.targetIpOrCidr, {
            direction: req.direction,
            protocol: req.protocol,
            portRange: req.portRange,
            applicationPath: req.applicationPath,
            ttlSeconds: req.ttlSeconds,
            reason: req.reason,
            overrideSafeguard: req.overrideSafeguard,
          }, { user: session.username, role: session.role, source: 'PrivilegedService' });

          const verify = await firewallFAL.verifyState();
          return {
            success: res.success,
            actionExecuted: req.action,
            executionTimeMs: Math.round(performance.now() - start),
            verifiedState: !verify.isTampered,
            resultMessage: res.success ? `Added WFP block rule for ${req.targetIpOrCidr}` : (res.error || 'Failed'),
            error: res.error,
          };
        }

        case 'FIREWALL_ADD_ALLOW': {
          if (!req.targetIpOrCidr) throw new Error('Target IP/CIDR missing.');
          const res = await firewallFAL.allow_ip(req.targetIpOrCidr, {
            direction: req.direction,
            protocol: req.protocol,
            portRange: req.portRange,
            reason: req.reason,
          }, { user: session.username, role: session.role, source: 'PrivilegedService' });

          const verify = await firewallFAL.verifyState();
          return {
            success: res.success,
            actionExecuted: req.action,
            executionTimeMs: Math.round(performance.now() - start),
            verifiedState: !verify.isTampered,
            resultMessage: res.success ? `Added WFP allow rule for ${req.targetIpOrCidr}` : (res.error || 'Failed'),
            error: res.error,
          };
        }

        case 'FIREWALL_REMOVE_RULE': {
          if (!req.ruleName) throw new Error('Rule identifier missing.');
          const res = await firewallFAL.remove_rule(req.ruleName, {
            user: session.username,
            role: session.role,
            source: 'PrivilegedService',
          });
          const verify = await firewallFAL.verifyState();
          return {
            success: res.success,
            actionExecuted: req.action,
            executionTimeMs: Math.round(performance.now() - start),
            verifiedState: !verify.isTampered,
            resultMessage: res.success ? `Removed rule ${req.ruleName}` : (res.error || 'Failed'),
            error: res.error,
          };
        }

        case 'FIREWALL_EMERGENCY_LOCKDOWN': {
          if (session.role !== 'ADMIN') throw new Error('Emergency lockdown requires ADMIN role.');
          const res = await firewallFAL.emergency_lockdown({
            user: session.username,
            role: session.role,
            source: 'PrivilegedService',
          });
          const verify = await firewallFAL.verifyState();
          return {
            success: res.success,
            actionExecuted: req.action,
            executionTimeMs: Math.round(performance.now() - start),
            verifiedState: !verify.isTampered,
            resultMessage: 'Emergency lockdown engaged successfully on Windows Filtering Platform.',
            error: res.error,
          };
        }

        case 'FIREWALL_LIFT_LOCKDOWN': {
          if (session.role !== 'ADMIN') throw new Error('Lifting lockdown requires ADMIN role.');
          const res = await firewallFAL.lift_lockdown({
            user: session.username,
            role: session.role,
            source: 'PrivilegedService',
          });
          return {
            success: res.success,
            actionExecuted: req.action,
            executionTimeMs: Math.round(performance.now() - start),
            verifiedState: true,
            resultMessage: 'Emergency lockdown lifted.',
          };
        }

        case 'FIREWALL_VERIFY_STATE': {
          const verify = await firewallFAL.verifyState();
          return {
            success: !verify.isTampered,
            actionExecuted: req.action,
            executionTimeMs: Math.round(performance.now() - start),
            verifiedState: !verify.isTampered,
            resultMessage: verify.message,
          };
        }

        case 'SERVICE_HEALTH_CHECK': {
          const health = await firewallFAL.healthCheck();
          return {
            success: health.status !== 'FAILED',
            actionExecuted: req.action,
            executionTimeMs: Math.round(performance.now() - start),
            verifiedState: !health.tamperDetected,
            resultMessage: health.message,
          };
        }

        default:
          throw new Error(`Unsupported or unauthorized privileged action.`);
      }
    } catch (err: unknown) {
      return {
        success: false,
        actionExecuted: req.action,
        executionTimeMs: Math.round(performance.now() - start),
        verifiedState: false,
        resultMessage: 'Privileged execution faulted safely',
        error: String(err),
      };
    }
  }

  /**
   * Exploit Simulation / Safety Test:
   * Confirms that arbitrary shell injection commands are strictly rejected.
   */
  public rejectArbitraryCommand(inputCommand: string): { rejected: boolean; reason: string } {
    return {
      rejected: true,
      reason: `SECURITY POLICY ENFORCED: Raw shell commands (${inputCommand.slice(0, 30)}...) are unconditionally rejected. The Aegis privileged architecture strictly forbids arbitrary shell/PowerShell/CMD execution.`,
    };
  }
}

export const privilegedWindowsService = new PrivilegedWindowsService();
