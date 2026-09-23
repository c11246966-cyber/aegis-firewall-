/**
 * Firewall Backend Interface for Aegis Cross-Platform Architecture
 */
import { 
  FirewallRule, 
  FirewallCapabilities, 
  FirewallHealth, 
  FirewallAction,
  RuleDirection,
  NetworkProtocol,
  FirewallBackendType
} from '../../types/aegis';

export interface RuleOptions {
  name?: string;
  ipCidr: string;
  direction?: RuleDirection;
  action?: FirewallAction;
  protocol?: NetworkProtocol;
  portRange?: string;
  applicationPath?: string;
  ttlSeconds?: number;
  reason?: string;
  comment?: string;
  isTrustedManagement?: boolean;
}

export interface BackendOperationResult {
  success: boolean;
  rule?: FirewallRule;
  rulesAffected?: number;
  error?: string;
  commandExecuted?: string;
  verifiedState?: boolean;
}

export interface IFirewallBackend {
  readonly backendType: FirewallBackendType;
  getCapabilities(): FirewallCapabilities;
  healthCheck(): Promise<FirewallHealth>;
  verifyState(): Promise<{ isTampered: boolean; activeAegisRules: number; message: string }>;
  listRules(): Promise<FirewallRule[]>;

  block_ip(ip: string, options?: Partial<RuleOptions>): Promise<BackendOperationResult>;
  unblock_ip(ip: string): Promise<BackendOperationResult>;
  allow_ip(ip: string, options?: Partial<RuleOptions>): Promise<BackendOperationResult>;

  block_cidr(cidr: string, options?: Partial<RuleOptions>): Promise<BackendOperationResult>;
  unblock_cidr(cidr: string): Promise<BackendOperationResult>;

  temporary_block(target: string, ttlSeconds: number, reason: string): Promise<BackendOperationResult>;

  add_rule(options: RuleOptions): Promise<BackendOperationResult>;
  remove_rule(ruleIdOrName: string): Promise<BackendOperationResult>;
  restore_rule(rule: FirewallRule): Promise<BackendOperationResult>;

  emergency_lockdown(trustedManagementIps: string[]): Promise<BackendOperationResult>;
  lift_lockdown(): Promise<BackendOperationResult>;
}
