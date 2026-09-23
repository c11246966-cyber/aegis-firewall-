/**
 * Aegis Cross-Platform Advanced Firewall / IDS / IPS Types
 * Architected for Windows Filtering Platform (WFP) as primary,
 * Linux nftables, and Simulation backends.
 */

export type PlatformType = 'WINDOWS' | 'LINUX' | 'SIMULATION';
export type FirewallBackendType = 'WINDOWS_WFP' | 'LINUX_NFTABLES' | 'SIMULATION';

export type OperatingMode = 'MONITOR' | 'SIMULATION' | 'ENFORCEMENT';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type IncidentStatus = 
  | 'OPEN' 
  | 'INVESTIGATING' 
  | 'MITIGATED' 
  | 'RESOLVED' 
  | 'FALSE_POSITIVE';

export type FirewallAction = 'DROP' | 'REJECT' | 'ALLOW';
export type RuleDirection = 'INBOUND' | 'OUTBOUND';
export type NetworkProtocol = 'TCP' | 'UDP' | 'ICMP' | 'ANY';

export type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'OPERATOR' | 'VIEWER';

export type SimulationVector = 
  | 'PORT_SCAN' 
  | 'SSH_BRUTE_FORCE' 
  | 'RDP_BRUTE_FORCE'
  | 'HTTP_ANOMALY' 
  | 'NETWORK_FLOOD'
  | 'SYN_FLOOD'
  | 'UDP_FLOOD'
  | 'ICMP_ANOMALY'
  | 'DNS_ANOMALY'
  | 'OUTBOUND_BEACON'
  | 'PROCESS_CORRELATION'
  | 'LOW_AND_SLOW'
  | 'DISTRIBUTED_ATTACK';

export interface UserSession {
  username: string;
  role: UserRole;
  token: string;
  loginTime: number;
  expiresAt: number;
  mfaVerified: boolean;
}

export interface SecurityEvent {
  id: string;
  timestamp: number;
  vector: SimulationVector;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'ICMP' | 'DNS';
  direction: RuleDirection;
  processName?: string;
  processId?: number;
  processPath?: string;
  signature: string;
  severity: SeverityLevel;
  riskDelta: number;
  payloadPreview: string;
  rawPacketHex: string;
  actionTaken: 'LOGGED' | 'ALERTED' | 'BLOCKED' | 'SIMULATED_BLOCK' | 'RATE_LIMITED' | 'QUARANTINED';
  blockedByRuleId?: string;
  reputationScore?: number;
  threatIntelMatch?: string;
}

export interface SecurityAlert {
  id: string;
  eventId?: string;
  title: string;
  description: string;
  timestamp: number;
  severity: SeverityLevel;
  vector: SimulationVector;
  sourceIp: string;
  destIp?: string;
  riskScore: number;
  acknowledged: boolean;
  clusterCount?: number; // Alert deduplication count
  lastSeen?: number;
}

export interface IncidentTimelineItem {
  id: string;
  timestamp: number;
  action: string;
  user: string;
  note?: string;
}

export interface SecurityIncident {
  id: string;
  title: string;
  vector: SimulationVector;
  sourceIp: string;
  destIp?: string;
  status: IncidentStatus;
  riskScore: number;
  createdAt: number;
  updatedAt: number;
  assignee: string;
  logsCount: number;
  timeline: IncidentTimelineItem[];
  mitigatedByRuleId?: string;
}

export interface FirewallRule {
  id: string;
  name: string; // Must begin with AEGIS-RULE- or AEGIS-WFP-
  ipCidr: string;
  ipVersion: 'IPv4' | 'IPv6';
  direction: RuleDirection;
  action: FirewallAction;
  protocol: NetworkProtocol;
  portRange?: string; // e.g. "3389", "80,443", "1024-65535", "ANY"
  applicationPath?: string; // Process/Application filtering (Windows WFP support)
  ttlSeconds: number; // 0 = permanent
  createdAt: number;
  expiresAt: number | null;
  reason: string;
  hits: number;
  chainOrGroup: string; // e.g. 'AEGIS-WFP-FILTER' or 'aegis_blacklist'
  isAegisManaged: boolean; // Flag ensuring Aegis never touches third-party rules
  isTrustedManagement?: boolean; // Protected from accidental block
  stateful: boolean;
  comment?: string;
}

export interface RiskFactor {
  factor: string;
  score: number;
  category: 'REPUTATION' | 'VELOCITY' | 'AUTH' | 'PROTOCOL' | 'BURST' | 'PROCESS' | 'DNS';
  description: string;
}

export interface RiskReport {
  currentScore: number; // 0 - 100
  threatLevel: 'DEFCON 5 (NORMAL)' | 'DEFCON 4 (GUARDED)' | 'DEFCON 3 (ELEVATED)' | 'DEFCON 2 (HIGH)' | 'DEFCON 1 (CRITICAL)';
  threatColor: string;
  vectorBreakdown: {
    portScan: number;
    sshRdpBruteForce: number;
    httpAnomaly: number;
    networkFlood: number;
    dnsAnomaly: number;
    outboundBeacon: number;
  };
  factors: RiskFactor[]; // Transparent score breakdown
  activeThreatsCount: number;
  blockedAttemptsCount: number;
  recentTrend: 'UP' | 'DOWN' | 'STABLE';
}

export interface AuditRecord {
  id: string;
  timestamp: number;
  requestId: string;
  user: string;
  role: UserRole;
  source: string; // e.g. 'WebUI', 'REST-API', 'CLI', 'PrivilegedService'
  action: string; // e.g. 'RULE_CREATE', 'IP_BLOCK', 'EMERGENCY_LOCKDOWN', 'LOGIN_FAILED'
  target: string;
  result: 'SUCCESS' | 'FAILED' | 'REJECTED';
  reason: string;
  hash: string; // Cryptographic audit chaining
}

export interface FirewallCapabilities {
  backend: FirewallBackendType;
  platform: PlatformType;
  ipv4Supported: boolean;
  ipv6Supported: boolean;
  inboundFiltering: boolean;
  outboundFiltering: boolean;
  statefulFiltering: boolean;
  portFiltering: boolean;
  applicationFiltering: boolean;
  ttlAutoExpiration: boolean;
  emergencyLockdown: boolean;
  tamperDetection: boolean;
  trustedManagementProtection: boolean;
}

export interface FirewallHealth {
  status: 'HEALTHY' | 'DEGRADED' | 'FAILED';
  backend: FirewallBackendType;
  driverState: 'WFP_ACTIVE' | 'NFTABLES_ACTIVE' | 'SIMULATION_ACTIVE';
  totalRules: number;
  aegisRulesCount: number;
  lastStateVerification: number;
  tamperDetected: boolean;
  syncDrift: boolean;
  message: string;
}

export interface SystemStatus {
  platform: PlatformType;
  backend: FirewallBackendType;
  mode: OperatingMode;
  isSafeMode: boolean;
  uptimeSeconds: number;
  packetsAnalyzed: number;
  activeBlocksCount: number;
  openIncidentsCount: number;
  trafficPps: number;
  bandwidthMbps: number;
  lastSimulatedVector: SimulationVector | null;
  soundEnabled: boolean;
  tamperDetected: boolean;
  emergencyLockdownActive: boolean;
}

export interface ThreatIntelEntry {
  ipOrCidr: string;
  threatType: 'TOR_EXIT' | 'BOTNET_C2' | 'BRUTE_FORCE' | 'SCANNER' | 'SUSPICIOUS_ASN';
  confidence: number; // 0 - 100
  country: string;
  asn: string;
  reportedIncidents: number;
  lastSeen: number;
}

export interface ProcessCorrelationInfo {
  pid: number;
  name: string;
  path: string;
  user: string;
  parentProcess: string;
  networkConnections: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'SUSPICIOUS';
}

export interface TestCaseResult {
  id: string;
  name: string;
  category: 'WINDOWS_WFP' | 'LINUX_NFTABLES' | 'SIMULATION' | 'VALIDATION' | 'RBAC' | 'SAFETY' | 'PIPELINE';
  status: 'PASS' | 'FAIL' | 'PENDING' | 'SKIPPED';
  durationMs: number;
  assertionsCount: number;
  details: string;
  errorMessage?: string;
}

export interface WfpVerificationStatus {
  backend: string;
  mode: OperatingMode;
  backendStatus: 'SIMULATION' | 'REAL ENFORCEMENT';
  service: 'RUNNING' | 'STOPPED';
  firewallApi: 'AVAILABLE' | 'UNAVAILABLE';
  lastRuleOperation: {
    action: 'BLOCK' | 'UNBLOCK' | 'ALLOW';
    status: 'SUCCESS' | 'FAILED';
    target: string;
    timestamp: number;
    ruleName?: string;
    error?: string;
  } | null;
  ruleVerification: 'VERIFIED' | 'NOT VERIFIED';
  selfTestPassed: boolean;
  isRealWindowsHost: boolean;
  statusNote: string;
}
