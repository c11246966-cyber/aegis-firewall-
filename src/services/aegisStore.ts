/**
 * Aegis Core Unified Store Service
 * 
 * Orchestrates:
 * - Firewall Abstraction Layer (Windows WFP as primary, Linux nftables, Simulation)
 * - Multi-Vector Detection Engine
 * - Transparent Risk Engine & Auditable Factor Ledger
 * - Policy & Containment Engine
 * - Management Security & RBAC AuthService
 * - Immutable Cryptographic Audit Logger
 * - Threat Intelligence & IP Reputation
 * - Privileged Windows Service Helper
 */

import { 
  SecurityEvent, 
  SecurityAlert, 
  SecurityIncident, 
  FirewallRule, 
  RiskReport, 
  SystemStatus, 
  SimulationVector, 
  OperatingMode, 
  IncidentStatus,
  FirewallAction,
  PlatformType,
  FirewallBackendType,
  FirewallCapabilities,
  FirewallHealth,
  AuditRecord,
  ThreatIntelEntry,
  TestCaseResult,
  RuleDirection,
  NetworkProtocol
} from '../types/aegis';

import { firewallFAL } from './firewall/FirewallAbstractionLayer';
import { detectionEngine } from './security/DetectionEngine';
import { riskEngine } from './security/RiskEngine';
import { policyEngine } from './security/PolicyEngine';
import { authService } from './security/AuthService';
import { auditLogger } from './security/AuditLogger';
import { threatIntelService } from './security/ThreatIntelService';
import { privilegedWindowsService } from './security/PrivilegedWindowsService';
import { testRunner } from './testRunner';
import { playTacticalBlip } from '../utils/audio';

const STORAGE_KEY_EVENTS = 'aegis_events_v2';
const STORAGE_KEY_ALERTS = 'aegis_alerts_v2';
const STORAGE_KEY_INCIDENTS = 'aegis_incidents_v2';
const STORAGE_KEY_CONFIG = 'aegis_config_v2';

// Baseline initial security events
const INITIAL_EVENTS: SecurityEvent[] = [
  {
    id: 'EVT-9042',
    timestamp: Date.now() - 142000,
    vector: 'PORT_SCAN',
    sourceIp: '185.220.101.5',
    sourcePort: 49152,
    destIp: '192.168.1.10',
    destPort: 22,
    protocol: 'TCP',
    direction: 'INBOUND',
    signature: 'ET SCAN Potential Aggressive Port Sweep (Port 22)',
    severity: 'MEDIUM',
    riskDelta: 15,
    payloadPreview: 'SYN seq=28491024 win=1024 len=0 [Nmap/7.94 probe]',
    rawPacketHex: '45 00 00 28 1a 2b 40 00 40 06 2a 1c b9 dc 65 05 c0 00 02 0a',
    actionTaken: 'ALERTED',
    reputationScore: 24,
    threatIntelMatch: 'Tor Exit Node Match (Confidence: 96%)',
  },
  {
    id: 'EVT-9043',
    timestamp: Date.now() - 110000,
    vector: 'RDP_BRUTE_FORCE',
    sourceIp: '198.51.100.77',
    sourcePort: 54120,
    destIp: '192.168.1.10',
    destPort: 3389,
    protocol: 'TCP',
    direction: 'INBOUND',
    signature: 'ET POLICY Windows RDP (3389) High-Rate Credential Guessing Burst',
    severity: 'CRITICAL',
    riskDelta: 35,
    payloadPreview: 'T.125 RDP NegReq user=Administrator from 198.51.100.77',
    rawPacketHex: '03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00',
    actionTaken: 'BLOCKED',
    reputationScore: 12,
    threatIntelMatch: 'Known Brute Force Scanner (ASN: AS49981)',
  },
  {
    id: 'EVT-9044',
    timestamp: Date.now() - 65000,
    vector: 'OUTBOUND_BEACON',
    sourceIp: '192.168.1.10',
    sourcePort: 49812,
    destIp: '203.0.113.19',
    destPort: 4444,
    protocol: 'TCP',
    direction: 'OUTBOUND',
    processName: 'cmd.exe',
    processId: 3824,
    processPath: 'C:\\Windows\\System32\\cmd.exe',
    signature: 'ET TROJAN Suspicious Outbound C2 Reverse Shell Beaconing',
    severity: 'CRITICAL',
    riskDelta: 45,
    payloadPreview: 'POST /api/v2/telemetry/heartbeat HTTP/1.1 (cmd.exe reverse shell)',
    rawPacketHex: '50 4f 53 54 20 2f 61 70 69 2f 76 32 2f 74 65 6c 65 6d 65 74',
    actionTaken: 'BLOCKED',
    reputationScore: 5,
    threatIntelMatch: 'Active Botnet C2 Controller',
  },
];

const INITIAL_ALERTS: SecurityAlert[] = [
  {
    id: 'ALT-1091',
    eventId: 'EVT-9044',
    title: 'Outbound Reverse Shell Beacon Blocked (cmd.exe)',
    description: 'Process cmd.exe attempted unauthorized socket connection to known C2 server 203.0.113.19:4444.',
    timestamp: Date.now() - 65000,
    severity: 'CRITICAL',
    vector: 'OUTBOUND_BEACON',
    sourceIp: '203.0.113.19',
    destIp: '192.168.1.10',
    riskScore: 92,
    acknowledged: false,
    clusterCount: 1,
  },
  {
    id: 'ALT-1092',
    eventId: 'EVT-9043',
    title: 'Windows RDP Credential Stuffing Burst Mitigated',
    description: 'High-frequency NTLM logon failures against Windows RDP port 3389 from 198.51.100.77.',
    timestamp: Date.now() - 110000,
    severity: 'CRITICAL',
    vector: 'RDP_BRUTE_FORCE',
    sourceIp: '198.51.100.77',
    destIp: '192.168.1.10',
    riskScore: 88,
    acknowledged: false,
    clusterCount: 3,
  },
  {
    id: 'ALT-1093',
    eventId: 'EVT-9042',
    title: 'Horizontal Reconnaissance Sweep Detected',
    description: 'Port scan sequence across privileged TCP daemons from Tor exit node 185.220.101.5.',
    timestamp: Date.now() - 142000,
    severity: 'MEDIUM',
    vector: 'PORT_SCAN',
    sourceIp: '185.220.101.5',
    destIp: '192.168.1.10',
    riskScore: 54,
    acknowledged: true,
    clusterCount: 1,
  },
];

const INITIAL_INCIDENTS: SecurityIncident[] = [
  {
    id: 'INC-2026-001',
    title: 'Suspicious Windows Reverse Shell Outbound C2 Attempt',
    vector: 'OUTBOUND_BEACON',
    sourceIp: '203.0.113.19',
    destIp: '192.168.1.10',
    status: 'MITIGATED',
    riskScore: 94,
    createdAt: Date.now() - 65000,
    updatedAt: Date.now() - 50000,
    assignee: 'Lead SOC Analyst',
    logsCount: 18,
    timeline: [
      {
        id: 'TL-1',
        timestamp: Date.now() - 65000,
        action: 'INCIDENT_DETECTED',
        user: 'DetectionEngine',
        note: 'Correlation rule triggered on cmd.exe outbound TCP socket',
      },
      {
        id: 'TL-2',
        timestamp: Date.now() - 50000,
        action: 'WFP_CONTAINMENT',
        user: 'AegisWFPBackend',
        note: 'Created AEGIS-WFP-OUT-BLK-203.0.113.19 drop rule for program cmd.exe',
      },
    ],
    mitigatedByRuleId: 'AEGIS-WFP-OUT-BLK-203.0.113.19',
  },
  {
    id: 'INC-2026-002',
    title: 'Distributed Windows RDP (3389) Password Guessing Burst',
    vector: 'RDP_BRUTE_FORCE',
    sourceIp: '198.51.100.77',
    destIp: '192.168.1.10',
    status: 'INVESTIGATING',
    riskScore: 82,
    createdAt: Date.now() - 110000,
    updatedAt: Date.now() - 80000,
    assignee: 'SOC Analyst',
    logsCount: 42,
    timeline: [
      {
        id: 'TL-3',
        timestamp: Date.now() - 110000,
        action: 'THRESHOLD_BREACH',
        user: 'DetectionEngine',
        note: 'Threshold of 10 failed logon bursts per minute exceeded',
      },
    ],
  },
];

class AegisStoreService {
  private events: SecurityEvent[] = [];
  private alerts: SecurityAlert[] = [];
  private incidents: SecurityIncident[] = [];
  private mode: OperatingMode = 'SIMULATION';
  private soundEnabled: boolean = false;
  private subscribers: Set<() => void> = new Set();
  private ppsRate: number = 1840;
  private mbpsBandwidth: number = 18.2;
  private packetsAnalyzed: number = 512400;
  private lastSimulatedVector: SimulationVector | null = null;
  private uptimeSeconds: number = 54100;
  private emergencyLockdownActive: boolean = false;

  constructor() {
    this.loadFromStorage();
    this.hookAuditSync();
    this.startBackgroundTicker();
  }

  private hookAuditSync() {
    firewallFAL.setAuditCallback((entry) => {
      auditLogger.log({
        user: entry.user,
        role: entry.role,
        source: 'FirewallAbstractionLayer',
        action: entry.action,
        target: entry.target,
        result: entry.result,
        reason: entry.reason,
      });
    });
  }

  private loadFromStorage() {
    try {
      const storedEvents = localStorage.getItem(STORAGE_KEY_EVENTS);
      this.events = storedEvents ? JSON.parse(storedEvents) : INITIAL_EVENTS;

      const storedAlerts = localStorage.getItem(STORAGE_KEY_ALERTS);
      this.alerts = storedAlerts ? JSON.parse(storedAlerts) : INITIAL_ALERTS;

      const storedIncidents = localStorage.getItem(STORAGE_KEY_INCIDENTS);
      this.incidents = storedIncidents ? JSON.parse(storedIncidents) : INITIAL_INCIDENTS;

      const storedConfig = localStorage.getItem(STORAGE_KEY_CONFIG);
      if (storedConfig) {
        const config = JSON.parse(storedConfig);
        if (config.mode) {
          this.mode = config.mode;
          policyEngine.setMode(config.mode);
        }
        if (typeof config.soundEnabled === 'boolean') {
          this.soundEnabled = config.soundEnabled;
        }
      }
    } catch {
      this.events = INITIAL_EVENTS;
      this.alerts = INITIAL_ALERTS;
      this.incidents = INITIAL_INCIDENTS;
    }
  }

  private persist() {
    try {
      localStorage.setItem(STORAGE_KEY_EVENTS, JSON.stringify(this.events.slice(0, 500)));
      localStorage.setItem(STORAGE_KEY_ALERTS, JSON.stringify(this.alerts.slice(0, 200)));
      localStorage.setItem(STORAGE_KEY_INCIDENTS, JSON.stringify(this.incidents.slice(0, 50)));
      localStorage.setItem(STORAGE_KEY_CONFIG, JSON.stringify({
        mode: this.mode,
        soundEnabled: this.soundEnabled,
      }));
    } catch (e) {
      console.warn('LocalStorage quota or serialization error:', e);
    }
  }

  private startBackgroundTicker() {
    setInterval(() => {
      this.uptimeSeconds += 1;

      // Realistic telemetry jitter
      const jitter = (Math.random() - 0.5) * 60;
      this.ppsRate = Math.max(800, Math.floor(this.ppsRate + jitter));
      this.mbpsBandwidth = Math.max(5.0, Math.round((this.ppsRate * 0.0105 + (Math.random() - 0.5) * 0.5) * 10) / 10);
      this.packetsAnalyzed += Math.floor(this.ppsRate * 0.1);

      // Check TTL rule auto-expiration
      this.checkExpiredRules();

      this.notify();
    }, 1000);
  }

  private async checkExpiredRules() {
    const rules = await firewallFAL.listRules();
    const now = Date.now();
    for (const rule of rules) {
      if (rule.expiresAt && now >= rule.expiresAt) {
        await firewallFAL.remove_rule(rule.id, {
          user: 'SYSTEM_TTL_WORKER',
          role: 'ADMIN',
          source: 'AegisBackgroundTicker',
        });
        this.notify();
      }
    }
  }

  public subscribe(callback: () => void): () => void {
    this.subscribers.add(callback);
    return () => {
      this.subscribers.delete(callback);
    };
  }

  private notify() {
    this.subscribers.forEach((cb) => {
      try {
        cb();
      } catch (err) {
        console.error('Error in subscriber callback:', err);
      }
    });
  }

  // --- Platform & Backend Management ---

  public getPlatform(): PlatformType {
    return firewallFAL.getPlatform();
  }

  public setPlatform(platform: PlatformType, backendType?: FirewallBackendType) {
    firewallFAL.setPlatform(platform, backendType);
    auditLogger.log({
      user: authService.getCurrentSession()?.username || 'SYSTEM',
      role: authService.getCurrentUserRole(),
      source: 'SocHeader',
      action: 'PLATFORM_SWITCH',
      target: platform,
      result: 'SUCCESS',
      reason: `Platform context switched to ${platform} (${firewallFAL.getActiveBackendType()})`,
    });
    this.notify();
  }

  public getFirewallBackend(): FirewallBackendType {
    return firewallFAL.getActiveBackendType();
  }

  public getFirewallCapabilities(): FirewallCapabilities {
    return firewallFAL.getCapabilities();
  }

  public async getFirewallHealth(): Promise<FirewallHealth> {
    return await firewallFAL.healthCheck();
  }

  public async verifyFirewallState(): Promise<{ isTampered: boolean; activeAegisRules: number; message: string }> {
    return await firewallFAL.verifyState();
  }

  // --- Emergency Lockdown ---

  public async emergencyLockdown(): Promise<{ success: boolean; error?: string }> {
    const session = authService.getCurrentSession();
    const res = await firewallFAL.emergency_lockdown({
      user: session?.username || 'admin',
      role: session?.role || 'ADMIN',
      source: 'DashboardEmergencyButton',
    });
    if (res.success) {
      this.emergencyLockdownActive = true;
      if (this.soundEnabled) playTacticalBlip('alert');
    }
    this.notify();
    return res;
  }

  public async liftLockdown(): Promise<{ success: boolean; error?: string }> {
    const session = authService.getCurrentSession();
    const res = await firewallFAL.lift_lockdown({
      user: session?.username || 'admin',
      role: session?.role || 'ADMIN',
      source: 'DashboardEmergencyButton',
    });
    if (res.success) {
      this.emergencyLockdownActive = false;
      if (this.soundEnabled) playTacticalBlip('clear');
    }
    this.notify();
    return res;
  }

  // --- Getters ---

  public getEvents(): SecurityEvent[] {
    return [...this.events];
  }

  public getAlerts(): SecurityAlert[] {
    return [...this.alerts];
  }

  public getIncidents(): SecurityIncident[] {
    return [...this.incidents];
  }

  public getRules(): FirewallRule[] {
    // Synchronous snapshot of FAL rules
    let list: FirewallRule[] = [];
    firewallFAL.listRules().then(r => { list = r; });
    // Also return loaded rules
    return list;
  }

  public async listRulesAsync(): Promise<FirewallRule[]> {
    return await firewallFAL.listRules();
  }

  public getAuditRecords(): AuditRecord[] {
    return auditLogger.getRecords();
  }

  public getKnownThreats(): ThreatIntelEntry[] {
    return threatIntelService.getKnownThreats();
  }

  public getSystemStatus(): SystemStatus {
    return {
      platform: firewallFAL.getPlatform(),
      backend: firewallFAL.getActiveBackendType(),
      mode: this.mode,
      isSafeMode: this.mode !== 'ENFORCEMENT',
      uptimeSeconds: this.uptimeSeconds,
      packetsAnalyzed: this.packetsAnalyzed,
      activeBlocksCount: this.events.filter(e => e.actionTaken === 'BLOCKED').length,
      openIncidentsCount: this.incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING').length,
      trafficPps: this.ppsRate,
      bandwidthMbps: this.mbpsBandwidth,
      lastSimulatedVector: this.lastSimulatedVector,
      soundEnabled: this.soundEnabled,
      tamperDetected: false,
      emergencyLockdownActive: this.emergencyLockdownActive,
    };
  }

  public getRiskReport(): RiskReport {
    return riskEngine.calculateRisk(this.events.slice(0, 40), this.alerts, this.ppsRate);
  }

  public getCurrentUser() {
    return authService.getCurrentSession();
  }

  // --- Actions ---

  public setMode(newMode: OperatingMode) {
    this.mode = newMode;
    policyEngine.setMode(newMode);
    auditLogger.log({
      user: authService.getCurrentSession()?.username || 'operator',
      role: authService.getCurrentUserRole(),
      source: 'SocHeader',
      action: 'OPERATING_MODE_CHANGE',
      target: newMode,
      result: 'SUCCESS',
      reason: `Operating mode shifted to ${newMode}`,
    });
    this.persist();
    this.notify();
  }

  public toggleSound(): boolean {
    this.soundEnabled = !this.soundEnabled;
    this.persist();
    this.notify();
    return this.soundEnabled;
  }

  public acknowledgeAlert(id: string) {
    const alert = this.alerts.find(a => a.id === id);
    if (alert) {
      alert.acknowledged = true;
      if (this.soundEnabled) playTacticalBlip('clear');
      this.persist();
      this.notify();
    }
  }

  public acknowledgeAllAlerts() {
    this.alerts.forEach(a => { a.acknowledged = true; });
    if (this.soundEnabled) playTacticalBlip('clear');
    this.persist();
    this.notify();
  }

  public updateIncidentStatus(
    incidentId: string, 
    newStatus: IncidentStatus, 
    user: string = 'SOC-Analyst',
    note?: string
  ): boolean {
    const incident = this.incidents.find(i => i.id === incidentId);
    if (!incident) return false;

    incident.status = newStatus;
    incident.updatedAt = Date.now();
    incident.timeline.unshift({
      id: `TL-${Date.now()}`,
      timestamp: Date.now(),
      action: `STATUS_CHANGED_TO_${newStatus}`,
      user,
      note: note || `Triage status updated to ${newStatus}`,
    });

    auditLogger.log({
      user,
      role: authService.getCurrentUserRole(),
      source: 'IncidentManagement',
      action: 'INCIDENT_TRIAGE_UPDATE',
      target: incidentId,
      result: 'SUCCESS',
      reason: `Incident marked as ${newStatus}. Note: ${note || 'None'}`,
    });

    this.persist();
    this.notify();
    return true;
  }

  public addRule(
    ipCidr: string, 
    action: FirewallAction, 
    ttlSeconds: number, 
    reason: string,
    comment?: string,
    overrideSafeguard?: boolean,
    direction: RuleDirection = 'INBOUND',
    protocol: NetworkProtocol = 'TCP',
    portRange?: string,
    applicationPath?: string
  ): { success: boolean; error?: string; rule?: FirewallRule } {
    const session = authService.getCurrentSession();
    let res: { success: boolean; error?: string; rule?: FirewallRule } = { success: false };

    // Use FAL with current session
    firewallFAL.add_rule({
      ipCidr,
      action,
      ttlSeconds,
      reason,
      comment,
      direction,
      protocol,
      portRange,
      applicationPath,
    }, {
      user: session?.username || 'operator',
      role: session?.role || 'ADMIN',
      source: 'NetworkControlPanel',
      operatingMode: this.mode,
    }).then(r => {
      res = r;
      if (r.success) {
        if (this.soundEnabled) playTacticalBlip('block');
        this.notify();
      }
    });

    return res;
  }

  public removeRule(id: string): boolean {
    const session = authService.getCurrentSession();
    let ok = false;
    firewallFAL.remove_rule(id, {
      user: session?.username || 'operator',
      role: session?.role || 'ADMIN',
      source: 'NetworkControlPanel',
    }).then(r => {
      ok = r.success;
      if (r.success) {
        if (this.soundEnabled) playTacticalBlip('clear');
        this.notify();
      }
    });
    return ok;
  }

  // --- End-to-End Simulation Vector Execution ---

  public async simulateVector(vector: SimulationVector): Promise<{
    event: SecurityEvent;
    alert?: SecurityAlert;
    incident?: SecurityIncident;
    mitigatedRule?: FirewallRule;
  }> {
    this.lastSimulatedVector = vector;

    // Pick realistic vector source IP & port
    let srcIp = '198.51.100.99';
    let dstPort = 80;
    let procName: string | undefined;
    let procPath: string | undefined;
    let direction: RuleDirection = 'INBOUND';

    switch (vector) {
      case 'PORT_SCAN':
        srcIp = '185.220.101.5';
        dstPort = 443;
        break;
      case 'RDP_BRUTE_FORCE':
        srcIp = '198.51.100.77';
        dstPort = 3389; // Windows RDP
        break;
      case 'SSH_BRUTE_FORCE':
        srcIp = '198.51.100.82';
        dstPort = 22;
        break;
      case 'HTTP_ANOMALY':
        srcIp = '203.0.113.19';
        dstPort = 443;
        break;
      case 'SYN_FLOOD':
      case 'NETWORK_FLOOD':
        srcIp = '45.154.255.89';
        dstPort = 80;
        this.ppsRate += 12000;
        break;
      case 'UDP_FLOOD':
        srcIp = '45.154.255.91';
        dstPort = 53;
        this.ppsRate += 18000;
        break;
      case 'ICMP_ANOMALY':
        srcIp = '198.51.100.115';
        dstPort = 0;
        break;
      case 'DNS_ANOMALY':
        srcIp = '185.220.101.99';
        dstPort = 53;
        break;
      case 'OUTBOUND_BEACON':
        srcIp = '203.0.113.200';
        dstPort = 8443;
        procName = 'cmd.exe';
        procPath = 'C:\\Windows\\System32\\cmd.exe';
        direction = 'OUTBOUND';
        break;
      case 'PROCESS_CORRELATION':
        srcIp = '203.0.113.205';
        dstPort = 4444;
        procName = 'powershell.exe';
        procPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
        direction = 'OUTBOUND';
        break;
      default:
        srcIp = '198.51.100.120';
        dstPort = 8080;
        break;
    }

    // 1. Detection Engine processing
    const det = detectionEngine.processFlow(vector, srcIp, dstPort, {
      processName: procName,
      processPath: procPath,
      direction,
    });
    const event = det.event;

    // 2. Policy Engine evaluation
    const pol = policyEngine.evaluateEvent(event);

    let createdAlert: SecurityAlert | undefined;
    let createdIncident: SecurityIncident | undefined;
    let mitigatedRule: FirewallRule | undefined;

    // 3. Alert creation (respecting deduplication)
    if (pol.shouldAlert) {
      createdAlert = {
        id: `ALT-${Date.now().toString().slice(-4)}-${Math.floor(Math.random() * 90 + 10)}`,
        eventId: event.id,
        title: det.signature,
        description: `${det.signature} observed from ${event.sourceIp} targeting port ${event.destPort}.`,
        timestamp: Date.now(),
        severity: event.severity,
        vector,
        sourceIp: event.sourceIp,
        destIp: event.destIp,
        riskScore: Math.min(100, event.riskDelta * 2 + 30),
        acknowledged: false,
        clusterCount: pol.clusterCount,
      };
      this.alerts.unshift(createdAlert);
    }

    // 4. Incident creation for Critical/High severity
    if (event.severity === 'CRITICAL' || event.severity === 'HIGH') {
      const incId = `INC-${new Date().getFullYear()}-${Math.floor(Math.random() * 900 + 100)}`;
      createdIncident = {
        id: incId,
        title: `Security Threat: ${det.signature}`,
        vector,
        sourceIp: event.sourceIp,
        destIp: event.destIp,
        status: pol.shouldContain ? 'MITIGATED' : 'OPEN',
        riskScore: createdAlert?.riskScore || 75,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        assignee: 'Unassigned',
        logsCount: 1,
        timeline: [
          {
            id: `TL-INIT-${Date.now()}`,
            timestamp: Date.now(),
            action: 'INCIDENT_CREATED',
            user: 'DetectionPipeline',
            note: `Triggered by vector ${vector} (${det.signature})`,
          },
        ],
      };
      this.incidents.unshift(createdIncident);
    }

    // 5. Automated Firewall Containment (in ENFORCEMENT mode)
    if (pol.shouldContain) {
      event.actionTaken = 'BLOCKED';
      const session = authService.getCurrentSession();
      const res = await firewallFAL.block_ip(event.sourceIp, {
        direction: event.direction,
        protocol: event.protocol === 'HTTP' ? 'TCP' : event.protocol === 'DNS' ? 'UDP' : (event.protocol as NetworkProtocol),
        portRange: String(event.destPort),
        applicationPath: event.processPath,
        ttlSeconds: pol.ttlSeconds,
        reason: `Automated Quarantine: ${det.signature}`,
      }, {
        user: 'AegisPolicyAutomator',
        role: 'ADMIN',
        source: 'AutomatedContainment',
        operatingMode: this.mode,
      });

      if (res.success && res.rule) {
        mitigatedRule = res.rule;
        event.blockedByRuleId = res.rule.id;
        if (createdIncident) {
          createdIncident.status = 'MITIGATED';
          createdIncident.mitigatedByRuleId = res.rule.id;
          createdIncident.timeline.unshift({
            id: `TL-AUTO-DROP-${Date.now()}`,
            timestamp: Date.now(),
            action: 'AUTOMATED_WFP_DROP',
            user: 'AegisEnforcementEngine',
            note: `Enforced firewall rule ${res.rule.name} with TTL ${pol.ttlSeconds}s.`,
          });
        }
      }
    }

    this.events.unshift(event);

    // Audio cue
    if (this.soundEnabled) {
      if (event.severity === 'CRITICAL') playTacticalBlip('alert');
      else playTacticalBlip('click');
    }

    this.persist();
    this.notify();

    return {
      event,
      alert: createdAlert,
      incident: createdIncident,
      mitigatedRule,
    };
  }

  public async runAllTests(onProgress?: (done: number, total: number, cur: TestCaseResult) => void): Promise<TestCaseResult[]> {
    return await testRunner.runAllTests(onProgress);
  }

  public resetToDefaults() {
    this.events = [...INITIAL_EVENTS];
    this.alerts = [...INITIAL_ALERTS];
    this.incidents = [...INITIAL_INCIDENTS];
    this.mode = 'SIMULATION';
    policyEngine.setMode('SIMULATION');
    this.persist();
    this.notify();
  }
}

export const aegisStore = new AegisStoreService();
