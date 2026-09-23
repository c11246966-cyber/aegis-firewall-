/**
 * Aegis Cross-Platform Advanced Firewall / IDS / IPS Dashboard
 * 
 * Primary Dev & Deployment Target: Windows (WFP Native)
 * Cross-Platform Support: Linux (nftables), Virtual Simulation Sandbox
 */

import React, { useState, useEffect } from 'react';
import { aegisStore } from './services/aegisStore';
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
  RuleDirection,
  NetworkProtocol,
  FirewallHealth
} from './types/aegis';

import { SocHeader } from './components/SocHeader';
import { CrossPlatformBar } from './components/CrossPlatformBar';
import { SafetyBanner } from './components/SafetyBanner';
import { SimulationDeck } from './components/SimulationDeck';
import { RiskGauge } from './components/RiskGauge';
import { AlertSystem } from './components/AlertSystem';
import { EventTracker } from './components/EventTracker';
import { IncidentManagement } from './components/IncidentManagement';
import { NetworkControl } from './components/NetworkControl';
import { ThreatIntelPanel } from './components/ThreatIntelPanel';
import { AuditLogViewer } from './components/AuditLogViewer';
import { TestRunnerPanel } from './components/TestRunnerPanel';
import { CliTerminal } from './components/CliTerminal';
import { ApiExplorer } from './components/ApiExplorer';
import { RiskBreakdownModal } from './components/RiskBreakdownModal';
import { authService } from './services/security/AuthService';

export default function App() {
  const [events, setEvents] = useState<SecurityEvent[]>(aegisStore.getEvents());
  const [alerts, setAlerts] = useState<SecurityAlert[]>(aegisStore.getAlerts());
  const [incidents, setIncidents] = useState<SecurityIncident[]>(aegisStore.getIncidents());
  const [rules, setRules] = useState<FirewallRule[]>(aegisStore.getRules());
  const [status, setStatus] = useState<SystemStatus>(aegisStore.getSystemStatus());
  const [risk, setRisk] = useState<RiskReport>(aegisStore.getRiskReport());
  const [capabilities, setCapabilities] = useState(aegisStore.getFirewallCapabilities());
  const [health, setHealth] = useState<FirewallHealth>({
    status: 'HEALTHY',
    backend: 'WINDOWS_WFP',
    driverState: 'WFP_ACTIVE',
    totalRules: 4,
    aegisRulesCount: 4,
    lastStateVerification: Date.now(),
    tamperDetected: false,
    syncDrift: false,
    message: 'WFP sublayer driver active',
  });

  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [safetyModalOpen, setSafetyModalOpen] = useState(false);
  const [riskModalOpen, setRiskModalOpen] = useState(false);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [presetFirewallIp, setPresetFirewallIp] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Subscribe to reactive store changes
  useEffect(() => {
    const unsubscribe = aegisStore.subscribe(async () => {
      setEvents(aegisStore.getEvents());
      setAlerts(aegisStore.getAlerts());
      setIncidents(aegisStore.getIncidents());
      setRules(await aegisStore.listRulesAsync());
      setStatus(aegisStore.getSystemStatus());
      setRisk(aegisStore.getRiskReport());
      setCapabilities(aegisStore.getFirewallCapabilities());
      const h = await aegisStore.getFirewallHealth();
      setHealth(h);
    });

    // Initial async rules fetch
    aegisStore.listRulesAsync().then(r => setRules(r));
    aegisStore.getFirewallHealth().then(h => setHealth(h));

    return () => unsubscribe();
  }, []);

  const showNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 5000);
  };

  const handleSelectMode = (mode: OperatingMode) => {
    aegisStore.setMode(mode);
    showNotice(`Operating mode switched to: ${mode}`);
  };

  const handleSelectPlatform = (platform: PlatformType) => {
    aegisStore.setPlatform(platform);
    showNotice(`Deployment platform switched to: ${platform}`);
  };

  const handleSimulate = async (vector: SimulationVector) => {
    const res = await aegisStore.simulateVector(vector);
    if (status.mode === 'ENFORCEMENT' && res.mitigatedRule) {
      showNotice(`[ENFORCEMENT AUTO-CONTAINMENT] Threat mitigated! WFP rule ${res.mitigatedRule.name} applied to drop ${res.mitigatedRule.ipCidr}`);
    }
    return res;
  };

  const handleAcknowledgeAlert = (id: string) => {
    aegisStore.acknowledgeAlert(id);
  };

  const handleAcknowledgeAllAlerts = () => {
    aegisStore.acknowledgeAllAlerts();
    showNotice('All active alerts marked as acknowledged.');
  };

  const handleInspectEvent = (eventId?: string) => {
    if (eventId) {
      setSelectedEventId(eventId);
      setActiveTab('dashboard');
      const el = document.getElementById('events-section');
      el?.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleUpdateIncidentStatus = (id: string, newStatus: IncidentStatus, note?: string) => {
    const user = authService.getCurrentSession()?.username || 'SOC-Analyst';
    const ok = aegisStore.updateIncidentStatus(id, newStatus, user, note);
    if (ok) {
      showNotice(`Incident ${id} triage updated to ${newStatus}`);
    }
  };

  const handleAddRule = (
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
  ) => {
    const res = aegisStore.addRule(
      ipCidr, 
      action, 
      ttlSeconds, 
      reason, 
      comment, 
      overrideSafeguard,
      direction,
      protocol,
      portRange,
      applicationPath
    );
    if (res.success) {
      showNotice(`Rule provisioned successfully to ${status.backend} for ${ipCidr}`);
    }
    return res;
  };

  const handleRemoveRule = (id: string) => {
    const ok = aegisStore.removeRule(id);
    if (ok) {
      showNotice(`Rule deleted safely from active firewall.`);
    }
  };

  const handleQuickBlockFromAlert = (ip: string) => {
    setPresetFirewallIp(ip);
    setActiveTab('firewall');
  };

  const handleEmergencyLockdown = async () => {
    const res = await aegisStore.emergencyLockdown();
    if (res.success) {
      showNotice('EMERGENCY LOCKDOWN ENGAGED: Inbound traffic dropped across WFP perimeter. Management IPs preserved.');
    } else {
      showNotice(`Lockdown failed: ${res.error}`);
    }
  };

  const handleLiftLockdown = async () => {
    const res = await aegisStore.liftLockdown();
    if (res.success) {
      showNotice('Lockdown lifted. Normal firewall filtering restored.');
    } else {
      showNotice(`Lift lockdown failed: ${res.error}`);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* SOC Tactical Header */}
      <SocHeader
        status={status}
        risk={risk}
        onSelectMode={handleSelectMode}
        onSelectPlatform={handleSelectPlatform}
        onToggleSound={() => aegisStore.toggleSound()}
        onOpenSafetyModal={() => setSafetyModalOpen(true)}
        onOpenRiskModal={() => setRiskModalOpen(true)}
        onResetData={() => {
          if (confirm('Reset Aegis state to baseline demonstration data?')) {
            aegisStore.resetToDefaults();
            showNotice('Aegis state reset to baseline.');
          }
        }}
        onEmergencyLockdown={handleEmergencyLockdown}
        onLiftLockdown={handleLiftLockdown}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-4 space-y-4">
        {/* Dynamic Action Notice Toast */}
        {actionNotice && (
          <div className="p-2.5 bg-cyan-950/80 border border-cyan-500/70 rounded text-xs font-mono-code text-cyan-200 shadow-[0_0_15px_rgba(6,182,212,0.2)] animate-fadeIn flex items-center justify-between">
            <span>{actionNotice}</span>
            <button onClick={() => setActionNotice(null)} className="text-cyan-400 hover:text-cyan-200 text-xs font-bold cursor-pointer">
              ✕
            </button>
          </div>
        )}

        {/* Cross-Platform Bar: OS, Backend, Health, Capabilities, and State Verification */}
        <CrossPlatformBar
          platform={status.platform}
          backend={status.backend}
          capabilities={capabilities}
          health={health}
          mode={status.mode}
          onVerifyState={() => aegisStore.verifyFirewallState()}
        />

        {/* Tab 1: SOC Main Dashboard */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Top Grid: Risk Gauge & Simulation Deck */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              <div className="lg:col-span-4">
                <RiskGauge risk={risk} mode={status.mode} />
              </div>
              <div className="lg:col-span-8">
                <SimulationDeck
                  currentMode={status.mode}
                  onSimulate={handleSimulate}
                />
              </div>
            </div>

            {/* Middle: Real-time Alerts System */}
            <div>
              <AlertSystem
                alerts={alerts}
                onAcknowledge={handleAcknowledgeAlert}
                onAcknowledgeAll={handleAcknowledgeAllAlerts}
                onInspectEvent={handleInspectEvent}
              />
            </div>

            {/* Bottom: Security Events Tracker */}
            <div id="events-section">
              <EventTracker
                events={events}
                selectedEventId={selectedEventId}
                onSelectEvent={(id) => setSelectedEventId(id)}
                onBlockIp={(ip) => handleQuickBlockFromAlert(ip)}
              />
            </div>
          </div>
        )}

        {/* Tab 2: Windows WFP / Firewall & Network Control */}
        {activeTab === 'firewall' && (
          <NetworkControl
            platform={status.platform}
            rules={rules}
            onAddRule={handleAddRule}
            onRemoveRule={handleRemoveRule}
            presetTargetIp={presetFirewallIp}
          />
        )}

        {/* Tab 3: Incidents Management */}
        {activeTab === 'incidents' && (
          <IncidentManagement
            incidents={incidents}
            onUpdateStatus={handleUpdateIncidentStatus}
            onBlockIp={(ip) => handleQuickBlockFromAlert(ip)}
          />
        )}

        {/* Tab 4: Threat Intelligence & Process Correlation */}
        {activeTab === 'threat_intel' && (
          <ThreatIntelPanel
            threats={aegisStore.getKnownThreats()}
            onBlockIp={handleQuickBlockFromAlert}
          />
        )}

        {/* Tab 5: Immutable Cryptographic Audit Ledger */}
        {activeTab === 'audit' && (
          <AuditLogViewer records={aegisStore.getAuditRecords()} />
        )}

        {/* Tab 6: Automated Test Suite Runner (25 Vectors) */}
        {activeTab === 'tests' && (
          <TestRunnerPanel />
        )}

        {/* Tab 7: Local Operator CLI & Privileged Service */}
        {activeTab === 'cli' && (
          <CliTerminal onSimulate={handleSimulate} />
        )}

        {/* Tab 8: REST API Explorer */}
        {activeTab === 'api' && (
          <ApiExplorer />
        )}
      </main>

      {/* Transparent Risk Score Breakdown Modal */}
      <RiskBreakdownModal
        isOpen={riskModalOpen}
        onClose={() => setRiskModalOpen(false)}
        risk={risk}
      />

      {/* Safe Simulation Boundaries & Safety Modal */}
      <SafetyBanner
        isOpen={safetyModalOpen}
        onClose={() => setSafetyModalOpen(false)}
      />

      {/* Tactical Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-3 text-xs font-mono-code text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>AEGIS CYBER DEFENSE // WINDOWS FILTERING PLATFORM &amp; LINUX NFTABLES</span>
          </div>
          <div>
            <span>ARCH: x86_64 // SUBLAYER: AEGIS_WFP_SUBLAYER // RESTRICTED IPC ENABLED</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
