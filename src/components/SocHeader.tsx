import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Radio, 
  Volume2, 
  VolumeX, 
  Cpu, 
  Terminal, 
  Code2, 
  Flame, 
  AlertTriangle,
  RotateCcw,
  Monitor,
  Activity,
  UserCheck,
  FileText,
  Lock,
  Unlock,
  CheckCircle2,
  Server
} from 'lucide-react';
import { 
  OperatingMode, 
  SystemStatus, 
  RiskReport, 
  PlatformType, 
  UserRole 
} from '../types/aegis';
import { authService } from '../services/security/AuthService';
import { osDetector } from '../services/security/OsEnvironmentDetector';

interface SocHeaderProps {
  status: SystemStatus;
  risk: RiskReport;
  onSelectMode: (mode: OperatingMode) => void;
  onSelectPlatform: (platform: PlatformType) => void;
  onToggleSound: () => void;
  onOpenSafetyModal: () => void;
  onOpenRiskModal?: () => void;
  onResetData: () => void;
  onEmergencyLockdown: () => void;
  onLiftLockdown: () => void;
  activeTab: string;
  onSelectTab: (tab: string) => void;
}

export const SocHeader: React.FC<SocHeaderProps> = ({
  status,
  risk,
  onSelectMode,
  onSelectPlatform,
  onToggleSound,
  onOpenSafetyModal,
  onOpenRiskModal,
  onResetData,
  onEmergencyLockdown,
  onLiftLockdown,
  activeTab,
  onSelectTab,
}) => {
  const currentSession = authService.getCurrentSession();
  const currentRole = authService.getCurrentUserRole();

  const modes: { id: OperatingMode; label: string; desc: string; color: string }[] = [
    { id: 'MONITOR', label: 'MONITOR', desc: 'Detect & Log Only', color: 'border-cyan-500/50 text-cyan-400' },
    { id: 'SIMULATION', label: 'SIMULATION', desc: 'Safe Dry-Run Testing', color: 'border-amber-500/50 text-amber-400' },
    { id: 'ENFORCEMENT', label: 'ENFORCEMENT', desc: 'Active WFP Containment', color: 'border-red-500/50 text-red-400' },
  ];

  const platforms: { id: PlatformType; label: string; backend: string }[] = [
    { id: 'WINDOWS', label: 'WINDOWS 11 / SERVER', backend: 'WFP / NetSecurity' },
    { id: 'LINUX', label: 'LINUX (UBUNTU / DEB)', backend: 'nftables' },
    { id: 'SIMULATION', label: 'SIMULATION ENGINE', backend: 'Safe Virtual Sandbox' },
  ];

  const tabs = [
    { id: 'dashboard', label: 'SOC DASHBOARD', icon: ShieldAlert },
    { id: 'firewall', label: 'WINDOWS WFP / FIREWALL', icon: ShieldCheck, badge: status.activeBlocksCount },
    { id: 'incidents', label: 'INCIDENTS', icon: AlertTriangle, badge: status.openIncidentsCount },
    { id: 'threat_intel', label: 'THREAT INTEL & PROCESSES', icon: Activity },
    { id: 'audit', label: 'AUDIT LEDGER', icon: FileText },
    { id: 'tests', label: 'AUTOMATED TEST SUITE', icon: CheckCircle2 },
    { id: 'cli', label: 'OPERATOR CLI', icon: Terminal },
    { id: 'api', label: 'REST API', icon: Code2 },
  ];

  const handleRoleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    authService.switchUserFast(e.target.value);
  };

  return (
    <header className="border-b border-cyan-900/40 bg-slate-950/95 backdrop-blur-md sticky top-0 z-40">
      {/* Top Threat & Status Bar */}
      <div className="max-w-7xl mx-auto px-4 py-2 flex flex-wrap items-center justify-between gap-3 text-xs border-b border-slate-900">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="relative flex items-center justify-center">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping absolute opacity-75" />
              <span className="w-2 h-2 rounded-full bg-emerald-500 relative" />
            </div>
            <span className="font-mono-code font-bold tracking-wider text-slate-200">AEGIS-CORE</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400 font-mono-code">
              PRIMARY: <span className="text-cyan-400 font-semibold">{status.platform} ({status.backend})</span>
            </span>
          </div>

          {/* Platform Switcher */}
          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5">
            <Server className="w-3 h-3 text-cyan-400" />
            <select
              value={status.platform}
              onChange={(e) => onSelectPlatform(e.target.value as PlatformType)}
              className="bg-transparent text-slate-300 font-mono-code text-[11px] focus:outline-none cursor-pointer"
              title="Target Deployment Platform"
            >
              <option value="WINDOWS" className="bg-slate-950 text-slate-200">Windows (WFP Native)</option>
              <option value="LINUX" className="bg-slate-950 text-slate-200">Linux (nftables)</option>
              <option value="SIMULATION" className="bg-slate-950 text-slate-200">Simulation Sandbox</option>
            </select>
          </div>

          <button
            onClick={onOpenSafetyModal}
            className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors cursor-pointer"
            title="Safe Simulation Boundaries & Safety Protocols"
          >
            <AlertTriangle className="w-3 h-3" />
            <span className="font-tactical font-semibold tracking-wider text-[11px]">
              {status.isSafeMode ? 'SAFE SIMULATION MODE' : 'LIVE ENFORCEMENT'}
            </span>
          </button>
        </div>

        {/* Dynamic Telemetry Metrics & RBAC Selector */}
        <div className="flex flex-wrap items-center gap-4 font-mono-code">
          <div className="flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-slate-400">INGRESS:</span>
            <span className="text-cyan-300 font-bold">{status.trafficPps.toLocaleString()} pps</span>
          </div>

          <div className="hidden sm:flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">BANDWIDTH:</span>
            <span className="text-emerald-300 font-bold">{status.bandwidthMbps} Mbps</span>
          </div>

          {/* Threat DEFCON dial click opens breakdown */}
          <button
            onClick={onOpenRiskModal}
            className="flex items-center gap-1.5 hover:opacity-80 cursor-pointer"
            title="Inspect itemized factor risk score breakdown"
          >
            <Flame className="w-3.5 h-3.5" style={{ color: risk.threatColor }} />
            <span className="text-slate-400">THREAT:</span>
            <span className="font-bold underline decoration-dotted" style={{ color: risk.threatColor }}>
              {risk.threatLevel.split(' ')[0]} ({risk.currentScore}/100)
            </span>
          </button>

          {/* RBAC Role Switcher */}
          <div className="flex items-center gap-1.5 pl-2 border-l border-slate-800">
            <UserCheck className="w-3.5 h-3.5 text-indigo-400" />
            <select
              value={currentSession?.username || 'admin'}
              onChange={handleRoleChange}
              className="bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-slate-200 text-[11px] font-mono-code cursor-pointer"
              title="Switch Active RBAC Identity (Admin / Analyst / Operator / Viewer)"
            >
              <option value="admin">User: admin (ADMIN)</option>
              <option value="analyst">User: analyst (ANALYST)</option>
              <option value="operator">User: operator (OPERATOR)</option>
              <option value="viewer">User: viewer (VIEWER - Read Only)</option>
            </select>
          </div>

          <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
            <button
              onClick={onToggleSound}
              className="p-1 rounded text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              title={status.soundEnabled ? 'Mute Tactical Blips' : 'Enable Tactical Blips'}
            >
              {status.soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-cyan-400" /> : <VolumeX className="w-3.5 h-3.5" />}
            </button>
            <button
              onClick={onResetData}
              className="p-1 rounded text-slate-400 hover:text-amber-400 transition-colors cursor-pointer"
              title="Reset Aegis SOC State"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Bar: Logo, Operating Mode Selector, Emergency Lockdown, and Tabs */}
      <div className="max-w-7xl mx-auto px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Branding & Subtitle */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded border border-cyan-500/60 bg-gradient-to-br from-cyan-950/80 to-slate-950 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.2)]">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-tactical text-lg font-black tracking-wider text-slate-100 uppercase">
                AEGIS DEFENSE PLATFORM
              </h1>
              <span className="text-[10px] font-mono-code px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700/60">
                WFP + LINUX IDS/IPS
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono-code">
              Cross-Platform Firewall &amp; Correlation Engine // Primary: Windows WFP
            </p>
          </div>
        </div>

        {/* Operating Modes & Emergency Lockdown */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Emergency Lockdown Button */}
          {status.emergencyLockdownActive ? (
            <button
              onClick={onLiftLockdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-emerald-500 bg-emerald-950/80 text-emerald-300 font-tactical text-xs font-bold tracking-wider hover:bg-emerald-900 transition-colors animate-pulse cursor-pointer"
              title="Emergency lockdown is currently ACTIVE. Click to lift."
            >
              <Unlock className="w-3.5 h-3.5" />
              <span>LIFT LOCKDOWN</span>
            </button>
          ) : (
            <button
              onClick={() => {
                if (currentRole !== 'ADMIN') {
                  alert('RBAC Refusal: Emergency Lockdown requires ADMIN authorization.');
                  return;
                }
                if (confirm('EMERGENCY LOCKDOWN WARNING: This drops all inbound traffic except Trusted Management IPs. Proceed?')) {
                  onEmergencyLockdown();
                }
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-red-500/80 bg-red-950/50 hover:bg-red-950 text-red-300 font-tactical text-xs font-bold tracking-wider transition-colors cursor-pointer"
              title="Isolates perimeter on Windows WFP immediately"
            >
              <Lock className="w-3.5 h-3.5 text-red-400" />
              <span>EMERGENCY LOCKDOWN</span>
            </button>
          )}

          {/* Operating Mode Selector */}
          <div className="flex items-center p-1 bg-slate-900/90 border border-slate-800 rounded-md">
            {modes.map((m) => {
              const isActive = status.mode === m.id;
              const isLocked = m.id === 'ENFORCEMENT' && !osDetector.hasPassedTests();
              return (
                <button
                  key={m.id}
                  onClick={() => onSelectMode(m.id)}
                  title={isLocked ? 'Locked: Backend Self-Test (RFC 1918) must be run and verified first' : m.desc}
                  className={`px-3 py-1 text-xs font-tactical font-bold tracking-wider rounded transition-all cursor-pointer ${
                    isActive
                      ? `bg-slate-950 border ${m.color} shadow-[0_0_10px_rgba(0,0,0,0.5)]`
                      : isLocked
                        ? 'text-slate-500 opacity-60 hover:opacity-100 hover:text-slate-300'
                        : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="flex flex-col items-center">
                    <div className="flex items-center gap-1">
                      {isLocked && <Lock className="w-2.5 h-2.5 text-amber-400" />}
                      <span>{m.label}</span>
                    </div>
                    <span className="text-[9px] font-mono-code opacity-75 font-normal">
                      {isLocked ? 'Self-Test Required' : m.desc}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Navigation Tabs Bar */}
      <div className="max-w-7xl mx-auto px-4 flex items-center gap-1 overflow-x-auto scrollbar-none border-t border-slate-900/80">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              className={`flex items-center gap-2 py-2 px-3 border-b-2 font-tactical text-xs tracking-wider transition-all whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {typeof tab.badge === 'number' && tab.badge > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono-code bg-red-950 text-red-400 border border-red-800 font-bold">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </header>
  );
};
