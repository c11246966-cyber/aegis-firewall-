import React, { useState } from 'react';
import { 
  Server, 
  ShieldCheck, 
  Cpu, 
  Activity, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Layers, 
  Code,
  Terminal,
  Shield,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { 
  PlatformType, 
  FirewallBackendType, 
  FirewallCapabilities, 
  FirewallHealth, 
  OperatingMode 
} from '../types/aegis';

interface CrossPlatformBarProps {
  platform: PlatformType;
  backend: FirewallBackendType;
  capabilities: FirewallCapabilities;
  health: FirewallHealth;
  mode: OperatingMode;
  onVerifyState: () => Promise<{ isTampered: boolean; message: string }>;
}

export const CrossPlatformBar: React.FC<CrossPlatformBarProps> = ({
  platform,
  backend,
  capabilities,
  health,
  mode,
  onVerifyState,
}) => {
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<string | null>(null);
  const [showEndpointsModal, setShowEndpointsModal] = useState(false);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await onVerifyState();
      setVerificationResult(res.message);
      setTimeout(() => setVerificationResult(null), 5000);
    } finally {
      setVerifying(false);
    }
  };

  const getOsLabel = () => {
    switch (platform) {
      case 'WINDOWS':
        return 'Microsoft Windows 11 / Windows Server (x64_64)';
      case 'LINUX':
        return 'Linux Ubuntu 24.04 LTS (Kernel 6.8.0-netfilter)';
      case 'SIMULATION':
      default:
        return 'Aegis Cross-Platform Emulation Runtime';
    }
  };

  const getBackendLabel = () => {
    switch (backend) {
      case 'WINDOWS_WFP':
        return 'Windows Filtering Platform (WFP) & Advanced Firewall';
      case 'LINUX_NFTABLES':
        return 'Linux Kernel nftables (table inet aegis_filter)';
      case 'SIMULATION':
      default:
        return 'Virtual Simulation Sandbox (Safe Mode)';
    }
  };

  return (
    <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-3">
      {/* Top OS / Backend / Health Strip */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-2 border-b border-slate-800/80 text-xs font-mono-code">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">OS:</span>
            <span className="font-bold text-slate-200">{getOsLabel()}</span>
          </div>

          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            <span className="text-slate-400">BACKEND:</span>
            <span className="font-bold text-indigo-300">{getBackendLabel()}</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Health Badge */}
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/50 text-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>HEALTH: {health.status} ({health.driverState})</span>
          </div>

          {/* Tamper Verification Trigger */}
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="flex items-center gap-1 px-2.5 py-0.5 rounded bg-slate-900 hover:bg-slate-850 text-cyan-300 border border-slate-700 hover:border-cyan-600 transition-colors cursor-pointer disabled:opacity-50"
            title="Perform cryptographic rule integrity and drift check"
          >
            <RefreshCw className={`w-3 h-3 ${verifying ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{verifying ? 'VERIFYING...' : 'VERIFY STATE'}</span>
          </button>

          {/* Endpoints Toggle */}
          <button
            onClick={() => setShowEndpointsModal(!showEndpointsModal)}
            className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-850 text-slate-300 border border-slate-700 cursor-pointer"
          >
            <Code className="w-3 h-3 text-cyan-400" />
            <span>/system/* APIs</span>
            {showEndpointsModal ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
      </div>

      {/* Verification Notice */}
      {verificationResult && (
        <div className="p-2 bg-cyan-950/40 border border-cyan-500/60 rounded text-xs font-mono-code text-cyan-300 flex items-center gap-2 animate-fadeIn">
          <ShieldCheck className="w-4 h-4 shrink-0 text-cyan-400" />
          <span>{verificationResult}</span>
        </div>
      )}

      {/* Capabilities Badges */}
      <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono-code">
        <span className="text-slate-500 uppercase text-[10px] mr-1">CAPABILITIES:</span>
        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">IPv4</span>
        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">IPv6</span>
        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">Inbound Filter</span>
        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">Outbound Filter</span>
        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">Stateful Inspection</span>
        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">Port Range Filtering</span>
        
        {capabilities.applicationFiltering ? (
          <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-semibold" title="Supported on Windows WFP">
            Process / Binary Path Rules (WFP)
          </span>
        ) : (
          <span className="px-2 py-0.5 rounded bg-slate-900/60 text-slate-500 border border-slate-800 line-through" title="Not native to standard L3/L4 nftables">
            Process Rules
          </span>
        )}

        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">TTL Auto-Expiration</span>
        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/60 font-semibold">
          Trusted Management Protection
        </span>
        <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800/60 font-semibold">
          Emergency Lockdown
        </span>
      </div>

      {/* System Platform Endpoints Accordion */}
      {showEndpointsModal && (
        <div className="pt-3 border-t border-slate-800 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2 text-xs font-mono-code">
          <div className="p-2.5 bg-black rounded border border-slate-800 space-y-1">
            <span className="text-cyan-400 font-bold">GET /system/platform</span>
            <pre className="text-[10px] text-slate-300 whitespace-pre-wrap">
              {JSON.stringify({ platform, os: getOsLabel(), arch: 'x86_64' }, null, 2)}
            </pre>
          </div>

          <div className="p-2.5 bg-black rounded border border-slate-800 space-y-1">
            <span className="text-indigo-400 font-bold">GET /system/firewall/backend</span>
            <pre className="text-[10px] text-slate-300 whitespace-pre-wrap">
              {JSON.stringify({ backend, sublayer: 'AEGIS_WFP_SUBLAYER', prefix: 'AEGIS-WFP-' }, null, 2)}
            </pre>
          </div>

          <div className="p-2.5 bg-black rounded border border-slate-800 space-y-1">
            <span className="text-emerald-400 font-bold">GET /system/firewall/capabilities</span>
            <pre className="text-[10px] text-slate-300 whitespace-pre-wrap">
              {JSON.stringify({ ipv4: true, ipv6: true, appFiltering: capabilities.applicationFiltering, ttl: true }, null, 2)}
            </pre>
          </div>

          <div className="p-2.5 bg-black rounded border border-slate-800 space-y-1">
            <span className="text-amber-400 font-bold">GET /system/firewall/health</span>
            <pre className="text-[10px] text-slate-300 whitespace-pre-wrap">
              {JSON.stringify({ status: health.status, driverState: health.driverState, tamper: health.tamperDetected }, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
