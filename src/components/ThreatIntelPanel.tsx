import React, { useState } from 'react';
import { 
  Activity, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  Globe, 
  Terminal, 
  AlertTriangle, 
  Server,
  Layers,
  Cpu
} from 'lucide-react';
import { ThreatIntelEntry, ProcessCorrelationInfo } from '../types/aegis';
import { threatIntelService } from '../services/security/ThreatIntelService';

interface ThreatIntelPanelProps {
  threats: ThreatIntelEntry[];
  onBlockIp?: (ip: string, reason: string) => void;
}

export const ThreatIntelPanel: React.FC<ThreatIntelPanelProps> = ({ threats, onBlockIp }) => {
  const [lookupIpInput, setLookupIpInput] = useState('185.220.101.5');
  const [lookupResult, setLookupResult] = useState<ReturnType<typeof threatIntelService.lookupIp> | null>(() => {
    return threatIntelService.lookupIp('185.220.101.5');
  });

  // Windows Processes Correlation State
  const monitoredProcesses: ProcessCorrelationInfo[] = [
    {
      pid: 3824,
      name: 'cmd.exe',
      path: 'C:\\Windows\\System32\\cmd.exe',
      user: 'NT AUTHORITY\\SYSTEM',
      parentProcess: 'w3wp.exe (PID 2104)',
      networkConnections: 1,
      riskLevel: 'HIGH',
    },
    {
      pid: 4912,
      name: 'powershell.exe',
      path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      user: 'CORP\\service_sql',
      parentProcess: 'sqlservr.exe (PID 1420)',
      networkConnections: 2,
      riskLevel: 'SUSPICIOUS',
    },
    {
      pid: 840,
      name: 'svchost.exe (TermService)',
      path: 'C:\\Windows\\System32\\svchost.exe',
      user: 'NT AUTHORITY\\NetworkService',
      parentProcess: 'services.exe (PID 620)',
      networkConnections: 14,
      riskLevel: 'LOW',
    },
    {
      pid: 712,
      name: 'lsass.exe',
      path: 'C:\\Windows\\System32\\lsass.exe',
      user: 'NT AUTHORITY\\SYSTEM',
      parentProcess: 'wininit.exe (PID 540)',
      networkConnections: 0,
      riskLevel: 'LOW',
    },
  ];

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupIpInput.trim()) return;
    const res = threatIntelService.lookupIp(lookupIpInput.trim());
    setLookupResult(res);
  };

  return (
    <div className="space-y-6">
      {/* Top Split: IP Reputation Lookup & Live Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* IP Reputation Lookup Box */}
        <div className="lg:col-span-5 bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
            <Search className="w-4 h-4 text-cyan-400" />
            <h3 className="font-tactical text-xs font-bold tracking-wider text-slate-200 uppercase">
              IP REPUTATION &amp; INTELLIGENCE QUERY
            </h3>
          </div>

          <form onSubmit={handleLookup} className="space-y-2">
            <div className="flex gap-2">
              <input
                type="text"
                value={lookupIpInput}
                onChange={(e) => setLookupIpInput(e.target.value)}
                placeholder="Enter IP (e.g. 185.220.101.5 or 203.0.113.19)..."
                className="flex-1 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs font-mono-code text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-tactical font-bold text-xs tracking-wider rounded transition-colors cursor-pointer"
              >
                CHECK IP
              </button>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono-code text-slate-400">
              <span>Samples:</span>
              <button type="button" onClick={() => { setLookupIpInput('185.220.101.5'); setLookupResult(threatIntelService.lookupIp('185.220.101.5')); }} className="text-cyan-400 hover:underline">185.220.101.5 (Tor)</button>
              <button type="button" onClick={() => { setLookupIpInput('203.0.113.19'); setLookupResult(threatIntelService.lookupIp('203.0.113.19')); }} className="text-cyan-400 hover:underline">203.0.113.19 (C2)</button>
              <button type="button" onClick={() => { setLookupIpInput('8.8.8.8'); setLookupResult(threatIntelService.lookupIp('8.8.8.8')); }} className="text-cyan-400 hover:underline">8.8.8.8 (Clean)</button>
            </div>
          </form>

          {/* Lookup Result Card */}
          {lookupResult && (
            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded space-y-3 font-mono-code text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">REPUTATION SCORE:</span>
                <span className={`px-2 py-0.5 rounded font-bold ${
                  lookupResult.reputationScore < 30 
                    ? 'bg-red-950 text-red-300 border border-red-500/50' 
                    : lookupResult.reputationScore < 70
                    ? 'bg-amber-950 text-amber-300 border border-amber-500/50'
                    : 'bg-emerald-950 text-emerald-300 border border-emerald-500/50'
                }`}>
                  {lookupResult.reputationScore} / 100 {lookupResult.reputationScore < 30 ? '(SEVERE THREAT)' : lookupResult.reputationScore < 70 ? '(SUSPICIOUS)' : '(CLEAN)'}
                </span>
              </div>

              <div className="space-y-1 text-slate-300 text-[11px]">
                <p><span className="text-slate-500">Summary:</span> {lookupResult.description}</p>
                {lookupResult.entry && (
                  <>
                    <p><span className="text-slate-500">Category:</span> <span className="font-bold text-red-400">{lookupResult.entry.threatType}</span></p>
                    <p><span className="text-slate-500">Confidence:</span> {lookupResult.entry.confidence}%</p>
                    <p><span className="text-slate-500">Country / ASN:</span> {lookupResult.entry.country} · {lookupResult.entry.asn}</p>
                    <p><span className="text-slate-500">Global Incidents:</span> {lookupResult.entry.reportedIncidents.toLocaleString()}</p>
                  </>
                )}
              </div>

              {lookupResult.isMalicious && onBlockIp && (
                <button
                  onClick={() => onBlockIp(lookupIpInput, `Threat intelligence match: ${lookupResult.entry?.threatType || 'Hostile'}`)}
                  className="w-full py-1.5 bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-500/60 rounded font-tactical font-bold text-xs tracking-wider transition-colors cursor-pointer"
                >
                  ADD WFP QUARANTINE RULE FOR {lookupIpInput}
                </button>
              )}
            </div>
          )}
        </div>

        {/* Threat Intelligence Feed Indicators */}
        <div className="lg:col-span-7 bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <h3 className="font-tactical text-xs font-bold tracking-wider text-slate-200 uppercase">
                ACTIVE THREAT INTELLIGENCE FEEDS &amp; IOC TRACKERS
              </h3>
            </div>
            <span className="text-[11px] font-mono-code text-slate-400">
              {threats.length} ACTIVE INDICATORS
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono-code">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase">
                  <th className="py-2 px-3">INDICATOR (IP)</th>
                  <th className="py-2 px-3">CATEGORY</th>
                  <th className="py-2 px-3">CONFIDENCE</th>
                  <th className="py-2 px-3">GEO / ASN</th>
                  <th className="py-2 px-3 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900">
                {threats.map((t) => (
                  <tr key={t.ipOrCidr} className="hover:bg-slate-900/40">
                    <td className="py-2.5 px-3 font-bold text-cyan-400">{t.ipOrCidr}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.2 rounded border border-red-500/40 bg-red-950/60 text-red-300 text-[10px] font-bold">
                        {t.threatType}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 font-semibold">{t.confidence}%</td>
                    <td className="py-2.5 px-3 text-slate-400 max-w-[200px] truncate" title={t.asn}>
                      {t.country} · {t.asn}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => onBlockIp?.(t.ipOrCidr, `Block IOC ${t.threatType}`)}
                        className="px-2 py-0.5 rounded bg-slate-900 hover:bg-red-950 text-slate-300 hover:text-red-300 border border-slate-700 hover:border-red-600 transition-colors text-[10px] cursor-pointer"
                      >
                        Block WFP
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Windows Process Network Correlation Monitor */}
      <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="font-tactical text-xs font-bold tracking-wider text-slate-200 uppercase">
              WINDOWS PROCESS &amp; NETWORK SOCKET CORRELATION (EDR / WFP INTEGRATION)
            </h3>
          </div>
          <span className="text-[11px] font-mono-code text-cyan-300">
            WFP APPLICATION FILTERING ACTIVE
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono-code">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase">
                <th className="py-2 px-3">PID</th>
                <th className="py-2 px-3">PROCESS NAME</th>
                <th className="py-2 px-3">EXECUTABLE BINARY PATH</th>
                <th className="py-2 px-3">ACCOUNT IDENTITY</th>
                <th className="py-2 px-3">PARENT PROCESS</th>
                <th className="py-2 px-3">SOCKETS</th>
                <th className="py-2 px-3 text-right">RISK LEVEL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {monitoredProcesses.map((p) => (
                <tr key={p.pid} className="hover:bg-slate-900/40">
                  <td className="py-2.5 px-3 font-semibold text-slate-400">{p.pid}</td>
                  <td className="py-2.5 px-3 font-bold text-slate-200">{p.name}</td>
                  <td className="py-2.5 px-3 text-slate-300 font-mono-code text-[11px] max-w-xs truncate" title={p.path}>
                    {p.path}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">{p.user}</td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">{p.parentProcess}</td>
                  <td className="py-2.5 px-3 font-semibold text-cyan-400">{p.networkConnections}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${
                      p.riskLevel === 'HIGH'
                        ? 'bg-red-950/80 text-red-300 border-red-500/50 animate-pulse'
                        : p.riskLevel === 'SUSPICIOUS'
                        ? 'bg-amber-950/80 text-amber-300 border-amber-500/50'
                        : 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50'
                    }`}>
                      {p.riskLevel}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
