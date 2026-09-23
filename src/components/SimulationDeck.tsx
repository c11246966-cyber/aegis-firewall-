import React, { useState } from 'react';
import { 
  Play, 
  Radar, 
  KeyRound, 
  Globe, 
  Waves, 
  ShieldCheck, 
  AlertOctagon, 
  CheckCircle2, 
  Loader2,
  Terminal,
  ArrowRight,
  Monitor,
  Radio,
  Cpu,
  Layers
} from 'lucide-react';
import { SimulationVector, OperatingMode } from '../types/aegis';

interface SimulationDeckProps {
  currentMode: OperatingMode;
  onSimulate: (vector: SimulationVector) => Promise<unknown>;
}

export const SimulationDeck: React.FC<SimulationDeckProps> = ({ currentMode, onSimulate }) => {
  const [runningVector, setRunningVector] = useState<SimulationVector | null>(null);
  const [lastResult, setLastResult] = useState<{
    vector: SimulationVector;
    message: string;
    details: string;
    actionTaken: string;
  } | null>(null);

  const vectors: {
    id: SimulationVector;
    title: string;
    description: string;
    target: string;
    signature: string;
    icon: React.ComponentType<{ className?: string }>;
    color: string;
    bgGlow: string;
    defaultAction: string;
  }[] = [
    {
      id: 'RDP_BRUTE_FORCE',
      title: 'WINDOWS RDP BRUTE FORCE',
      description: 'Simulates high-velocity NTLM logon failures targeting Windows Remote Desktop (port 3389).',
      target: 'Windows RDP (Port 3389/TCP)',
      signature: 'ET POLICY Windows RDP (3389) High-Rate Credential Guessing Burst',
      icon: Monitor,
      color: 'text-rose-400 border-rose-500/40',
      bgGlow: 'hover:border-rose-400/80 hover:shadow-[0_0_20px_rgba(244,63,94,0.15)]',
      defaultAction: currentMode === 'ENFORCEMENT' ? 'Auto-Block WFP Rule (1800s TTL)' : 'Alert & Log Event',
    },
    {
      id: 'OUTBOUND_BEACON',
      title: 'REVERSE SHELL C2 BEACON',
      description: 'Simulates cmd.exe or powershell.exe establishing unauthorized outbound socket to external C2.',
      target: 'Outbound TCP socket to 203.0.113.19:4444',
      signature: 'ET TROJAN Suspicious Outbound C2 Reverse Shell Beaconing',
      icon: Cpu,
      color: 'text-red-400 border-red-500/40',
      bgGlow: 'hover:border-red-400/80 hover:shadow-[0_0_20px_rgba(239,68,68,0.15)]',
      defaultAction: currentMode === 'ENFORCEMENT' ? 'WFP Program Block (3600s TTL)' : 'Critical Incident Created',
    },
    {
      id: 'PORT_SCAN',
      title: 'PORT SCAN (SYN SWEEP)',
      description: 'Simulates aggressive horizontal SYN reconnaissance sweeping ports 21, 22, 80, 443, 3389, 8080.',
      target: 'Ports: 21, 22, 80, 443, 3389, 8080',
      signature: 'ET SCAN Potential Aggressive Port Sweep',
      icon: Radar,
      color: 'text-amber-400 border-amber-500/40',
      bgGlow: 'hover:border-amber-400/80 hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]',
      defaultAction: currentMode === 'ENFORCEMENT' ? 'Drop Attacker IP (900s TTL)' : 'Alert & Port Correlation',
    },
    {
      id: 'DNS_ANOMALY',
      title: 'DNS TUNNELING EXFILTRATION',
      description: 'Simulates high-entropy Base64 subdomain queries for covert data exfiltration.',
      target: 'Port 53/UDP (TXT high-entropy query)',
      signature: 'ET MALWARE High-Entropy Base64 Subdomain DNS Tunneling',
      icon: Radio,
      color: 'text-cyan-400 border-cyan-500/40',
      bgGlow: 'hover:border-cyan-400/80 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]',
      defaultAction: currentMode === 'ENFORCEMENT' ? 'Quarantine IP (1800s TTL)' : 'DNS Query Alarm',
    },
    {
      id: 'HTTP_ANOMALY',
      title: 'HTTP SQL INJECTION (OWASP)',
      description: 'Simulates web application URI injection targeting telemetry database.',
      target: 'Port 443/HTTPS (URI parameter)',
      signature: 'OWASP CRS 942100: SQL Injection Attempt detected',
      icon: Globe,
      color: 'text-orange-400 border-orange-500/40',
      bgGlow: 'hover:border-orange-400/80 hover:shadow-[0_0_20px_rgba(249,115,22,0.15)]',
      defaultAction: currentMode === 'ENFORCEMENT' ? 'Immediate WFP Block' : 'Critical SOC Alert',
    },
    {
      id: 'SYN_FLOOD',
      title: 'SYN VOLUMETRIC FLOOD',
      description: 'Simulates high-velocity SYN flood exceeding sliding window thresholds.',
      target: 'Ingress Interface (+12,000 pps burst)',
      signature: 'ET DOS TCP SYN Volumetric Flooding Anomaly',
      icon: Waves,
      color: 'text-purple-400 border-purple-500/40',
      bgGlow: 'hover:border-purple-400/80 hover:shadow-[0_0_20px_rgba(168,85,247,0.15)]',
      defaultAction: currentMode === 'ENFORCEMENT' ? 'Subnet Quarantine (600s TTL)' : 'Volumetric Alarm',
    },
  ];

  const handleRun = async (vector: SimulationVector) => {
    setRunningVector(vector);
    try {
      await onSimulate(vector);
      let actionMsg = '';
      if (currentMode === 'ENFORCEMENT') {
        actionMsg = 'ENFORCEMENT ACTION: Offending IP quarantined via native WFP rule (AEGIS-WFP-*)!';
      } else if (currentMode === 'MONITOR') {
        actionMsg = 'MONITOR ACTION: Passive observation mode. Event logged, no firewall mutation performed.';
      } else {
        actionMsg = 'SIMULATION ACTION: Safe test telemetry generated, alert logged, and incident triage record created.';
      }

      setLastResult({
        vector,
        message: `Simulation vector "${vector}" executed successfully.`,
        details: `Correlated telemetry flow processed by DetectionEngine -> PolicyEngine -> Firewall FAL.`,
        actionTaken: actionMsg,
      });
    } finally {
      setRunningVector(null);
    }
  };

  return (
    <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-4">
      {/* Deck Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-cyan-400" />
            <h2 className="font-tactical text-sm font-bold tracking-wider text-slate-200 uppercase">
              SAFE ATTACK SIMULATION &amp; TESTING VECTORS
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono-code mt-0.5">
            Trigger cross-platform test scenarios to evaluate detection rules, risk scoring, and auto-quarantine.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono-code text-xs">
          <span className="text-slate-400">CURRENT MODE:</span>
          <span className={`px-2 py-0.5 rounded font-bold border ${
            currentMode === 'ENFORCEMENT' 
              ? 'bg-red-950 text-red-400 border-red-800' 
              : currentMode === 'MONITOR'
              ? 'bg-cyan-950 text-cyan-400 border-cyan-800'
              : 'bg-amber-950 text-amber-400 border-amber-800'
          }`}>
            {currentMode}
          </span>
        </div>
      </div>

      {/* Vector Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {vectors.map((v) => {
          const Icon = v.icon;
          const isRunning = runningVector === v.id;

          return (
            <div
              key={v.id}
              className={`p-3.5 rounded-lg border bg-slate-900/50 transition-all flex flex-col justify-between gap-3 ${v.color} ${v.bgGlow}`}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4" />
                    <span className="font-tactical font-bold text-xs tracking-wider uppercase text-slate-100">
                      {v.title}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono-code px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                    TEST VECTOR
                  </span>
                </div>

                <p className="text-xs text-slate-300 font-mono-code leading-relaxed">
                  {v.description}
                </p>

                <div className="space-y-1 text-[11px] font-mono-code text-slate-400 pt-1 border-t border-slate-800/80">
                  <div className="truncate">
                    <span className="text-slate-500">Target:</span> {v.target}
                  </div>
                  <div className="text-[10px] text-cyan-400/80 truncate" title={v.signature}>
                    {v.signature}
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-2">
                <span className="text-[10px] font-mono-code text-slate-400 truncate">
                  {v.defaultAction}
                </span>

                <button
                  onClick={() => handleRun(v.id)}
                  disabled={isRunning || runningVector !== null}
                  className="flex items-center gap-1.5 px-3 py-1 bg-slate-950 hover:bg-slate-800 text-slate-200 border border-slate-700 hover:border-cyan-500 rounded font-tactical text-xs font-bold tracking-wider transition-all disabled:opacity-50 cursor-pointer shrink-0"
                >
                  {isRunning ? (
                    <>
                      <Loader2 className="w-3 h-3 animate-spin text-cyan-400" />
                      <span>SIMULATING</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3 h-3 text-cyan-400 fill-cyan-400" />
                      <span>INJECT</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Simulation Result Notification */}
      {lastResult && (
        <div className="p-3 bg-slate-900 border border-cyan-800/60 rounded-md font-mono-code text-xs text-slate-200 space-y-1 animate-fadeIn">
          <div className="flex items-center gap-2 text-cyan-400 font-bold">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{lastResult.message}</span>
          </div>
          <p className="text-slate-400 text-[11px]">{lastResult.details}</p>
          <div className="p-1.5 bg-slate-950 rounded border border-slate-800 text-amber-300 font-semibold text-[11px]">
            {lastResult.actionTaken}
          </div>
        </div>
      )}
    </div>
  );
};
