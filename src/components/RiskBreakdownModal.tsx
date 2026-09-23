import React from 'react';
import { 
  X, 
  Flame, 
  ShieldAlert, 
  CheckCircle2, 
  HelpCircle, 
  Layers, 
  Activity, 
  TrendingUp,
  Cpu
} from 'lucide-react';
import { RiskReport } from '../types/aegis';

interface RiskBreakdownModalProps {
  isOpen: boolean;
  onClose: () => void;
  risk: RiskReport;
}

export const RiskBreakdownModal: React.FC<RiskBreakdownModalProps> = ({
  isOpen,
  onClose,
  risk,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-950 border border-slate-800 rounded-lg max-w-2xl w-full p-5 shadow-2xl space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5" style={{ color: risk.threatColor }} />
            <h2 className="font-tactical text-base font-bold tracking-wider text-slate-100 uppercase">
              TRANSPARENT 0-100 RISK SCORE BREAKDOWN
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-200 rounded cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Score & DEFCON Banner */}
        <div className="p-3 bg-slate-900/80 border border-slate-800 rounded flex flex-wrap items-center justify-between gap-3 font-mono-code">
          <div>
            <span className="text-slate-400 text-xs block">AGGREGATE SYSTEM RISK:</span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-tactical" style={{ color: risk.threatColor }}>
                {risk.currentScore} / 100
              </span>
              <span className="text-xs px-2 py-0.5 rounded font-bold uppercase" style={{ backgroundColor: `${risk.threatColor}20`, color: risk.threatColor }}>
                {risk.threatLevel}
              </span>
            </div>
          </div>

          <div className="text-right text-xs">
            <span className="text-slate-400 block">TRENDING:</span>
            <span className="text-cyan-400 font-bold flex items-center gap-1 justify-end">
              <TrendingUp className="w-3.5 h-3.5" />
              {risk.recentTrend === 'UP' ? 'ELEVATING' : 'NOMINAL'}
            </span>
          </div>
        </div>

        {/* Vector Breakdown Pills */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 text-center font-mono-code text-[11px]">
          <div className="p-2 bg-slate-900 border border-slate-800 rounded">
            <span className="text-slate-500 block text-[9px]">PORTSCAN</span>
            <span className="text-slate-200 font-bold">{risk.vectorBreakdown.portScan}</span>
          </div>
          <div className="p-2 bg-slate-900 border border-slate-800 rounded">
            <span className="text-slate-500 block text-[9px]">RDP / SSH</span>
            <span className="text-slate-200 font-bold">{risk.vectorBreakdown.sshRdpBruteForce}</span>
          </div>
          <div className="p-2 bg-slate-900 border border-slate-800 rounded">
            <span className="text-slate-500 block text-[9px]">HTTP CRSS</span>
            <span className="text-slate-200 font-bold">{risk.vectorBreakdown.httpAnomaly}</span>
          </div>
          <div className="p-2 bg-slate-900 border border-slate-800 rounded">
            <span className="text-slate-500 block text-[9px]">FLOODS</span>
            <span className="text-slate-200 font-bold">{risk.vectorBreakdown.networkFlood}</span>
          </div>
          <div className="p-2 bg-slate-900 border border-slate-800 rounded">
            <span className="text-slate-500 block text-[9px]">DNS TUNNEL</span>
            <span className="text-slate-200 font-bold">{risk.vectorBreakdown.dnsAnomaly}</span>
          </div>
          <div className="p-2 bg-slate-900 border border-slate-800 rounded">
            <span className="text-slate-500 block text-[9px]">BEACONS</span>
            <span className="text-slate-200 font-bold">{risk.vectorBreakdown.outboundBeacon}</span>
          </div>
        </div>

        {/* Itemized Contributing Factors Table */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono-code text-slate-400">
            <span>ITEMIZED FACTOR CONTRIBUTION LEDGER (NO BLACK BOX)</span>
            <span>{risk.factors.length} FACTORS EVALUATED</span>
          </div>

          <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1 font-mono-code text-xs">
            {risk.factors.map((f, idx) => (
              <div 
                key={idx}
                className="p-2.5 bg-slate-900/50 border border-slate-800/80 rounded flex items-center justify-between gap-3"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-200">{f.factor}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 uppercase">
                      {f.category}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{f.description}</p>
                </div>

                <div className="text-right shrink-0">
                  <span className="text-xs font-bold text-amber-400">+{f.score} pts</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-800 flex justify-between items-center text-xs font-mono-code">
          <span className="text-slate-500">
            Aegis Transparent Risk Engine // Deterministic &amp; Auditable
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded font-tactical text-xs tracking-wider cursor-pointer"
          >
            DISMISS
          </button>
        </div>
      </div>
    </div>
  );
};
