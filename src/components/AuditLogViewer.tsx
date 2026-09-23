import React, { useState } from 'react';
import { 
  FileText, 
  Search, 
  ShieldCheck, 
  AlertTriangle, 
  Download, 
  Check, 
  Copy, 
  Lock, 
  Hash,
  Filter
} from 'lucide-react';
import { AuditRecord, UserRole } from '../types/aegis';
import { auditLogger } from '../services/security/AuditLogger';

interface AuditLogViewerProps {
  records: AuditRecord[];
}

export const AuditLogViewer: React.FC<AuditLogViewerProps> = ({ records }) => {
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [filterRole, setFilterRole] = useState<string>('ALL');
  const [verifiedStatus, setVerifiedStatus] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleVerifyLedger = () => {
    const res = auditLogger.verifyIntegrity();
    if (res.isValid) {
      setVerifiedStatus(`✓ AUDIT INTEGRITY VERIFIED: All ${res.verifiedCount} records verified via SHA-256 cryptographic chain continuity.`);
    } else {
      setVerifiedStatus(`⚠️ AUDIT TAMPER DETECTED: Hash broken at record index ${res.errorIndex}!`);
    }
    setTimeout(() => setVerifiedStatus(null), 6000);
  };

  const filtered = records.filter(r => {
    if (filterAction !== 'ALL' && r.action !== filterAction) return false;
    if (filterRole !== 'ALL' && r.role !== filterRole) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        r.id.toLowerCase().includes(q) ||
        r.user.toLowerCase().includes(q) ||
        r.target.toLowerCase().includes(q) ||
        r.reason.toLowerCase().includes(q) ||
        r.requestId.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(records, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-audit-ledger-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyHash = (hash: string, id: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <h2 className="font-tactical text-sm font-bold tracking-wider text-slate-200 uppercase">
              IMMUTABLE CRYPTOGRAPHIC AUDIT LEDGER
            </h2>
            <span className="text-[10px] font-mono-code px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
              TAMPER-EVIDENT HASH CHAIN
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono-code mt-0.5">
            Structured forensic log of every login, policy modification, privileged WFP operation, and mode change.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleVerifyLedger}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 rounded font-tactical text-xs font-bold tracking-wider transition-colors cursor-pointer"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            <span>VERIFY LEDGER CHAIN</span>
          </button>

          <button
            onClick={downloadJson}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded font-tactical text-xs font-bold tracking-wider transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT JSON</span>
          </button>
        </div>
      </div>

      {/* Verification Banner */}
      {verifiedStatus && (
        <div className="p-2.5 bg-cyan-950/60 border border-cyan-500/60 rounded text-xs font-mono-code text-cyan-200 flex items-center gap-2 animate-fadeIn">
          <Lock className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{verifiedStatus}</span>
        </div>
      )}

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono-code">
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by user, action, target, reason, or requestId..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          <div className="flex items-center gap-1 text-slate-400">
            <Filter className="w-3 h-3 text-slate-500" />
            <span>ACTION:</span>
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Actions</option>
              <option value="BLOCK_IP">BLOCK_IP</option>
              <option value="UNBLOCK_IP">UNBLOCK_IP</option>
              <option value="ADD_RULE">ADD_RULE</option>
              <option value="REMOVE_RULE">REMOVE_RULE</option>
              <option value="EMERGENCY_LOCKDOWN">EMERGENCY_LOCKDOWN</option>
              <option value="OPERATING_MODE_CHANGE">OPERATING_MODE_CHANGE</option>
              <option value="SERVICE_INITIALIZATION">SERVICE_INITIALIZATION</option>
            </select>
          </div>

          <div className="flex items-center gap-1 text-slate-400">
            <span>ROLE:</span>
            <select
              value={filterRole}
              onChange={(e) => setFilterRole(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Roles</option>
              <option value="ADMIN">ADMIN</option>
              <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
              <option value="OPERATOR">OPERATOR</option>
              <option value="VIEWER">VIEWER</option>
            </select>
          </div>
        </div>
      </div>

      {/* Audit Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono-code">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
              <th className="py-2 px-3">RECORD ID</th>
              <th className="py-2 px-3">TIMESTAMP</th>
              <th className="py-2 px-3">USER / ROLE</th>
              <th className="py-2 px-3">ACTION</th>
              <th className="py-2 px-3">TARGET</th>
              <th className="py-2 px-3">RESULT</th>
              <th className="py-2 px-3">REASON / AUDIT DETAIL</th>
              <th className="py-2 px-3">HASH CHAIN</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-900">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  No matching audit records found.
                </td>
              </tr>
            ) : (
              filtered.map((r) => (
                <tr key={r.id} className="hover:bg-slate-900/40">
                  <td className="py-2.5 px-3 font-semibold text-slate-300">{r.id}</td>
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {new Date(r.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className="font-semibold text-slate-200">{r.user}</span>
                    <span className="text-[10px] ml-1.5 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-indigo-300">
                      {r.role}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-bold text-cyan-400 whitespace-nowrap">
                    {r.action}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 max-w-[140px] truncate" title={r.target}>
                    {r.target}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${
                      r.result === 'SUCCESS' 
                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50' 
                        : r.result === 'REJECTED'
                        ? 'bg-amber-950/80 text-amber-300 border-amber-500/50'
                        : 'bg-red-950/80 text-red-300 border-red-500/50'
                    }`}>
                      {r.result}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate" title={r.reason}>
                    {r.reason}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      onClick={() => copyHash(r.hash, r.id)}
                      className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-cyan-400 cursor-pointer"
                      title={`Cryptographic Hash: ${r.hash}`}
                    >
                      <Hash className="w-3 h-3" />
                      <span>{r.hash.slice(0, 10)}...</span>
                      {copiedId === r.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
