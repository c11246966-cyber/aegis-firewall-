import React, { useState } from 'react';
import { 
  Play, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  ShieldCheck, 
  AlertTriangle, 
  Filter, 
  Search, 
  RefreshCw,
  Cpu,
  Layers,
  Terminal
} from 'lucide-react';
import { TestCaseResult } from '../types/aegis';
import { aegisStore } from '../services/aegisStore';

export const TestRunnerPanel: React.FC = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState<TestCaseResult[]>([]);
  const [progress, setProgress] = useState({ done: 0, total: 25 });
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [search, setSearch] = useState('');

  const runTests = async () => {
    setIsRunning(true);
    setResults([]);
    setProgress({ done: 0, total: 25 });

    try {
      const allResults = await aegisStore.runAllTests((done, total, cur) => {
        setProgress({ done, total });
        setResults(prev => [...prev, cur]);
      });
      setResults(allResults);
    } finally {
      setIsRunning(false);
    }
  };

  const filtered = results.filter(r => {
    if (filterCategory !== 'ALL' && r.category !== filterCategory) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.details.toLowerCase().includes(q);
    }
    return true;
  });

  const passCount = results.filter(r => r.status === 'PASS').length;
  const failCount = results.filter(r => r.status === 'FAIL').length;
  const totalDuration = results.reduce((acc, r) => acc + r.durationMs, 0);

  return (
    <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <h2 className="font-tactical text-sm font-bold tracking-wider text-slate-200 uppercase">
              AUTOMATED VERIFICATION &amp; SELF-TEST RUNNER
            </h2>
            <span className="text-[10px] font-mono-code px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
              25 VALIDATION VECTORS
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono-code mt-0.5">
            Automated verification suite validating Windows WFP, Linux nftables, simulation, RBAC, safeguards, and recovery.
          </p>
        </div>

        <button
          onClick={runTests}
          disabled={isRunning}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-tactical font-bold text-xs tracking-wider rounded transition-colors cursor-pointer disabled:opacity-50"
        >
          {isRunning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>RUNNING TESTS ({progress.done}/{progress.total})...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5" />
              <span>EXECUTE FULL TEST SUITE</span>
            </>
          )}
        </button>
      </div>

      {/* Progress & Summary Bar */}
      {results.length > 0 && (
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2 font-mono-code text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-4">
              <span className="text-slate-400">STATUS:</span>
              <span className="flex items-center gap-1 text-emerald-400 font-bold">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {passCount} PASSED
              </span>
              {failCount > 0 ? (
                <span className="flex items-center gap-1 text-red-400 font-bold">
                  <XCircle className="w-3.5 h-3.5" />
                  {failCount} FAILED
                </span>
              ) : (
                <span className="text-slate-500">0 FAILED</span>
              )}
            </div>

            <div className="flex items-center gap-1 text-slate-400 text-[11px]">
              <Clock className="w-3 h-3 text-cyan-400" />
              <span>Total Suite Runtime: {totalDuration.toFixed(1)} ms</span>
            </div>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
            <div 
              className={`h-full transition-all duration-300 ${failCount > 0 ? 'bg-amber-500' : 'bg-cyan-500'}`}
              style={{ width: `${(progress.done / progress.total) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Filters and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono-code">
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search test cases by name or ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3 h-3 text-slate-500" />
          <span className="text-slate-400">CATEGORY:</span>
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Categories</option>
            <option value="WINDOWS_WFP">Windows WFP</option>
            <option value="LINUX_NFTABLES">Linux nftables</option>
            <option value="SIMULATION">Simulation</option>
            <option value="VALIDATION">IP & CIDR Validation</option>
            <option value="RBAC">RBAC & Authentication</option>
            <option value="SAFETY">Safety & Protection</option>
            <option value="PIPELINE">Pipeline & Flow</option>
          </select>
        </div>
      </div>

      {/* Test Cases Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono-code">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
              <th className="py-2 px-3">TEST ID</th>
              <th className="py-2 px-3">NAME &amp; TESTED SUBSYSTEM</th>
              <th className="py-2 px-3">CATEGORY</th>
              <th className="py-2 px-3">STATUS</th>
              <th className="py-2 px-3">DURATION</th>
              <th className="py-2 px-3">ASSERTIONS</th>
              <th className="py-2 px-3">VERIFICATION LOGS / DETAILS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-900">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500">
                  {results.length === 0 ? 'Click "EXECUTE FULL TEST SUITE" to run verification tests.' : 'No tests matching filters.'}
                </td>
              </tr>
            ) : (
              filtered.map((tc) => (
                <tr key={tc.id} className="hover:bg-slate-900/40">
                  <td className="py-2.5 px-3 font-semibold text-slate-400">{tc.id}</td>
                  <td className="py-2.5 px-3 font-bold text-slate-200">{tc.name}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-1.5 py-0.2 rounded border border-slate-800 bg-slate-900 text-cyan-300 text-[10px]">
                      {tc.category}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {tc.status === 'PASS' ? (
                      <span className="px-2 py-0.5 rounded border border-emerald-500/50 bg-emerald-950/80 text-emerald-300 text-[10px] font-bold flex items-center gap-1 w-fit">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        PASS
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded border border-red-500/50 bg-red-950/80 text-red-300 text-[10px] font-bold flex items-center gap-1 w-fit">
                        <XCircle className="w-3 h-3 text-red-400" />
                        FAIL
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {tc.durationMs} ms
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-slate-300">
                    {tc.assertionsCount} checks
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px] max-w-sm truncate" title={tc.details}>
                    {tc.errorMessage ? (
                      <span className="text-red-400 font-bold">{tc.errorMessage}</span>
                    ) : (
                      tc.details
                    )}
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
