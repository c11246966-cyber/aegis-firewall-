import React, { useState, useRef, useEffect } from 'react';
import { 
  Terminal as TerminalIcon, 
  Play, 
  Code2, 
  Copy, 
  Check, 
  Trash2, 
  CornerDownLeft, 
  Download,
  Lock,
  Unlock,
  ShieldCheck,
  CheckCircle2
} from 'lucide-react';
import { aegisStore } from '../services/aegisStore';
import { SimulationVector, OperatingMode, IncidentStatus } from '../types/aegis';
import { authService } from '../services/security/AuthService';
import { privilegedWindowsService } from '../services/security/PrivilegedWindowsService';

interface CliTerminalProps {
  onSimulate: (vec: SimulationVector) => Promise<unknown>;
}

interface TerminalLine {
  id: string;
  type: 'input' | 'output' | 'error' | 'success';
  text: string;
}

export const CliTerminal: React.FC<CliTerminalProps> = ({ onSimulate }) => {
  const [activeSubTab, setActiveSubTab] = useState<'terminal' | 'python_source'>('terminal');
  const [command, setCommand] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [lines, setLines] = useState<TerminalLine[]>([
    { id: '1', type: 'output', text: 'Aegis Cross-Platform Advanced Firewall / IDS / IPS Operator CLI [v2.4.0]' },
    { id: '2', type: 'output', text: 'Active Primary Engine: Windows Filtering Platform (WFP) / Linux nftables' },
    { id: '3', type: 'output', text: 'Privileged Boundary: RESTRICTED IPC (No raw shell access permitted)' },
    { id: '4', type: 'output', text: 'Type "aegis help" or click command pills below to test capabilities.' },
  ]);
  const [copiedPython, setCopiedPython] = useState(false);

  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const addLine = (type: TerminalLine['type'], text: string) => {
    setLines(prev => [...prev, { id: String(Date.now() + Math.random()), type, text }]);
  };

  const executeCommand = async (cmdStr: string) => {
    const raw = cmdStr.trim();
    if (!raw) return;

    // Add to history
    setHistory(prev => [...prev, raw]);
    setHistoryIndex(-1);
    const user = authService.getCurrentSession()?.username || 'operator';
    addLine('input', `${user}@aegis-soc:~$ ${raw}`);

    // Command injection test detection
    if (raw.startsWith('cmd') || raw.startsWith('powershell') || raw.startsWith('bash') || raw.startsWith('sh') || raw.includes('rm -rf') || raw.includes('del /f')) {
      const rej = privilegedWindowsService.rejectArbitraryCommand(raw);
      addLine('error', `[!] SECURITY VIOLATION REFUSAL:\n    ${rej.reason}`);
      return;
    }

    const parts = raw.split(/\s+/);
    let cmd = parts[0];
    let args = parts.slice(1);

    if (cmd === 'aegis' && args.length > 0) {
      cmd = args[0];
      args = args.slice(1);
    }

    if (cmd === 'clear') {
      setLines([]);
      return;
    }

    if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
      addLine('output', `AEGIS OPERATOR COMMAND REFERENCE:
  aegis status                        Show system status, DEFCON risk score, and ingress rate
  aegis platform                      Show current OS platform and active WFP / nftables backend
  aegis verify                        Run cryptographic rule state verification & drift detection
  aegis test                          Run full 25-vector automated self-test suite
  aegis lockdown                      Engage immediate emergency perimeter lockdown
  aegis lift-lockdown                 Lift emergency perimeter lockdown
  aegis audit tail                    Tail recent tamper-evident cryptographic audit records
  aegis user [admin|analyst|viewer]   Switch active RBAC identity
  aegis mode [MONITOR|SIM|ENFORCE]   Set active operating mode
  aegis simulate --vector <VECTOR>    Trigger test: RDP_BRUTE_FORCE, OUTBOUND_BEACON, PORT_SCAN, SYN_FLOOD
  aegis block <IP> [--ttl <SECS>]     Add firewall quarantine rule (with loopback & management protection)
  aegis unblock <IP>                  Remove quarantine rule for target IP
  aegis rules list                    List all active provisioned rules
  clear                               Clear terminal screen`);
      return;
    }

    if (cmd === 'platform') {
      const p = aegisStore.getPlatform();
      const b = aegisStore.getFirewallBackend();
      const caps = aegisStore.getFirewallCapabilities();
      addLine('output', `[+] PLATFORM CONTEXT:
    Target OS:          ${p} (${p === 'WINDOWS' ? 'Windows 11 / Windows Server 2025' : 'Linux Kernel 6.8.0'})
    Firewall Backend:   ${b}
    WFP Sublayer:       AEGIS_WFP_SUBLAYER (GUID: {78f56a32-12bc-449e-bfa1-e23109a63319})
    Rule Prefix:        AEGIS-WFP-*
    Process Filtering:  ${caps.applicationFiltering ? 'SUPPORTED (Windows WFP)' : 'N/A'}
    Stateful Filtering: ${caps.statefulFiltering ? 'ENABLED' : 'DISABLED'}`);
      return;
    }

    if (cmd === 'verify') {
      addLine('output', `[*] Performing WFP rule state verification against baseline policy SHA-256...`);
      const verify = await aegisStore.verifyFirewallState();
      if (!verify.isTampered) {
        addLine('success', `[+] STATE INTEGRITY VERIFIED: ${verify.message}`);
      } else {
        addLine('error', `[!] TAMPER WARNING: ${verify.message}`);
      }
      return;
    }

    if (cmd === 'test') {
      addLine('output', `[*] Starting 25-vector automated verification suite...`);
      const results = await aegisStore.runAllTests();
      const pass = results.filter(r => r.status === 'PASS').length;
      addLine('success', `[+] TEST SUITE FINISHED: ${pass}/25 PASSED in ${results.reduce((a, b) => a + b.durationMs, 0).toFixed(1)}ms.`);
      return;
    }

    if (cmd === 'lockdown') {
      const res = await aegisStore.emergencyLockdown();
      if (res.success) {
        addLine('success', `[+] EMERGENCY LOCKDOWN ENGAGED: Inbound perimeter dropped on WFP. Management IPs preserved.`);
      } else {
        addLine('error', `[!] LOCKDOWN FAILED: ${res.error}`);
      }
      return;
    }

    if (cmd === 'lift-lockdown') {
      const res = await aegisStore.liftLockdown();
      if (res.success) {
        addLine('success', `[+] EMERGENCY LOCKDOWN LIFTED: Perimeter restored to standard policy.`);
      } else {
        addLine('error', `[!] FAILED: ${res.error}`);
      }
      return;
    }

    if (cmd === 'audit') {
      const recs = aegisStore.getAuditRecords().slice(0, 5);
      addLine('output', `[+] TAIL RECENT AUDIT LEDGER (LAST 5 RECORDS):`);
      recs.forEach(r => {
        addLine('output', `  [${new Date(r.timestamp).toLocaleTimeString()}] ${r.action} -> ${r.target} (${r.result}) by ${r.user} [hash: ${r.hash.slice(0, 8)}...]`);
      });
      return;
    }

    if (cmd === 'status') {
      const st = aegisStore.getSystemStatus();
      const risk = aegisStore.getRiskReport();
      addLine('output', `[+] AEGIS SYSTEM STATUS:
    Platform & Backend:${st.platform} (${st.backend})
    Operating Mode:    ${st.mode}
    Safe Simulation:   ${st.isSafeMode ? 'ENABLED (SAFE MODE)' : 'LIVE ENFORCEMENT'}
    Threat Level:      ${risk.threatLevel} (${risk.currentScore}/100)
    Ingress Traffic:   ${st.trafficPps.toLocaleString()} pps / ${st.bandwidthMbps} Mbps
    Packets Analyzed:  ${st.packetsAnalyzed.toLocaleString()}
    Active Blocks:     ${st.activeBlocksCount} rules
    Open Incidents:    ${st.openIncidentsCount}`);
      return;
    }

    if (cmd === 'user') {
      if (args.length > 0) {
        const u = args[0].toLowerCase();
        if (authService.switchUserFast(u)) {
          addLine('success', `[+] Switched active session to user: ${u} (${authService.getCurrentUserRole()})`);
        } else {
          addLine('error', `[!] Unknown user: ${u}. Available: admin, analyst, operator, viewer.`);
        }
      } else {
        const cur = authService.getCurrentSession();
        addLine('output', `Active User: ${cur?.username} | Role: ${cur?.role} | Token: ${cur?.token?.slice(0, 15)}...`);
      }
      return;
    }

    if (cmd === 'block') {
      const ip = args[0];
      if (!ip) {
        addLine('error', 'Usage: aegis block <IP_OR_CIDR> [--ttl <SECS>]');
        return;
      }
      let ttl = 900;
      const ttlIdx = args.indexOf('--ttl');
      if (ttlIdx !== -1 && args[ttlIdx + 1]) {
        ttl = parseInt(args[ttlIdx + 1], 10) || 900;
      }
      const res = aegisStore.addRule(ip, 'DROP', ttl, 'CLI operator intervention');
      if (res.success) {
        addLine('success', `[+] Rule provisioned to WFP: DROP ${ip} (TTL: ${ttl}s)`);
      } else {
        addLine('error', `[!] Firewall operation refused: ${res.error}`);
      }
      return;
    }

    if (cmd === 'unblock') {
      const ip = args[0];
      if (!ip) {
        addLine('error', 'Usage: aegis unblock <IP_OR_CIDR>');
        return;
      }
      const rules = await aegisStore.listRulesAsync();
      const match = rules.find(r => r.ipCidr === ip);
      if (match) {
        aegisStore.removeRule(match.id);
        addLine('success', `[+] Removed rule ${match.name} for ${ip}.`);
      } else {
        addLine('error', `[!] No active rule found for IP: ${ip}.`);
      }
      return;
    }

    if (cmd === 'simulate') {
      const vecIdx = args.indexOf('--vector');
      const vec = (vecIdx !== -1 && args[vecIdx + 1]) ? (args[vecIdx + 1] as SimulationVector) : 'RDP_BRUTE_FORCE';
      addLine('output', `[*] Injecting telemetry simulation vector: ${vec}...`);
      await onSimulate(vec);
      addLine('success', `[+] Simulation vector ${vec} processed by Detection Engine -> Policy Engine.`);
      return;
    }

    if (cmd === 'rules') {
      const rules = await aegisStore.listRulesAsync();
      addLine('output', `[+] ACTIVE PROVISIONED RULES (${rules.length} ENTRIES):`);
      rules.forEach(r => {
        addLine('output', `  • ${r.name}: ${r.action} ${r.ipCidr} [${r.direction || 'IN'}/${r.protocol || 'TCP'}] (TTL: ${r.ttlSeconds}s hits: ${r.hits})`);
      });
      return;
    }

    addLine('error', `Command not recognized: "${raw}". Type "aegis help" for available commands.`);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      executeCommand(command);
      setCommand('');
    } else if (e.key === 'ArrowUp') {
      if (history.length > 0) {
        const nextIdx = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(nextIdx);
        setCommand(history[nextIdx]);
      }
    } else if (e.key === 'ArrowDown') {
      if (historyIndex !== -1) {
        const nextIdx = historyIndex + 1;
        if (nextIdx >= history.length) {
          setHistoryIndex(-1);
          setCommand('');
        } else {
          setHistoryIndex(nextIdx);
          setCommand(history[nextIdx]);
        }
      }
    }
  };

  return (
    <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <TerminalIcon className="w-4 h-4 text-cyan-400" />
            <h2 className="font-tactical text-sm font-bold tracking-wider text-slate-200 uppercase">
              LOCAL OPERATOR CLI &amp; IPC INTERFACE
            </h2>
            <span className="text-[10px] font-mono-code px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
              RESTRICTED IPC BOUNDARY
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono-code mt-0.5">
            Command-line administrative interface communicating directly with the privileged Aegis helper service.
          </p>
        </div>

        <button
          onClick={() => setLines([])}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 font-mono-code text-xs cursor-pointer"
        >
          <Trash2 className="w-3 h-3" />
          <span>CLEAR SCREEN</span>
        </button>
      </div>

      {/* Suggested Command Pills */}
      <div className="flex flex-wrap items-center gap-2 text-xs font-mono-code">
        <span className="text-slate-500 text-[11px]">RUN:</span>
        <button onClick={() => executeCommand('aegis platform')} className="px-2 py-0.5 rounded bg-slate-900 hover:bg-cyan-950 text-cyan-300 border border-slate-800 hover:border-cyan-700 cursor-pointer">
          aegis platform
        </button>
        <button onClick={() => executeCommand('aegis verify')} className="px-2 py-0.5 rounded bg-slate-900 hover:bg-cyan-950 text-cyan-300 border border-slate-800 hover:border-cyan-700 cursor-pointer">
          aegis verify
        </button>
        <button onClick={() => executeCommand('aegis test')} className="px-2 py-0.5 rounded bg-slate-900 hover:bg-cyan-950 text-cyan-300 border border-slate-800 hover:border-cyan-700 cursor-pointer">
          aegis test
        </button>
        <button onClick={() => executeCommand('aegis simulate --vector RDP_BRUTE_FORCE')} className="px-2 py-0.5 rounded bg-slate-900 hover:bg-rose-950 text-rose-300 border border-slate-800 hover:border-rose-700 cursor-pointer">
          simulate RDP_BRUTE_FORCE
        </button>
        <button onClick={() => executeCommand('aegis simulate --vector OUTBOUND_BEACON')} className="px-2 py-0.5 rounded bg-slate-900 hover:bg-red-950 text-red-300 border border-slate-800 hover:border-red-700 cursor-pointer">
          simulate OUTBOUND_BEACON
        </button>
        <button onClick={() => executeCommand('aegis rules list')} className="px-2 py-0.5 rounded bg-slate-900 hover:bg-cyan-950 text-cyan-300 border border-slate-800 hover:border-cyan-700 cursor-pointer">
          aegis rules list
        </button>
        <button onClick={() => executeCommand('cmd.exe /c del system32')} className="px-2 py-0.5 rounded bg-red-950/60 hover:bg-red-900 text-red-300 border border-red-800 cursor-pointer" title="Tests that arbitrary command injection is blocked">
          [Test Injection Rejection]
        </button>
      </div>

      {/* Terminal Screen */}
      <div 
        className="bg-black/90 border border-slate-800 rounded-lg p-4 font-mono-code text-xs space-y-1 min-h-[380px] max-h-[460px] overflow-y-auto"
        onClick={() => inputRef.current?.focus()}
      >
        {lines.map((l) => (
          <div 
            key={l.id} 
            className={`whitespace-pre-wrap leading-relaxed ${
              l.type === 'input' ? 'text-slate-100 font-bold' :
              l.type === 'error' ? 'text-red-400' :
              l.type === 'success' ? 'text-emerald-400 font-semibold' :
              'text-slate-300'
            }`}
          >
            {l.text}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Terminal Input Bar */}
      <div className="flex items-center gap-2 p-2 bg-slate-900/90 border border-slate-800 rounded-lg font-mono-code text-xs">
        <span className="text-cyan-400 font-bold shrink-0">{authService.getCurrentSession()?.username || 'operator'}@aegis-soc:~$</span>
        <input
          ref={inputRef}
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder='Type command (e.g. "aegis status", "aegis platform", "aegis verify")...'
          className="flex-1 bg-transparent text-slate-100 placeholder:text-slate-600 focus:outline-none"
          autoFocus
        />
        <button
          onClick={() => { executeCommand(command); setCommand(''); }}
          className="p-1.5 text-cyan-400 hover:text-cyan-300 rounded cursor-pointer"
        >
          <CornerDownLeft className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
