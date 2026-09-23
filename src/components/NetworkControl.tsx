import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldX, 
  ShieldAlert, 
  Clock, 
  AlertTriangle, 
  Check, 
  Trash2, 
  Plus, 
  Copy, 
  Download, 
  Terminal,
  Code,
  Layers,
  Lock,
  Server,
  Cpu
} from 'lucide-react';
import { 
  FirewallRule, 
  FirewallAction, 
  RuleDirection, 
  NetworkProtocol, 
  PlatformType,
  OperatingMode,
  WfpVerificationStatus
} from '../types/aegis';
import { validateIpOrCidr, IpValidationResult } from '../utils/ipValidator';
import { authService } from '../services/security/AuthService';
import { WfpVerificationPanel } from './WfpVerificationPanel';
import { aegisStore } from '../services/aegisStore';

interface NetworkControlProps {
  platform: PlatformType;
  rules: FirewallRule[];
  mode?: OperatingMode;
  onSelectMode?: (mode: OperatingMode) => void;
  onAddRule: (
    ipCidr: string, 
    action: FirewallAction, 
    ttlSeconds: number, 
    reason: string,
    comment?: string,
    overrideSafeguard?: boolean,
    direction?: RuleDirection,
    protocol?: NetworkProtocol,
    portRange?: string,
    applicationPath?: string
  ) => { success: boolean; error?: string };
  onRemoveRule: (id: string) => void;
  presetTargetIp?: string | null;
}

export const NetworkControl: React.FC<NetworkControlProps> = ({
  platform,
  rules,
  mode = 'SIMULATION',
  onSelectMode,
  onAddRule,
  onRemoveRule,
  presetTargetIp,
}) => {
  const [wfpStatus, setWfpStatus] = useState<WfpVerificationStatus>(() => aegisStore.getWfpVerificationStatus());

  useEffect(() => {
    const update = () => {
      setWfpStatus(aegisStore.getWfpVerificationStatus());
    };
    const unsub = aegisStore.subscribe(update);
    return unsub;
  }, []);
  const [targetIp, setTargetIp] = useState(presetTargetIp || '');
  const [action, setAction] = useState<FirewallAction>('DROP');
  const [direction, setDirection] = useState<RuleDirection>('INBOUND');
  const [protocol, setProtocol] = useState<NetworkProtocol>('TCP');
  const [portRange, setPortRange] = useState('');
  const [applicationPath, setApplicationPath] = useState('');
  const [ttlSeconds, setTtlSeconds] = useState<number>(900); // 15 min default
  const [reason, setReason] = useState('Manual SOC operator intervention');
  const [overrideSafeguard, setOverrideSafeguard] = useState(false);
  const [validation, setValidation] = useState<IpValidationResult | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [syntaxView, setSyntaxView] = useState<'windows' | 'nftables' | 'iptables'>('windows');
  const [copiedCode, setCopiedCode] = useState(false);

  const currentUserRole = authService.getCurrentUserRole();

  // Sync presetTargetIp if passed
  useEffect(() => {
    if (presetTargetIp) {
      setTargetIp(presetTargetIp);
      setValidation(validateIpOrCidr(presetTargetIp));
    }
  }, [presetTargetIp]);

  // Validate on change
  const handleIpChange = (val: string) => {
    setTargetIp(val);
    setFormError(null);
    if (val.trim()) {
      setValidation(validateIpOrCidr(val));
    } else {
      setValidation(null);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (currentUserRole === 'VIEWER') {
      setFormError('RBAC 403 FORBIDDEN: Viewers cannot create or modify firewall rules.');
      return;
    }

    const result = onAddRule(
      targetIp, 
      action, 
      ttlSeconds, 
      reason, 
      undefined, 
      overrideSafeguard,
      direction,
      protocol,
      portRange || undefined,
      applicationPath || undefined
    );

    if (!result.success) {
      setFormError(result.error || 'Failed to apply rule');
    } else {
      setTargetIp('');
      setValidation(null);
      setPortRange('');
      setApplicationPath('');
      setOverrideSafeguard(false);
    }
  };

  const formatRemaining = (expiresAt: number | null) => {
    if (!expiresAt) return 'Permanent (No TTL)';
    const remainingMs = expiresAt - Date.now();
    if (remainingMs <= 0) return 'Expiring...';
    const totalSecs = Math.floor(remainingMs / 1000);
    const m = Math.floor(totalSecs / 60);
    const s = totalSecs % 60;
    if (m > 60) {
      const h = Math.floor(m / 60);
      return `${h}h ${m % 60}m`;
    }
    return `${m}m ${s}s`;
  };

  const generateWindowsSyntax = () => {
    return `# =====================================================================
# AEGIS NATIVE WINDOWS FILTERING PLATFORM (WFP) & ADVANCED FIREWALL CONFIG
# Sublayer: AEGIS_WFP_SUBLAYER (GUID: {78f56a32-12bc-449e-bfa1-e23109a63319})
# Timestamp: ${new Date().toISOString()}
# Active Aegis Rules: ${rules.length}
# =====================================================================

# Ensure Aegis WFP Sublayer is active
Write-Host "Verifying Aegis Windows Filtering Platform sublayer..."

${rules.map(r => {
  const dir = r.direction || 'INBOUND';
  const proto = r.protocol || 'TCP';
  const portParam = r.portRange ? ` -LocalPort ${r.portRange}` : '';
  const progParam = r.applicationPath ? ` -Program "${r.applicationPath}"` : '';
  const actionParam = r.action === 'ALLOW' ? 'Allow' : 'Block';
  
  return `# Rule ID: ${r.id} | TTL: ${r.ttlSeconds}s | Hits: ${r.hits}
New-NetFirewallRule -Name "${r.name}" \`
  -DisplayName "${r.name}" \`
  -Description "${r.reason} (Aegis SOC Managed)" \`
  -Direction ${dir === 'INBOUND' ? 'Inbound' : 'Outbound'} \`
  -Action ${actionParam} \`
  -RemoteAddress "${r.ipCidr}" \`
  -Protocol ${proto}${portParam}${progParam} \`
  -Profile Any \`
  -Enabled True`;
}).join('\n\n')}
`;
  };

  const generateNftablesSyntax = () => {
    return `# =====================================================================
# AEGIS LINUX KERNEL NFTABLES CONFIGURATION (INET AEGIS_FILTER)
# Timestamp: ${new Date().toISOString()}
# =====================================================================

table inet aegis_filter {
  set aegis_drop_v4 {
    type ipv4_addr
    flags timeout
    elements = {
${rules.filter(r => r.action === 'DROP' && !r.ipCidr.includes(':')).map(r => `      ${r.ipCidr} timeout ${r.ttlSeconds}s comment "${r.name}"`).join(',\n')}
    }
  }

  set aegis_whitelist_v4 {
    type ipv4_addr
    elements = {
${rules.filter(r => r.action === 'ALLOW' && !r.ipCidr.includes(':')).map(r => `      ${r.ipCidr} comment "${r.name}"`).join(',\n')}
    }
  }

  chain aegis_input {
    type filter hook input priority -100; policy accept;
    
    # Loopback and established state protection
    iif "lo" accept
    ct state established,related accept

    # Whitelist before blacklist
    ip saddr @aegis_whitelist_v4 accept
    ip saddr @aegis_drop_v4 counter drop
  }
}
`;
  };

  const generateIptablesSyntax = () => {
    return `# =====================================================================
# AEGIS LEGACY IPTABLES FALLBACK CONFIGURATION
# =====================================================================
iptables -N AEGIS_INPUT
iptables -F AEGIS_INPUT
iptables -A INPUT -j AEGIS_INPUT
iptables -A AEGIS_INPUT -i lo -j ACCEPT
iptables -A AEGIS_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

${rules.map(r => {
  if (r.action === 'ALLOW') {
    return `iptables -A AEGIS_INPUT -s ${r.ipCidr} -j ACCEPT -m comment --comment "${r.name}: ${r.reason}"`;
  }
  return `iptables -A AEGIS_INPUT -s ${r.ipCidr} -j DROP -m comment --comment "${r.name}: TTL-${r.ttlSeconds}s hits=${r.hits}"`;
}).join('\n')}
`;
  };

  const copyConfig = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <h2 className="font-tactical text-sm font-bold tracking-wider text-slate-200 uppercase">
              FIREWALL ABSTRACTION &amp; WFP / NFTABLES CONTROLS
            </h2>
            <span className="text-[10px] font-mono-code px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
              PRIMARY: {platform}
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono-code mt-0.5">
            Windows Filtering Platform (WFP), stateful inspection, process-aware rules, and subnet quarantines.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono-code">
          <span className="text-slate-400">ACTIVE RULES:</span>
          <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-bold">
            {rules.length} PROVISIONED
          </span>
        </div>
      </div>

      {/* Dedicated Windows WFP Verification Panel */}
      <WfpVerificationPanel
        status={wfpStatus}
        mode={mode}
        onRefreshStatus={() => setWfpStatus(aegisStore.getWfpVerificationStatus())}
        onModeSwitch={onSelectMode}
      />

      {/* Add Rule Form */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-tactical font-bold tracking-wider text-slate-200 uppercase mb-3 flex items-center gap-1.5">
          <Plus className="w-3.5 h-3.5 text-cyan-400" />
          <span>PROVISION FIREWALL RULE ({platform === 'WINDOWS' ? 'WFP NetSecurity' : 'Linux Kernel'})</span>
        </h3>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 text-xs font-mono-code">
            {/* IP / CIDR Input */}
            <div className="sm:col-span-4">
              <label className="block text-slate-400 mb-1">TARGET IP OR CIDR (v4 / v6)</label>
              <input
                type="text"
                placeholder="e.g. 198.51.100.42 or 203.0.113.0/24"
                value={targetIp}
                onChange={(e) => handleIpChange(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono-code"
                required
              />
            </div>

            {/* Action */}
            <div className="sm:col-span-2">
              <label className="block text-slate-400 mb-1">ACTION</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value as FirewallAction)}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="DROP">DROP</option>
                <option value="REJECT">REJECT (RST)</option>
                <option value="ALLOW">ALLOW (WHITELIST)</option>
              </select>
            </div>

            {/* Direction */}
            <div className="sm:col-span-2">
              <label className="block text-slate-400 mb-1">DIRECTION</label>
              <select
                value={direction}
                onChange={(e) => setDirection(e.target.value as RuleDirection)}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="INBOUND">INBOUND</option>
                <option value="OUTBOUND">OUTBOUND</option>
              </select>
            </div>

            {/* Protocol */}
            <div className="sm:col-span-2">
              <label className="block text-slate-400 mb-1">PROTOCOL</label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value as NetworkProtocol)}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
                <option value="ANY">ANY</option>
              </select>
            </div>

            {/* TTL Selector */}
            <div className="sm:col-span-2">
              <label className="block text-slate-400 mb-1">TTL (AUTO-EXPIRE)</label>
              <select
                value={ttlSeconds}
                onChange={(e) => setTtlSeconds(parseInt(e.target.value, 10))}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value={300}>5 Min (300s)</option>
                <option value={900}>15 Min (900s)</option>
                <option value={3600}>1 Hour (3,600s)</option>
                <option value={86400}>24 Hours (86,400s)</option>
                <option value={0}>Permanent (0s)</option>
              </select>
            </div>
          </div>

          {/* Port and Process Path (Windows WFP feature) */}
          <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 text-xs font-mono-code pt-1">
            <div className="sm:col-span-4">
              <label className="block text-slate-400 mb-1">PORT RANGE (OPTIONAL)</label>
              <input
                type="text"
                placeholder="e.g. 80,443 or 3389 or 1-1024"
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono-code"
              />
            </div>

            <div className="sm:col-span-8">
              <label className="block text-slate-400 mb-1 flex items-center justify-between">
                <span>APPLICATION / BINARY PATH (WINDOWS WFP PROCESS FILTER)</span>
                <span className="text-[10px] text-cyan-400">Windows WFP Native</span>
              </label>
              <input
                type="text"
                placeholder="e.g. C:\Windows\System32\cmd.exe or powershell.exe"
                value={applicationPath}
                onChange={(e) => setApplicationPath(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono-code"
              />
            </div>
          </div>

          {/* Reason */}
          <div className="text-xs font-mono-code">
            <label className="block text-slate-400 mb-1">REASON &amp; AUDIT COMMENT</label>
            <input
              type="text"
              placeholder="e.g. Automated incident containment for malicious RDP credential sweep"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono-code"
              required
            />
          </div>

          {/* Validation Feedback & Safety Warning */}
          {validation && (
            <div className="text-xs font-mono-code">
              {validation.isTrustedManagement ? (
                <div className="p-2.5 rounded bg-red-950/80 border border-red-500 text-red-200 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold">CRITICAL SAFETY INTERLOCK:</span> Target IP is in the
                    Trusted Management Protection List ({targetIp}). Dropping this target is strictly
                    blocked to preserve SOC connectivity.
                  </div>
                </div>
              ) : validation.isSafeguarded ? (
                <div className="p-2.5 rounded bg-amber-950/80 border border-amber-500 text-amber-200 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <div>
                      <span className="font-bold">RFC1918 / LOOPBACK SAFEGUARD:</span> {validation.safeguardMessage || 'Private address range safeguard triggered.'}
                    </div>
                    <label className="flex items-center gap-2 cursor-pointer font-bold text-amber-300">
                      <input
                        type="checkbox"
                        checked={overrideSafeguard}
                        onChange={(e) => setOverrideSafeguard(e.target.checked)}
                        className="rounded border-amber-500"
                      />
                      <span>Override Safeguard (Acknowledge risk of blocking internal range)</span>
                    </label>
                  </div>
                </div>
              ) : validation.isValid ? (
                <div className="text-emerald-400 flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5" />
                  <span>Valid {validation.version} Address</span>
                </div>
              ) : (
                <div className="text-red-400 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>{validation.error}</span>
                </div>
              )}
            </div>
          )}

          {formError && (
            <div className="p-2 bg-red-950/80 border border-red-500 text-red-200 text-xs font-mono-code rounded">
              {formError}
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={validation?.isTrustedManagement || (!validation?.isValid && !overrideSafeguard)}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-tactical font-bold text-xs tracking-wider rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              PROVISION RULE TO {platform === 'WINDOWS' ? 'WINDOWS WFP' : 'NFTABLES'}
            </button>
          </div>
        </form>
      </div>

      {/* Active Rules Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs font-mono-code">
          <span className="font-bold text-slate-300 uppercase tracking-wider">
            ACTIVE ENFORCED RULES (PREFIX: AEGIS-WFP-*)
          </span>
          <span className="text-slate-500">
            Rules sorted by creation time
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono-code">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                <th className="py-2 px-3">RULE ID / WFP NAME</th>
                <th className="py-2 px-3">TARGET IP / CIDR</th>
                <th className="py-2 px-3">ACTION</th>
                <th className="py-2 px-3">DIR / PROTO</th>
                <th className="py-2 px-3">PROCESS / PORT</th>
                <th className="py-2 px-3">REMAINING TTL</th>
                <th className="py-2 px-3">HITS</th>
                <th className="py-2 px-3">REASON</th>
                <th className="py-2 px-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {rules.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500">
                    No active firewall rules provisioned.
                  </td>
                </tr>
              ) : (
                rules.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-900/40">
                    <td className="py-2.5 px-3 font-semibold text-slate-300 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-cyan-400 font-mono-code text-[11px]">{r.name}</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-bold text-slate-100 whitespace-nowrap">
                      {r.ipCidr}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        r.action === 'ALLOW' 
                          ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/50' 
                          : 'bg-red-950/80 text-red-300 border border-red-500/50'
                      }`}>
                        {r.action}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-400">
                        {r.direction || 'IN'} / {r.protocol || 'TCP'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 max-w-[120px] truncate" title={r.applicationPath || r.portRange || 'Any'}>
                      {r.applicationPath ? r.applicationPath.split('\\').pop() : r.portRange || 'Any'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                      <span className="flex items-center gap-1 text-[11px]">
                        <Clock className="w-3 h-3 text-cyan-400" />
                        {formatRemaining(r.expiresAt)}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-cyan-300 whitespace-nowrap">
                      {r.hits.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate" title={r.reason}>
                      {r.reason}
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => onRemoveRule(r.id)}
                        className="p-1 rounded text-slate-500 hover:text-red-400 hover:bg-red-950/30 transition-colors cursor-pointer"
                        title="Delete rule safely from firewall"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Syntax Preview Tab */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-tactical font-bold tracking-wider text-slate-200 uppercase">
              PLATFORM FIREWALL SYNTAX PREVIEW
            </h3>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex bg-slate-950 border border-slate-800 rounded p-0.5 text-xs font-mono-code">
              <button
                onClick={() => setSyntaxView('windows')}
                className={`px-3 py-1 rounded transition-colors cursor-pointer ${
                  syntaxView === 'windows' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold' : 'text-slate-400'
                }`}
              >
                Windows (WFP / PowerShell)
              </button>
              <button
                onClick={() => setSyntaxView('nftables')}
                className={`px-3 py-1 rounded transition-colors cursor-pointer ${
                  syntaxView === 'nftables' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold' : 'text-slate-400'
                }`}
              >
                Linux (nftables)
              </button>
              <button
                onClick={() => setSyntaxView('iptables')}
                className={`px-3 py-1 rounded transition-colors cursor-pointer ${
                  syntaxView === 'iptables' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold' : 'text-slate-400'
                }`}
              >
                Linux (iptables)
              </button>
            </div>

            <button
              onClick={() => copyConfig(syntaxView === 'windows' ? generateWindowsSyntax() : syntaxView === 'nftables' ? generateNftablesSyntax() : generateIptablesSyntax())}
              className="flex items-center gap-1.5 px-3 py-1 bg-slate-950 hover:bg-slate-850 text-slate-200 border border-slate-800 rounded text-xs font-mono-code cursor-pointer"
            >
              {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCode ? 'COPIED' : 'COPY'}</span>
            </button>
          </div>
        </div>

        <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono-code text-[11px] text-slate-300 overflow-x-auto max-h-72 leading-relaxed">
          {syntaxView === 'windows' ? generateWindowsSyntax() : syntaxView === 'nftables' ? generateNftablesSyntax() : generateIptablesSyntax()}
        </pre>
      </div>
    </div>
  );
};
