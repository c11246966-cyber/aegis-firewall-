import React, { useState } from 'react';
import { 
  Code2, 
  Send, 
  Copy, 
  Check, 
  Database, 
  ShieldCheck, 
  Play, 
  Cpu,
  CornerDownRight,
  FileCode,
  Server,
  Layers,
  Lock,
  Unlock,
  CheckCircle2
} from 'lucide-react';
import { aegisStore } from '../services/aegisStore';
import { SimulationVector, OperatingMode, IncidentStatus } from '../types/aegis';

interface ApiEndpoint {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  summary: string;
  description: string;
  requestBodySample?: object;
  curlExample: string;
  handler: (body?: unknown) => Promise<unknown> | unknown;
}

export const ApiExplorer: React.FC = () => {
  const [selectedEndpointIndex, setSelectedEndpointIndex] = useState(0);
  const [customBody, setCustomBody] = useState<string>('');
  const [responseOutput, setResponseOutput] = useState<string | null>(null);
  const [statusCode, setStatusCode] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);

  const endpoints: ApiEndpoint[] = [
    {
      method: 'GET',
      path: '/system/platform',
      summary: 'Get current OS platform & architecture',
      description: 'Returns detected platform (WINDOWS, LINUX, SIMULATION), architecture, and OS kernel version.',
      curlExample: 'curl -X GET "http://127.0.0.1:8000/system/platform"',
      handler: () => ({
        platform: aegisStore.getPlatform(),
        architecture: 'x86_64',
        os: aegisStore.getPlatform() === 'WINDOWS' ? 'Windows 11 / Windows Server 2025' : 'Ubuntu 24.04 LTS',
        status: 'ONLINE',
      }),
    },
    {
      method: 'GET',
      path: '/system/firewall/backend',
      summary: 'Get active firewall abstraction backend',
      description: 'Returns active backend engine (WINDOWS_WFP, LINUX_NFTABLES, SIMULATION), sublayer GUID, and rule prefix.',
      curlExample: 'curl -X GET "http://127.0.0.1:8000/system/firewall/backend"',
      handler: () => ({
        backend: aegisStore.getFirewallBackend(),
        sublayer: 'AEGIS_WFP_SUBLAYER',
        sublayerGuid: '{78f56a32-12bc-449e-bfa1-e23109a63319}',
        prefix: 'AEGIS-WFP-',
        driverLoaded: true,
      }),
    },
    {
      method: 'GET',
      path: '/system/firewall/capabilities',
      summary: 'List supported firewall capabilities',
      description: 'Reports support for IPv4/IPv6, Inbound/Outbound, stateful inspection, process filtering, TTL expiration, and lockdown.',
      curlExample: 'curl -X GET "http://127.0.0.1:8000/system/firewall/capabilities"',
      handler: () => aegisStore.getFirewallCapabilities(),
    },
    {
      method: 'GET',
      path: '/system/firewall/health',
      summary: 'Health check and tamper verification',
      description: 'Checks driver communication status, sublayer state, and cryptographic tamper detection.',
      curlExample: 'curl -X GET "http://127.0.0.1:8000/system/firewall/health"',
      handler: async () => await aegisStore.getFirewallHealth(),
    },
    {
      method: 'GET',
      path: '/system/status',
      summary: 'Get Aegis system status & telemetry',
      description: 'Returns current operating mode (MONITOR/SIMULATION/ENFORCEMENT), packet rates, and active counters.',
      curlExample: 'curl -X GET "http://127.0.0.1:8000/system/status"',
      handler: () => aegisStore.getSystemStatus(),
    },
    {
      method: 'POST',
      path: '/firewall/emergency-lockdown',
      summary: 'Engage emergency perimeter lockdown',
      description: 'Immediately blocks all incoming connections across WFP except Trusted Management IPs.',
      curlExample: 'curl -X POST "http://127.0.0.1:8000/firewall/emergency-lockdown"',
      handler: async () => await aegisStore.emergencyLockdown(),
    },
    {
      method: 'POST',
      path: '/firewall/lift-lockdown',
      summary: 'Lift emergency perimeter lockdown',
      description: 'Restores baseline firewall policies after emergency containment.',
      curlExample: 'curl -X POST "http://127.0.0.1:8000/firewall/lift-lockdown"',
      handler: async () => await aegisStore.liftLockdown(),
    },
    {
      method: 'POST',
      path: '/firewall/rules',
      summary: 'Add firewall rule with mandatory 7-step safety check',
      description: 'Creates an AEGIS-WFP- prefixed rule with validation, RBAC verification, audit logging, and state check.',
      requestBodySample: {
        ipCidr: '198.51.100.88',
        action: 'DROP',
        direction: 'INBOUND',
        protocol: 'TCP',
        portRange: '3389',
        ttlSeconds: 900,
        reason: 'Automated REST API mitigation for RDP brute-force',
      },
      curlExample: 'curl -X POST "http://127.0.0.1:8000/firewall/rules" -H "Content-Type: application/json" -d \'{"ipCidr":"198.51.100.88","action":"DROP","ttlSeconds":900,"reason":"REST block"}\'',
      handler: (body: unknown) => {
        const b = body as any;
        return aegisStore.addRule(
          b?.ipCidr || '198.51.100.88', 
          b?.action || 'DROP', 
          b?.ttlSeconds || 900, 
          b?.reason || 'API rule',
          undefined,
          false,
          b?.direction || 'INBOUND',
          b?.protocol || 'TCP',
          b?.portRange,
          b?.applicationPath
        );
      },
    },
    {
      method: 'POST',
      path: '/simulate',
      summary: 'Trigger safe attack simulation vector',
      description: 'Injects test packets for RDP_BRUTE_FORCE, PORT_SCAN, OUTBOUND_BEACON, HTTP_ANOMALY, or SYN_FLOOD.',
      requestBodySample: {
        vector: 'RDP_BRUTE_FORCE',
      },
      curlExample: 'curl -X POST "http://127.0.0.1:8000/simulate" -H "Content-Type: application/json" -d \'{"vector":"RDP_BRUTE_FORCE"}\'',
      handler: async (body: unknown) => {
        const b = body as { vector?: SimulationVector };
        const vec = b?.vector || 'RDP_BRUTE_FORCE';
        return await aegisStore.simulateVector(vec);
      },
    },
    {
      method: 'GET',
      path: '/audit/records',
      summary: 'Fetch cryptographically chained audit records',
      description: 'Returns tamper-evident audit ledger with hashes, users, actions, and timestamps.',
      curlExample: 'curl -X GET "http://127.0.0.1:8000/audit/records"',
      handler: () => aegisStore.getAuditRecords().slice(0, 10),
    },
  ];

  const currentEndpoint = endpoints[selectedEndpointIndex];

  const handleSelectEndpoint = (index: number) => {
    setSelectedEndpointIndex(index);
    const ep = endpoints[index];
    if (ep.requestBodySample) {
      setCustomBody(JSON.stringify(ep.requestBodySample, null, 2));
    } else {
      setCustomBody('');
    }
    setResponseOutput(null);
    setStatusCode(null);
  };

  const handleExecute = async () => {
    setLoading(true);
    setResponseOutput(null);
    try {
      let parsedBody: unknown = undefined;
      if (currentEndpoint.requestBodySample && customBody.trim()) {
        parsedBody = JSON.parse(customBody);
      }
      const res = await currentEndpoint.handler(parsedBody);
      setResponseOutput(JSON.stringify(res, null, 2));
      setStatusCode(200);
    } catch (err: unknown) {
      setResponseOutput(JSON.stringify({ error: String(err) }, null, 2));
      setStatusCode(400);
    } finally {
      setLoading(false);
    }
  };

  const copyCurl = () => {
    navigator.clipboard.writeText(currentEndpoint.curlExample);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  return (
    <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-cyan-400" />
            <h2 className="font-tactical text-sm font-bold tracking-wider text-slate-200 uppercase">
              CROSS-PLATFORM REST API EXPLORER
            </h2>
            <span className="text-[10px] font-mono-code px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
              FASTAPI SPECIFICATION
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono-code mt-0.5">
            Test platform discovery endpoints, native WFP firewall manipulation, and telemetry queries.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono-code">
          <span className="text-slate-400">SERVER:</span>
          <span className="text-cyan-400 font-bold">http://127.0.0.1:8000</span>
        </div>
      </div>

      {/* Explorer Split Pane */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Endpoint Selector List */}
        <div className="lg:col-span-4 bg-slate-900/60 border border-slate-800 rounded-lg p-2 space-y-1 max-h-[600px] overflow-y-auto">
          {endpoints.map((ep, idx) => {
            const isSelected = selectedEndpointIndex === idx;
            const methodColor = 
              ep.method === 'GET' ? 'text-cyan-400 bg-cyan-950/80 border-cyan-800' :
              ep.method === 'POST' ? 'text-emerald-400 bg-emerald-950/80 border-emerald-800' :
              ep.method === 'PATCH' ? 'text-amber-400 bg-amber-950/80 border-amber-800' :
              'text-red-400 bg-red-950/80 border-red-800';

            return (
              <button
                key={ep.path + ep.method}
                onClick={() => handleSelectEndpoint(idx)}
                className={`w-full text-left p-2.5 rounded transition-all flex flex-col gap-1 cursor-pointer ${
                  isSelected 
                    ? 'bg-slate-950 border border-cyan-500/60 shadow-[0_0_10px_rgba(6,182,212,0.1)]' 
                    : 'hover:bg-slate-850 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`px-1.5 py-0.2 rounded border text-[10px] font-mono-code font-bold ${methodColor}`}>
                    {ep.method}
                  </span>
                  <span className="font-mono-code text-xs font-bold text-slate-200 truncate">
                    {ep.path}
                  </span>
                </div>
                <span className="text-[11px] text-slate-400 truncate">
                  {ep.summary}
                </span>
              </button>
            );
          })}
        </div>

        {/* Selected Endpoint Execution & Output */}
        <div className="lg:col-span-8 space-y-4">
          {/* Detail Header */}
          <div className="p-3 bg-slate-900/80 border border-slate-800 rounded space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded border text-xs font-mono-code font-bold ${
                  currentEndpoint.method === 'GET' ? 'text-cyan-400 bg-cyan-950 border-cyan-800' :
                  currentEndpoint.method === 'POST' ? 'text-emerald-400 bg-emerald-950 border-emerald-800' :
                  'text-amber-400 bg-amber-950 border-amber-800'
                }`}>
                  {currentEndpoint.method}
                </span>
                <span className="font-mono-code text-sm font-bold text-slate-100">
                  {currentEndpoint.path}
                </span>
              </div>

              <button
                onClick={handleExecute}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 rounded font-tactical text-xs font-bold tracking-wider transition-colors disabled:opacity-50 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{loading ? 'SENDING...' : 'DISPATCH REQUEST'}</span>
              </button>
            </div>

            <p className="text-xs text-slate-300 font-mono-code">
              {currentEndpoint.description}
            </p>

            {/* cURL command */}
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-2 text-[11px] font-mono-code">
              <span className="text-slate-400 truncate max-w-md">
                {currentEndpoint.curlExample}
              </span>
              <button
                onClick={copyCurl}
                className="flex items-center gap-1 text-slate-400 hover:text-cyan-400 cursor-pointer shrink-0"
              >
                {copiedCurl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedCurl ? 'COPIED' : 'COPY CURL'}</span>
              </button>
            </div>
          </div>

          {/* Request Body (if POST/PATCH) */}
          {currentEndpoint.requestBodySample && (
            <div className="space-y-1">
              <label className="block text-xs font-mono-code text-slate-400">
                JSON REQUEST PAYLOAD:
              </label>
              <textarea
                value={customBody}
                onChange={(e) => setCustomBody(e.target.value)}
                rows={5}
                className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded font-mono-code text-xs text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
            </div>
          )}

          {/* Response Box */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-code">
              <span className="text-slate-400">HTTP RESPONSE BODY:</span>
              {statusCode !== null && (
                <span className={`px-2 py-0.5 rounded font-bold ${
                  statusCode === 200 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-red-950 text-red-300 border border-red-800'
                }`}>
                  HTTP {statusCode} OK
                </span>
              )}
            </div>

            <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono-code text-xs text-slate-300 overflow-x-auto min-h-[160px] max-h-[300px]">
              {responseOutput || '// Click "DISPATCH REQUEST" to send request to backend API.'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
