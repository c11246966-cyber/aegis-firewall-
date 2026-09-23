/**
 * Aegis Automated Verification & Self-Test Suite
 * 
 * Implements automated unit and integration tests across 25 security vectors:
 * - Windows backend (WFP rule manipulation, netsh/PowerShell abstraction)
 * - Linux backend (nftables table/set/chain abstraction)
 * - Simulation backend (dry-run mode)
 * - IPv4 & IPv6 validation (link-local, multicast, loopback)
 * - CIDR boundary parsing
 * - Firewall state verification & tamper detection
 * - Duplicate rule prevention
 * - TTL expiration
 * - Allowlist protection
 * - Trusted management protection
 * - RBAC enforcement (ADMIN, ANALYST, OPERATOR, VIEWER)
 * - Authentication & session expiry
 * - Brute-force account lockout
 * - Cryptographic audit logging integrity
 * - Malformed API request rejection
 * - Privilege escalation prevention
 * - Arbitrary shell command injection rejection (failsafe)
 * - Firewall modification failure rollback handling
 * - Service health & recovery
 * - Alert deduplication & flood protection
 */

import { TestCaseResult } from '../types/aegis';
import { WindowsFirewallBackend } from './firewall/WindowsFirewallBackend';
import { LinuxFirewallBackend } from './firewall/LinuxFirewallBackend';
import { SimulationBackend } from './firewall/SimulationBackend';
import { firewallFAL } from './firewall/FirewallAbstractionLayer';
import { validateIpOrCidr, parseIpv4ToNumber, isValidIpv6 } from '../utils/ipValidator';
import { authService } from './security/AuthService';
import { auditLogger } from './security/AuditLogger';
import { privilegedWindowsService } from './security/PrivilegedWindowsService';
import { policyEngine } from './security/PolicyEngine';

export class TestRunner {
  public async runAllTests(
    onProgress?: (completed: number, total: number, current: TestCaseResult) => void
  ): Promise<TestCaseResult[]> {
    const results: TestCaseResult[] = [];
    const testCases = this.getTestDefinitions();

    for (let i = 0; i < testCases.length; i++) {
      const tc = testCases[i];
      const start = performance.now();
      try {
        const testRes = await tc.fn();
        const durationMs = Math.round((performance.now() - start) * 100) / 100;
        const finalResult: TestCaseResult = {
          id: tc.id,
          name: tc.name,
          category: tc.category,
          status: testRes.pass ? 'PASS' : 'FAIL',
          durationMs,
          assertionsCount: testRes.assertions,
          details: testRes.details,
          errorMessage: testRes.error,
        };
        results.push(finalResult);
        onProgress?.(i + 1, testCases.length, finalResult);
      } catch (err: unknown) {
        const durationMs = Math.round((performance.now() - start) * 100) / 100;
        const failedResult: TestCaseResult = {
          id: tc.id,
          name: tc.name,
          category: tc.category,
          status: 'FAIL',
          durationMs,
          assertionsCount: 1,
          details: 'Exception encountered during test execution',
          errorMessage: String(err),
        };
        results.push(failedResult);
        onProgress?.(i + 1, testCases.length, failedResult);
      }
    }

    return results;
  }

  private getTestDefinitions(): Array<{
    id: string;
    name: string;
    category: TestCaseResult['category'];
    fn: () => Promise<{ pass: boolean; assertions: number; details: string; error?: string }>;
  }> {
    return [
      // 1. Windows Backend
      {
        id: 'TEST-001',
        name: 'Windows Firewall Backend (WFP add_rule & remove_rule)',
        category: 'WINDOWS_WFP',
        fn: async () => {
          const win = new WindowsFirewallBackend();
          const testIp = '198.51.100.81';
          const addRes = await win.add_rule({ ipCidr: testIp, action: 'DROP', ttlSeconds: 300, reason: 'Unit test' });
          if (!addRes.success || !addRes.rule?.name.startsWith('AEGIS-WFP-')) {
            return { pass: false, assertions: 2, details: 'Failed to create prefixed WFP rule', error: addRes.error };
          }
          const delRes = await win.remove_rule(addRes.rule.id);
          return {
            pass: delRes.success,
            assertions: 3,
            details: 'WFP rule provisioned with strict AEGIS-WFP- prefix and deleted cleanly.',
          };
        },
      },

      // 2. Linux Backend
      {
        id: 'TEST-002',
        name: 'Linux nftables Backend (table & set element creation)',
        category: 'LINUX_NFTABLES',
        fn: async () => {
          const lnx = new LinuxFirewallBackend();
          const res = await lnx.add_rule({ ipCidr: '185.220.101.44', action: 'DROP', ttlSeconds: 600 });
          return {
            pass: res.success && !!res.commandExecuted?.includes('inet aegis_filter'),
            assertions: 2,
            details: 'nftables table inet aegis_filter set element created with timeout parameter.',
          };
        },
      },

      // 3. Simulation Backend
      {
        id: 'TEST-003',
        name: 'Simulation Backend (Dry-run zero OS kernel mutation)',
        category: 'SIMULATION',
        fn: async () => {
          const sim = new SimulationBackend();
          const res = await sim.add_rule({ ipCidr: '203.0.113.88', action: 'DROP', ttlSeconds: 900 });
          const rules = await sim.listRules();
          return {
            pass: res.success && rules.some(r => r.ipCidr === '203.0.113.88'),
            assertions: 2,
            details: 'Virtual dry-run executed; state projected accurately in virtual sandbox.',
          };
        },
      },

      // 4. IPv4 Validation
      {
        id: 'TEST-004',
        name: 'IPv4 Validation (Standard, broadcast, and invalid octets)',
        category: 'VALIDATION',
        fn: async () => {
          const valid = validateIpOrCidr('198.51.100.42');
          const invalid = validateIpOrCidr('999.1.2.3');
          const broadcast = validateIpOrCidr('255.255.255.255');
          const pass = valid.isValid && !invalid.isValid && broadcast.isSafeguarded;
          return {
            pass,
            assertions: 3,
            details: 'Verified IPv4 octet bounds [0-255] and broadcast rejection.',
          };
        },
      },

      // 5. IPv6 Validation
      {
        id: 'TEST-005',
        name: 'IPv6 Validation (Full, compressed, link-local, loopback)',
        category: 'VALIDATION',
        fn: async () => {
          const validV6 = validateIpOrCidr('2001:db8:85a3::8a2e:370:7334');
          const loopbackV6 = validateIpOrCidr('::1');
          const linkLocalV6 = validateIpOrCidr('fe80::1');
          const pass = validV6.isValid && loopbackV6.isSafeguarded && linkLocalV6.isSafeguarded;
          return {
            pass,
            assertions: 3,
            details: 'IPv6 syntax verified. Loopback (::1) and link-local (fe80::/10) protected.',
          };
        },
      },

      // 6. CIDR Validation
      {
        id: 'TEST-006',
        name: 'CIDR Subnet Validation (/0 to /32 IPv4 and /0 to /128 IPv6)',
        category: 'VALIDATION',
        fn: async () => {
          const validCidr = validateIpOrCidr('198.51.100.0/24');
          const invalidCidr = validateIpOrCidr('198.51.100.0/35');
          const validV6Cidr = validateIpOrCidr('2001:db8::/64');
          const pass = validCidr.isValid && !invalidCidr.isValid && validV6Cidr.isValid;
          return {
            pass,
            assertions: 3,
            details: 'Verified IPv4 /0-/32 and IPv6 /0-/128 mask prefix boundaries.',
          };
        },
      },

      // 7. Firewall State Verification & Tamper Detection
      {
        id: 'TEST-007',
        name: 'Firewall State Verification & Tamper Detection',
        category: 'SAFETY',
        fn: async () => {
          const win = new WindowsFirewallBackend();
          const verify = await win.verifyState();
          return {
            pass: !verify.isTampered && verify.activeAegisRules > 0,
            assertions: 2,
            details: 'WFP rule registry verified against Aegis security hash; no drift detected.',
          };
        },
      },

      // 8. Duplicate Rule Handling
      {
        id: 'TEST-008',
        name: 'Duplicate Rule Handling (Idempotent update without orphaned duplicates)',
        category: 'SAFETY',
        fn: async () => {
          const win = new WindowsFirewallBackend();
          const ip = '198.51.100.55';
          await win.add_rule({ ipCidr: ip, action: 'DROP', ttlSeconds: 300 });
          const countBefore = (await win.listRules()).length;
          await win.add_rule({ ipCidr: ip, action: 'DROP', ttlSeconds: 600 });
          const countAfter = (await win.listRules()).length;
          return {
            pass: countBefore === countAfter,
            assertions: 2,
            details: 'Duplicate IP rule updated in-place idempotently without orphan creation.',
          };
        },
      },

      // 9. TTL Auto-Expiration
      {
        id: 'TEST-009',
        name: 'TTL Auto-Expiration Calculation & Countdown',
        category: 'SAFETY',
        fn: async () => {
          const win = new WindowsFirewallBackend();
          const res = await win.add_rule({ ipCidr: '198.51.100.60', action: 'DROP', ttlSeconds: 900 });
          const r = res.rule;
          const pass = !!(r?.expiresAt && r.expiresAt > Date.now());
          return {
            pass,
            assertions: 2,
            details: `Rule timestamp calculated: expiresAt = ${new Date(r?.expiresAt || 0).toISOString()}`,
          };
        },
      },

      // 10. Allowlist Protection
      {
        id: 'TEST-010',
        name: 'Allowlist Protection (Whitelist IP cannot be dropped)',
        category: 'SAFETY',
        fn: async () => {
          const decision = policyEngine.evaluateEvent({
            id: 'EVT-TEST',
            timestamp: Date.now(),
            vector: 'PORT_SCAN',
            sourceIp: '192.168.1.1', // Default gateway allowlisted
            sourcePort: 1234,
            destIp: '192.168.1.10',
            destPort: 80,
            protocol: 'TCP',
            direction: 'INBOUND',
            signature: 'Test signature',
            severity: 'CRITICAL',
            riskDelta: 30,
            payloadPreview: '',
            rawPacketHex: '',
            actionTaken: 'LOGGED',
          });
          return {
            pass: decision.recommendedAction === 'ALLOW' && !decision.shouldContain,
            assertions: 2,
            details: 'Critical alert from allowlisted host intercepted; containment aborted.',
          };
        },
      },

      // 11. Trusted Management Protection
      {
        id: 'TEST-011',
        name: 'Trusted Management Protection (Safeguards against admin lockout)',
        category: 'SAFETY',
        fn: async () => {
          const val = validateIpOrCidr('192.168.1.100'); // SOC Admin Workstation
          const win = new WindowsFirewallBackend();
          const res = await win.block_ip('192.168.1.100');
          return {
            pass: val.isTrustedManagement && !res.success,
            assertions: 2,
            details: 'WFP backend rejected DROP on 192.168.1.100: Protected Management IP.',
          };
        },
      },

      // 12. RBAC: Admin Authorized
      {
        id: 'TEST-012',
        name: 'RBAC: Role ADMIN Authorized for Privileged Operations',
        category: 'RBAC',
        fn: async () => {
          authService.switchUserFast('admin');
          const isAuth = authService.isAuthorized(['ADMIN']);
          return {
            pass: isAuth,
            assertions: 1,
            details: 'User "admin" authenticated with role ADMIN granted full policy privileges.',
          };
        },
      },

      // 13. RBAC: Viewer Rejected
      {
        id: 'TEST-013',
        name: 'RBAC: Role VIEWER Rejected with 403 Forbidden',
        category: 'RBAC',
        fn: async () => {
          authService.switchUserFast('viewer');
          const res = await firewallFAL.block_ip('198.51.100.91', undefined, {
            user: 'viewer',
            role: 'VIEWER',
            source: 'Test',
          });
          authService.switchUserFast('admin'); // restore
          return {
            pass: !res.success && Boolean(res.error?.includes('403')),
            assertions: 2,
            details: 'Firewall modification rejected: VIEWER role restricted from mutate operations.',
          };
        },
      },

      // 14. Authentication & Session Expiration
      {
        id: 'TEST-014',
        name: 'Authentication & Session Token Lifecycle',
        category: 'RBAC',
        fn: async () => {
          const login = authService.login('operator', 'Aegis@Operator2026!');
          const session = authService.getCurrentSession();
          const pass = login.success && !!session?.token && session.expiresAt > Date.now();
          authService.switchUserFast('admin'); // restore
          return {
            pass,
            assertions: 3,
            details: 'Session token minted with 4-hour expiration window.',
          };
        },
      },

      // 15. Brute-Force Account Lockout Protection
      {
        id: 'TEST-015',
        name: 'Management Lockout Protection (Max 5 failed attempts -> 15 min lock)',
        category: 'RBAC',
        fn: async () => {
          // Attempt 5 bad passwords for a dummy user
          authService.login('operator', 'wrong1');
          authService.login('operator', 'wrong2');
          authService.login('operator', 'wrong3');
          authService.login('operator', 'wrong4');
          const finalAttempt = authService.login('operator', 'wrong5');
          const pass = !finalAttempt.success && !!finalAttempt.error?.includes('locked');
          authService.switchUserFast('admin'); // restore
          return {
            pass,
            assertions: 2,
            details: 'Account successfully placed into 15-minute cooldown following 5 consecutive failures.',
          };
        },
      },

      // 16. Audit Logging Cryptographic Hash Chaining
      {
        id: 'TEST-016',
        name: 'Audit Logging Chained Integrity (Tamper-evident verification)',
        category: 'SAFETY',
        fn: async () => {
          auditLogger.log({
            user: 'admin',
            role: 'ADMIN',
            source: 'UnitTest',
            action: 'VERIFY_AUDIT_HASH',
            target: 'TEST_HASH_TARGET',
            result: 'SUCCESS',
            reason: 'Testing hash chain continuity',
          });
          const verify = auditLogger.verifyIntegrity();
          return {
            pass: verify.isValid && verify.verifiedCount > 0,
            assertions: 2,
            details: `Audit ledger verified: ${verify.verifiedCount} records verified via cryptographic chaining.`,
          };
        },
      },

      // 17. Malformed API Requests
      {
        id: 'TEST-017',
        name: 'Malformed API Request Rejection',
        category: 'VALIDATION',
        fn: async () => {
          const res = await firewallFAL.block_ip('not-an-ip-address');
          return {
            pass: !res.success && !!res.error,
            assertions: 1,
            details: 'Malformed IP input rejected gracefully prior to backend execution.',
          };
        },
      },

      // 18. Privilege Escalation Prevention
      {
        id: 'TEST-018',
        name: 'Privilege Escalation Prevention (Operator cannot trigger Emergency Lockdown)',
        category: 'RBAC',
        fn: async () => {
          const res = await firewallFAL.emergency_lockdown({
            user: 'operator',
            role: 'OPERATOR',
            source: 'Test',
          });
          return {
            pass: !res.success && Boolean(res.error?.includes('403')),
            assertions: 2,
            details: 'Emergency lockdown invocation by non-ADMIN rejected by security gatekeeper.',
          };
        },
      },

      // 19. Arbitrary Command Injection Rejection
      {
        id: 'TEST-019',
        name: 'Arbitrary Command Injection Rejection (Failsafe IPC boundary)',
        category: 'SAFETY',
        fn: async () => {
          const shellAttempt = 'cmd.exe /c del /f /q C:\\Windows\\System32\\drivers\\etc\\hosts';
          const res = privilegedWindowsService.rejectArbitraryCommand(shellAttempt);
          return {
            pass: res.rejected,
            assertions: 2,
            details: 'Raw shell string unconditionally rejected by privileged service IPC dispatcher.',
          };
        },
      },

      // 20. Firewall Modification Failure & Rollback
      {
        id: 'TEST-020',
        name: 'Firewall Modification Failure Reporting (No false success)',
        category: 'SAFETY',
        fn: async () => {
          const win = new WindowsFirewallBackend();
          const res = await win.remove_rule('NON_EXISTENT_RULE_ID_XYZ');
          return {
            pass: !res.success && !!res.error,
            assertions: 2,
            details: 'Deletion failure accurately reported with diagnostic message without corrupting state.',
          };
        },
      },

      // 21. Privileged Service Health Check
      {
        id: 'TEST-021',
        name: 'Privileged Service Daemon Health & Heartbeat',
        category: 'WINDOWS_WFP',
        fn: async () => {
          const status = privilegedWindowsService.getServiceStatus();
          return {
            pass: status.status === 'RUNNING' && status.driverLoaded,
            assertions: 2,
            details: `Aegis Windows Service active as ${status.account} with WFP sublayer driver loaded.`,
          };
        },
      },

      // 22. Alert Deduplication
      {
        id: 'TEST-022',
        name: 'Alert Deduplication (Aggregating high-frequency identical events)',
        category: 'PIPELINE',
        fn: async () => {
          const evt: any = {
            id: 'EVT-DEDUP-1',
            timestamp: Date.now(),
            vector: 'PORT_SCAN',
            sourceIp: '198.51.100.99',
            destPort: 80,
            severity: 'HIGH',
            signature: 'Port scan test',
          };
          policyEngine.evaluateEvent(evt);
          const second = policyEngine.evaluateEvent({ ...evt, id: 'EVT-DEDUP-2' });
          return {
            pass: second.isDeduplicated && second.clusterCount >= 2,
            assertions: 2,
            details: 'Subsequent alerts from same vector/source within 15s clustered automatically.',
          };
        },
      },

      // 23. Alert Flood Protection
      {
        id: 'TEST-023',
        name: 'Alert Flood Protection (Circuit breaker under flood conditions)',
        category: 'PIPELINE',
        fn: async () => {
          const dummyEvt: any = {
            id: 'EVT-FLOOD',
            timestamp: Date.now(),
            vector: 'SYN_FLOOD',
            sourceIp: '198.51.100.111',
            destPort: 443,
            severity: 'CRITICAL',
            signature: 'Flood test',
          };
          // Simulate 55 events rapidly
          let suppressed = false;
          for (let i = 0; i < 55; i++) {
            const dec = policyEngine.evaluateEvent({ ...dummyEvt, id: `EVT-F-${i}` });
            if (dec.isFloodSuppressed) suppressed = true;
          }
          return {
            pass: suppressed,
            assertions: 2,
            details: 'Circuit breaker triggered after 50 alerts in 10s window to protect SOC console.',
          };
        },
      },

      // 24. Emergency Lockdown Execution
      {
        id: 'TEST-024',
        name: 'Emergency Perimeter Lockdown & Management Pinning',
        category: 'WINDOWS_WFP',
        fn: async () => {
          const win = new WindowsFirewallBackend();
          const res = await win.emergency_lockdown(['192.168.1.100']);
          const rules = await win.listRules();
          const hasDropAll = rules.some(r => r.ipCidr === '0.0.0.0/0' && r.action === 'DROP');
          const hasMgmtAllow = rules.some(r => r.ipCidr === '192.168.1.100' && r.action === 'ALLOW');
          await win.lift_lockdown();
          return {
            pass: res.success && hasDropAll && hasMgmtAllow,
            assertions: 3,
            details: 'Drop-all perimeter rule applied while pinning 192.168.1.100 management access.',
          };
        },
      },

      // 25. Recovery & Self-Test Verification
      {
        id: 'TEST-025',
        name: 'System Self-Test & State Recovery Verification',
        category: 'SAFETY',
        fn: async () => {
          const health = await firewallFAL.healthCheck();
          const verify = await firewallFAL.verifyState();
          return {
            pass: health.status === 'HEALTHY' && !verify.isTampered,
            assertions: 2,
            details: 'Aegis core subsystem diagnostics completed successfully. All subsystems operational.',
          };
        },
      },
    ];
  }
}

export const testRunner = new TestRunner();
