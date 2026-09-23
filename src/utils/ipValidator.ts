/**
 * Aegis Cross-Platform IP & CIDR Validator
 * Supports IPv4 and IPv6, protects loopback, link-local, RFC 1918,
 * and designated Trusted Management IPs.
 */

export interface IpValidationResult {
  isValid: boolean;
  version: 'IPv4' | 'IPv6' | 'UNKNOWN';
  normalized: string;
  isSafeguarded: boolean;
  isTrustedManagement: boolean;
  safeguardType?: 'LOOPBACK' | 'RFC1918_10' | 'RFC1918_172' | 'RFC1918_192' | 'LINK_LOCAL' | 'BROADCAST' | 'TRUSTED_MANAGEMENT';
  safeguardMessage?: string;
  error?: string;
}

// Configurable trusted management network addresses / administrator workstations
export const DEFAULT_TRUSTED_MANAGEMENT_IPS = [
  '192.168.1.100',      // SOC Primary Admin Workstation
  '192.168.1.101',      // SOC Secondary Admin Workstation
  '10.200.0.1',         // Internal Management VPN Gateway
  '10.200.0.0/24',      // Management Subnet
  'fe80::1',            // IPv6 Local Gateway
];

export function parseIpv4ToNumber(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = parseInt(part, 10);
    if (n < 0 || n > 255) return null;
    num = (num << 8) + n;
  }
  return num >>> 0;
}

export function isValidIpv6(ip: string): boolean {
  // Regex pattern for full & compressed IPv6 notation
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Regex.test(ip.trim());
}

export function validateIpOrCidr(rawInput: string, customTrustedIps?: string[]): IpValidationResult {
  const input = rawInput.trim();
  const trustedList = customTrustedIps || DEFAULT_TRUSTED_MANAGEMENT_IPS;

  if (!input) {
    return {
      isValid: false,
      version: 'UNKNOWN',
      normalized: '',
      isSafeguarded: false,
      isTrustedManagement: false,
      error: 'IP address or CIDR range cannot be empty',
    };
  }

  // Check Trusted Management IPs first
  if (trustedList.includes(input)) {
    return {
      isValid: true,
      version: input.includes(':') ? 'IPv6' : 'IPv4',
      normalized: input,
      isSafeguarded: true,
      isTrustedManagement: true,
      safeguardType: 'TRUSTED_MANAGEMENT',
      safeguardMessage: `CRITICAL SAFEGUARD: ${input} is designated as a Trusted Management IP. Blocking this address would sever SOC management access.`,
    };
  }

  // IPv6 check
  if (input.includes(':')) {
    let ipv6Addr = input;
    let ipv6Mask: number | null = null;

    if (input.includes('/')) {
      const parts = input.split('/');
      if (parts.length !== 2) {
        return { isValid: false, version: 'IPv6', normalized: input, isSafeguarded: false, isTrustedManagement: false, error: 'Malformed IPv6 CIDR format' };
      }
      ipv6Addr = parts[0].trim();
      ipv6Mask = parseInt(parts[1].trim(), 10);
      if (isNaN(ipv6Mask) || ipv6Mask < 0 || ipv6Mask > 128) {
        return { isValid: false, version: 'IPv6', normalized: input, isSafeguarded: false, isTrustedManagement: false, error: 'IPv6 prefix must be between /0 and /128' };
      }
    }

    if (!isValidIpv6(ipv6Addr)) {
      return {
        isValid: false,
        version: 'IPv6',
        normalized: input,
        isSafeguarded: false,
        isTrustedManagement: false,
        error: 'Invalid IPv6 address format',
      };
    }

    const normalized = ipv6Mask !== null ? `${ipv6Addr.toLowerCase()}/${ipv6Mask}` : ipv6Addr.toLowerCase();

    // Check IPv6 Loopback
    if (ipv6Addr === '::1' || ipv6Addr === '::' || ipv6Addr === '0:0:0:0:0:0:0:1') {
      return {
        isValid: true,
        version: 'IPv6',
        normalized,
        isSafeguarded: true,
        isTrustedManagement: false,
        safeguardType: 'LOOPBACK',
        safeguardMessage: 'CRITICAL SAFEGUARD: Blocking IPv6 loopback (::1) is prohibited. Local IPC communication would fail.',
      };
    }

    // Check IPv6 Link-Local
    if (ipv6Addr.toLowerCase().startsWith('fe80:')) {
      return {
        isValid: true,
        version: 'IPv6',
        normalized,
        isSafeguarded: true,
        isTrustedManagement: false,
        safeguardType: 'LINK_LOCAL',
        safeguardMessage: 'LINK-LOCAL SAFEGUARD: fe80::/10 is reserved for local link-layer routing.',
      };
    }

    return {
      isValid: true,
      version: 'IPv6',
      normalized,
      isSafeguarded: false,
      isTrustedManagement: false,
    };
  }

  // IPv4 check
  let ipPart = input;
  let maskPart: number | null = null;

  if (input.includes('/')) {
    const tokens = input.split('/');
    if (tokens.length !== 2) {
      return { isValid: false, version: 'IPv4', normalized: input, isSafeguarded: false, isTrustedManagement: false, error: 'Invalid CIDR format' };
    }
    ipPart = tokens[0].trim();
    const mask = parseInt(tokens[1].trim(), 10);
    if (isNaN(mask) || mask < 0 || mask > 32) {
      return { isValid: false, version: 'IPv4', normalized: input, isSafeguarded: false, isTrustedManagement: false, error: 'IPv4 CIDR prefix must be between /0 and /32' };
    }
    maskPart = mask;
  }

  const ipNum = parseIpv4ToNumber(ipPart);
  if (ipNum === null) {
    return {
      isValid: false,
      version: 'IPv4',
      normalized: input,
      isSafeguarded: false,
      isTrustedManagement: false,
      error: 'Malformed IPv4 address. Expected format: x.x.x.x or x.x.x.x/xx',
    };
  }

  const normalized = maskPart !== null ? `${ipPart}/${maskPart}` : ipPart;

  // Check Loopback: 127.0.0.0/8
  const loopbackStart = parseIpv4ToNumber('127.0.0.0')!;
  const loopbackEnd = parseIpv4ToNumber('127.255.255.255')!;
  if (ipNum >= loopbackStart && ipNum <= loopbackEnd) {
    return {
      isValid: true,
      version: 'IPv4',
      normalized,
      isSafeguarded: true,
      isTrustedManagement: false,
      safeguardType: 'LOOPBACK',
      safeguardMessage: 'CRITICAL SAFEGUARD: 127.0.0.0/8 loopback space is protected. Blocking localhost severs host daemon communication.',
    };
  }

  // RFC 1918: 10.0.0.0/8
  const rfc10Start = parseIpv4ToNumber('10.0.0.0')!;
  const rfc10End = parseIpv4ToNumber('10.255.255.255')!;
  if (ipNum >= rfc10Start && ipNum <= rfc10End) {
    return {
      isValid: true,
      version: 'IPv4',
      normalized,
      isSafeguarded: true,
      isTrustedManagement: false,
      safeguardType: 'RFC1918_10',
      safeguardMessage: 'RFC1918 SAFEGUARD: 10.0.0.0/8 is reserved for private internal subnets.',
    };
  }

  // RFC 1918: 172.16.0.0/12
  const rfc172Start = parseIpv4ToNumber('172.16.0.0')!;
  const rfc172End = parseIpv4ToNumber('172.31.255.255')!;
  if (ipNum >= rfc172Start && ipNum <= rfc172End) {
    return {
      isValid: true,
      version: 'IPv4',
      normalized,
      isSafeguarded: true,
      isTrustedManagement: false,
      safeguardType: 'RFC1918_172',
      safeguardMessage: 'RFC1918 SAFEGUARD: 172.16.0.0/12 is private internal space (Docker/Hyper-V network bridges).',
    };
  }

  // RFC 1918: 192.168.0.0/16
  const rfc192Start = parseIpv4ToNumber('192.168.0.0')!;
  const rfc192End = parseIpv4ToNumber('192.168.255.255')!;
  if (ipNum >= rfc192Start && ipNum <= rfc192End) {
    return {
      isValid: true,
      version: 'IPv4',
      normalized,
      isSafeguarded: true,
      isTrustedManagement: false,
      safeguardType: 'RFC1918_192',
      safeguardMessage: 'RFC1918 SAFEGUARD: 192.168.0.0/16 is private LAN space.',
    };
  }

  // Link-Local: 169.254.0.0/16
  const linkLocalStart = parseIpv4ToNumber('169.254.0.0')!;
  const linkLocalEnd = parseIpv4ToNumber('169.254.255.255')!;
  if (ipNum >= linkLocalStart && ipNum <= linkLocalEnd) {
    return {
      isValid: true,
      version: 'IPv4',
      normalized,
      isSafeguarded: true,
      isTrustedManagement: false,
      safeguardType: 'LINK_LOCAL',
      safeguardMessage: 'LINK-LOCAL SAFEGUARD: 169.254.0.0/16 is APIPA autoconfigured link-local / cloud metadata (169.254.169.254).',
    };
  }

  // Broadcast / Null
  if (ipNum === 0xFFFFFFFF || ipNum === 0) {
    return {
      isValid: false,
      version: 'IPv4',
      normalized,
      isSafeguarded: true,
      isTrustedManagement: false,
      safeguardType: 'BROADCAST',
      safeguardMessage: 'Cannot target 0.0.0.0 or 255.255.255.255 broadcast addresses.',
      error: 'Invalid target broadcast address',
    };
  }

  return {
    isValid: true,
    version: 'IPv4',
    normalized,
    isSafeguarded: false,
    isTrustedManagement: false,
  };
}
