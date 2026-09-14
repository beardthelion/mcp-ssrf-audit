// Semgrep test fixture for mcp-ssrf-audit-g4-typescript.
// G4 = a URL hostname reaches an IP-literal parser (net.isIP, isIPv4,
// isIPv6, or a bare isIP import) without bracket stripping. WHATWG
// URL.hostname keeps brackets on IPv6 literals, so isIP("[::1]") === 0 and
// the private-range branch is skipped.
// The finding lands on the isIP-family call.

import net from "node:net";
import { isIP } from "node:net";

declare function resolveAllIps(h: string): Promise<{ address: string }[]>;
declare function isPrivateIPv4(ip: string): boolean;
declare function isPrivateIpv4(ip: string): boolean;
declare function isPrivateIpv6(ip: string): boolean;

// Positive: the kazuph/mcp-fetch shape (CVE-2026-80347). URL.hostname is
// passed to net.isIP with no bracket handling anywhere in the block.
async function isSafeUrl(input: string): Promise<boolean> {
  const u = new URL(input);
  const hostname = u.hostname;
  // ruleid: mcp-ssrf-audit-g4-typescript
  const isIp = net.isIP(hostname) !== 0;
  if (isIp) {
    // ruleid: mcp-ssrf-audit-g4-typescript
    if (net.isIP(hostname) === 4 && isPrivateIPv4(hostname)) {
      return false;
    }
    // ruleid: mcp-ssrf-audit-g4-typescript
    if (net.isIP(hostname) === 6) {
      return false;
    }
  }
  const ips = await resolveAllIps(hostname);
  return ips.every((r) => !isPrivateIPv4(r.address));
}

// Positive: the open-websearch shape (CVE-2026-42260). A host-named
// parameter feeds a bare isIP import; the caller passes the unstripped
// hostname.
function isPrivateOrLocalIp(ip: string): boolean {
  // ruleid: mcp-ssrf-audit-g4-typescript
  const version = isIP(ip);
  if (version === 4) {
    return isPrivateIpv4(ip);
  }
  if (version === 6) {
    return isPrivateIpv6(ip);
  }
  return false;
}

// Positive: isIP inside an if condition on u.hostname.
function check(input: string): boolean {
  const u = new URL(input);
  // ruleid: mcp-ssrf-audit-g4-typescript
  if (net.isIP(u.hostname) === 0) {
    return true;
  }
  return false;
}

// Positive: host-named arrow parameter feeding isIPv6.
const looksPrivate = (ip: string): boolean =>
  // ruleid: mcp-ssrf-audit-g4-typescript
  net.isIPv6(ip) && ip.startsWith("fe80:");

// Negative: open-websearch PATCHED shape. The host is bracket-stripped
// before isIP, so no finding.
function isPrivateOrLocalHostnameFixed(hostname: string): boolean {
  const raw = hostname.trim().toLowerCase();
  const host = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;
  // ok: mcp-ssrf-audit-g4-typescript
  if (isIP(host) === 0) {
    return false;
  }
  return true;
}

// Negative: auth-fetch shape. regex strip of brackets before net.isIP.
function assertSafeUrl(rawUrl: string): URL {
  const parsed = new URL(rawUrl);
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  // ok: mcp-ssrf-audit-g4-typescript
  const addresses = net.isIP(host) ? [host] : [];
  return parsed;
}

// Negative: a v4/v6 dispatch pair in the same block classifies
// already-resolved addresses, not a raw hostname.
function isPrivateOrLinkLocal(ip: string): boolean {
  // ok: mcp-ssrf-audit-g4-typescript
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  // ok: mcp-ssrf-audit-g4-typescript
  if (net.isIPv6(ip)) return isPrivateIpv6(ip);
  return true;
}

// Negative for G4 (this is the G5 site): IPv4-mapped tail extraction marks
// a normalization pipeline; the ::ffff handling suppresses G4.
function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    // ok: mcp-ssrf-audit-g4-typescript
    if (net.isIPv4(v4)) {
      return isPrivateIPv4(v4);
    }
  }
  return false;
}

// Negative: isIP on a parameter that is not host-flavored and no .hostname
// in the block is outside this guard shape.
function looksLikeIp(version: number, data: string): boolean {
  // ok: mcp-ssrf-audit-g4-typescript
  return net.isIP(data) === version;
}
