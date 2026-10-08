// Semgrep test fixture for mcp-ssrf-audit-g2-typescript.
// G2 = the host check is string matching against literals, regexes, or a
// blocklist collection, with no IP parser, range check, or DNS resolution
// in the same guard. The finding lands on the blocklist-check expression.

declare function dnsLookupAll(h: string): Promise<{ address: string }[]>;
declare function is_ip_private(h: string): boolean;

// Positive: exact compares plus a
// dotted-quad regex, nothing else.
export function isPrivateIp(url: string): boolean {
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;
  // ruleid: mcp-ssrf-audit-g2-typescript
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return true;
  }
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  // ruleid: mcp-ssrf-audit-g2-typescript
  const match = hostname.match(ipv4Regex);
  if (match) {
    const a = Number(match[1]);
    if (a === 10) return true;
  }
  return false;
}

// Positive: blocklist regexes tested against the
// lowercased hostname.
const BLOCKED_HOSTNAMES = /^(localhost|.*\.local|.*\.internal)$/i;
const PRIVATE_IPV4 = /^(127\.\d+\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+\.\d+)$/;
function validateUrl(raw: string): boolean {
  const parsed = new URL(raw);
  const hostname = parsed.hostname.toLowerCase();
  // ruleid: mcp-ssrf-audit-g2-typescript
  if (BLOCKED_HOSTNAMES.test(hostname) || PRIVATE_IPV4.test(hostname)) {
    return false;
  }
  return true;
}

// Positive: suffix blocklist and array includes.
function isBlockedHost(input: string): boolean {
  const u = new URL(input);
  const h = u.hostname;
  // ruleid: mcp-ssrf-audit-g2-typescript
  if (h.endsWith(".local") || h.endsWith(".internal")) {
    return true;
  }
  // ruleid: mcp-ssrf-audit-g2-typescript
  return ["localhost", "127.0.0.1", "::1"].includes(h);
}

// Negative: literal compares alongside an IP-literal parse and DNS
// resolution are a first-stage filter, not a string-only blocklist.
async function isSafeUrl(input: string): Promise<boolean> {
  const u = new URL(input);
  const hostname = u.hostname;
  const lower = hostname.toLowerCase();
  // ok: mcp-ssrf-audit-g2-typescript
  if (lower === "localhost" || lower.endsWith(".local")) {
    return false;
  }
  if (net.isIP(hostname) === 4) return false;
  const ips = await dnsLookupAll(hostname);
  return ips.every((r) => r.address !== "127.0.0.1");
}

// Negative: literal compare plus a range-library call in the same block.
function validateHost(input: string): void {
  const parsed = new URL(input);
  const hostname = parsed.hostname;
  const bare = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  // ok: mcp-ssrf-audit-g2-typescript
  if (bare === "localhost" || is_ip_private(bare)) {
    throw new Error("private");
  }
}

// Negative: a literal compare with no URL/hostname context in the block is
// not a host blocklist.
function pickEnv(name: string): string {
  // ok: mcp-ssrf-audit-g2-typescript
  if (name === "localhost") {
    return "dev";
  }
  return name;
}
