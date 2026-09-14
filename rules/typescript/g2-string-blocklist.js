// Semgrep test fixture for mcp-ssrf-audit-g2-typescript (plain JS variant).

const net = require("node:net");

// Positive: exact literal compares on the parsed hostname.
function isPrivateIp(url) {
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;
  // ruleid: mcp-ssrf-audit-g2-typescript
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return true;
  }
  // ruleid: mcp-ssrf-audit-g2-typescript
  return hostname.endsWith(".local");
}

// Positive: blocklist regex test in a host-checking block.
const BLOCKED_HOSTNAMES = /^(localhost|.*\.local|.*\.internal)$/i;
function validateUrl(raw) {
  const parsed = new URL(raw);
  // ruleid: mcp-ssrf-audit-g2-typescript
  return BLOCKED_HOSTNAMES.test(parsed.hostname.toLowerCase());
}

// Negative: blocklist literals next to an IP parse and a resolver are a
// first-stage filter.
async function isSafeUrl(input) {
  const u = new URL(input);
  const hostname = u.hostname;
  // ok: mcp-ssrf-audit-g2-typescript
  if (hostname === "localhost") return false;
  if (net.isIP(hostname) !== 0) return !isPrivateIPv4(hostname);
  const ips = await lookupAll(hostname);
  return ips.length === 0;
}
