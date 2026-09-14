// Semgrep test fixture for mcp-ssrf-audit-g4-typescript (plain JS variant).

const net = require("node:net");

// Positive: URL.hostname straight into net.isIP, no bracket handling.
function isSafeUrl(input) {
  const u = new URL(input);
  const hostname = u.hostname;
  // ruleid: mcp-ssrf-audit-g4-typescript
  if (net.isIP(hostname) === 4) {
    return false;
  }
  return true;
}

// Positive: host-named parameter feeding a bare isIP call.
function isPrivateOrLocalIp(ip) {
  // ruleid: mcp-ssrf-audit-g4-typescript
  const version = net.isIP(ip);
  return version !== 0;
}

// Negative: bracket strip via startsWith/endsWith + slice before isIP.
function isPrivateOrLocalHostnameFixed(hostname) {
  const raw = hostname.trim().toLowerCase();
  const host = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;
  // ok: mcp-ssrf-audit-g4-typescript
  return net.isIP(host) === 0;
}

// Negative: bracket strip via replace before isIP.
function check(input) {
  const host = new URL(input).hostname.replace(/^\[|\]$/g, "");
  // ok: mcp-ssrf-audit-g4-typescript
  return net.isIP(host);
}
