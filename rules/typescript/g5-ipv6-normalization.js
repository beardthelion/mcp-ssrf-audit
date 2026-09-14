// Semgrep test fixture for mcp-ssrf-audit-g5-typescript (plain JS variant).

const net = require("node:net");

// Positive: dotted-tail slice plus a plain IPv4 literal check.
function isPrivateV6(ip) {
  const lower = ip.toLowerCase();
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    // ruleid: mcp-ssrf-audit-g5-typescript
    if (net.isIPv4(v4)) {
      return isPrivateV4(v4);
    }
  }
  return false;
}

// Negative: hexadecimal reconstruction of the mapped tail.
function isPrivateV6Fixed(ip) {
  const lower = ip.toLowerCase();
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    // ok: mcp-ssrf-audit-g5-typescript
    if (net.isIPv4(v4)) return isPrivateV4(v4);
    const groups = v4.split(":");
    if (groups.length === 2) {
      const hi = parseInt(groups[0], 16);
      const lo = parseInt(groups[1], 16);
      return isPrivateV4([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join("."));
    }
  }
  return false;
}
