// Semgrep test fixture for mcp-ssrf-audit-g5-typescript.
// G5 = the ::ffff: prefix branch slices the tail and applies a plain IPv4
// check, which only covers dotted-quad mapped strings and misses the
// WHATWG-hex-normalized ::ffff:7f00:1 form plus NAT64/6to4 translations.
// The finding lands on the isIPv4/isIP call on the extracted tail.

import net from "node:net";

declare function isPrivateV4(ip: string): boolean;

// Positive: the auth-fetch-mcp vulnerable shape (CVE-2026-49857).
function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  if (lower.startsWith("fe80:") || lower.startsWith("fc") ||
      lower.startsWith("fd") || lower.startsWith("ff")) return true;
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    // ruleid: mcp-ssrf-audit-g5-typescript
    if (net.isIPv4(v4)) {
      return isPrivateV4(v4);
    }
  }
  return false;
}

// Positive: same shape through net.isIP on the tail.
function mappedIsPrivate(addr: string): boolean {
  const lower = addr.toLowerCase();
  if (lower.startsWith("::ffff:")) {
    const tail = lower.substring("::ffff:".length);
    // ruleid: mcp-ssrf-audit-g5-typescript
    return net.isIP(tail) === 4 && isPrivateV4(tail);
  }
  return false;
}

// Negative: the patched auth-fetch shape. Hex group reconstruction
// (split on ':' plus parseInt base 16) covers the normalized form.
function isPrivateV6Fixed(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    // ok: mcp-ssrf-audit-g5-typescript
    if (net.isIPv4(v4)) return isPrivateV4(v4);
    const groups = v4.split(":");
    if (groups.length === 2 &&
        groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
      const hi = parseInt(groups[0], 16);
      const lo = parseInt(groups[1], 16);
      const mapped = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateV4(mapped);
    }
  }
  return false;
}

// Negative: a normalization path that handles NAT64/6to4 is out of scope
// for G5 even when it also slices a ::ffff: tail.
function normalizeAll(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower.startsWith("64:ff9b::") || lower.startsWith("2002:")) {
    return isPrivateV4(translate(lower));
  }
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    // ok: mcp-ssrf-audit-g5-typescript
    if (net.isIPv4(v4)) return isPrivateV4(v4);
    const groups = v4.split(":");
    const hi = parseInt(groups[0] ?? "0", 16);
    return hi === 0x7f00;
  }
  return false;
}

// Negative: isIPv4 on an ordinary argument with no ::ffff handling in the
// block is not a normalization gap.
function isPrivateOrLinkLocal(ip: string): boolean {
  // ok: mcp-ssrf-audit-g5-typescript
  if (net.isIPv4(ip)) return isPrivateV4(ip);
  // ok: mcp-ssrf-audit-g5-typescript
  if (net.isIPv6(ip)) return isPrivateV6(ip);
  return true;
}
