// Semgrep test fixture for mcp-ssrf-audit-g3-typescript.
// G3 = the guard parses the host as an IP literal (net.isIP and friends)
// but the same guard block fetches by name without resolving DNS. A name
// that is not a literal sails past the literal check and resolves to
// whatever the attacker points it at.
// The finding lands on the isIP-family call.

import net from "node:net";

// Positive: literal check, then fetch the unresolved name.
async function fetchIfPublic(url: string): Promise<Response> {
  const u = new URL(url);
  const hostname = u.hostname;
  // ruleid: mcp-ssrf-audit-g3-typescript
  if (net.isIP(hostname) !== 0 && isPrivateRange(hostname)) {
    throw new Error("private address");
  }
  return fetch(u.toString());
}

// Positive: the isIP gate decides whether to check ranges at all; a
// non-literal host goes straight to the sink.
async function guardedGet(url: string): Promise<Response> {
  const parsed = new URL(url);
  // ruleid: mcp-ssrf-audit-g3-typescript
  const isLiteral = net.isIP(parsed.hostname) !== 0;
  if (isLiteral && isPrivateRange(parsed.hostname)) {
    throw new Error("blocked");
  }
  return fetch(parsed.toString(), { redirect: "follow" });
}

// Negative: DNS resolution in the same block means the isIP call is
// classifying resolved output, which is not the G3 shape.
async function resolveThenCheck(url: string): Promise<Response> {
  const u = new URL(url);
  const hostname = u.hostname;
  // ok: mcp-ssrf-audit-g3-typescript
  const literal = net.isIP(hostname);
  const addresses = literal
    ? [hostname]
    : (await lookup(hostname, { all: true })).map((a) => a.address);
  if (addresses.some((a) => isPrivateRange(a))) {
    throw new Error("blocked");
  }
  return fetch(u.toString());
}

// Negative: isIP with no outbound request in the block is not this class.
function classify(ip: string): number {
  // ok: mcp-ssrf-audit-g3-typescript
  return net.isIP(ip);
}

// Negative: a sink with no literal check in the block is G0/G6 territory,
// not G3.
async function plain(url: string): Promise<Response> {
  return fetch(url);
}
