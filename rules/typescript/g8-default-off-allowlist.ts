// Semgrep test fixture for mcp-ssrf-audit-g8-typescript.
// G8 = the guard is default-off or bypassable: env kill switches,
// allow-everything gates, empty-default allowlists, fail-open emptiness
// checks, and unanchored hostname suffix/prefix/substring checks.
// The finding lands on the weak construct itself.

declare const opts: { allowedDomains?: string[] };

// Positive: the kazuph HEAD kill switch (CVE-2026-80347). The env read
// fires, and so does the early-allow gate.
// ruleid: mcp-ssrf-audit-g8-typescript
const DISABLE_SSRF_GUARD = process.env.MCP_FETCH_DISABLE_SSRF_GUARD === "1";

async function isSafeUrl(input: string) {
  const u = new URL(input);
  // ruleid: mcp-ssrf-audit-g8-typescript
  if (DISABLE_SSRF_GUARD) {
    return { ok: true, url: u };
  }
  const hostname = u.hostname;
  const ips = await lookupAll(hostname);
  return ips.every((a) => !isPrivateRange(a.address));
}

// Positive: the auth-fetch allow-private bypass (CVE-2026-49857).
// ruleid: mcp-ssrf-audit-g8-typescript
const ALLOW_PRIVATE = (process.env.AUTH_FETCH_ALLOW_PRIVATE ?? "").toLowerCase();

function assertSafeUrl(rawUrl: string): URL {
  const parsed = new URL(rawUrl);
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  // ruleid: mcp-ssrf-audit-g8-typescript
  if (allowAllPrivate()) {
    return parsed;
  }
  if (net.isIP(host) !== 0) return parsed;
  return parsed;
}

// Positive: empty-default allowlist reads.
// ruleid: mcp-ssrf-audit-g8-typescript
const rawHosts = process.env.AUTH_FETCH_ALLOW_HOSTS ?? "";
// ruleid: mcp-ssrf-audit-g8-typescript
const domains = opts.allowedDomains ?? [];

// Positive: fail-open emptiness gate on an allowlist.
function allowlistGate(hostname: string, allowedHosts: string[]): boolean {
  // ruleid: mcp-ssrf-audit-g8-typescript
  if (allowedHosts.length === 0) {
    return true;
  }
  return allowedHosts.includes(hostname);
}

// Positive: unanchored suffix allowlist check on the parsed hostname.
// "example.com" would also match "notexample.com" and "example.com.evil".
function allowlistOk(input: string, allowed: string[]): boolean {
  const u = new URL(input);
  const h = u.hostname;
  // ruleid: mcp-ssrf-audit-g8-typescript
  if (allowed.some((d) => h.endsWith(d))) return true;
  // ruleid: mcp-ssrf-audit-g8-typescript
  return allowed.some((d) => h.startsWith(d));
}

// Intentionally not flagged: a substring .includes on a host value is
// lexically identical to collection.includes exact membership, so the rule
// accepts this miss rather than firing on every array membership test.
function hostAllowed(host: string, allowed: string[]): boolean {
  // ok: mcp-ssrf-audit-g8-typescript
  return allowed.some((d) => host.includes(d));
}

// Negative: benign environment reads are not guard configuration.
const TIMEOUT_MS = Number(process.env.MCP_FETCH_TIMEOUT_MS || 12000);
// ok: mcp-ssrf-audit-g8-typescript
const homeDir = process.env.HOME || "";
// ok: mcp-ssrf-audit-g8-typescript
const disableServer = process.env.MCP_FETCH_DISABLE_SERVER === "1";

// Negative: anchored domain matching uses a dot boundary or exact equality.
function anchoredAllowlist(input: string, allowed: string[]): boolean {
  const u = new URL(input);
  const h = u.hostname;
  // ok: mcp-ssrf-audit-g8-typescript
  return allowed.some((d) => h === d || h.endsWith("." + d));
}

// Negative: a literal suffix blocklist is the G2 shape, not G8.
function literalBlocklist(input: string): boolean {
  const h = new URL(input).hostname;
  // ok: mcp-ssrf-audit-g8-typescript
  return h.endsWith(".local");
}

// Negative: a suffix check inside a block that also parses IP literals and
// resolves DNS is a first-stage filter, classified elsewhere.
async function layeredGuard(input: string): Promise<boolean> {
  const u = new URL(input);
  const lower = u.hostname.toLowerCase();
  // ok: mcp-ssrf-audit-g8-typescript
  if (lower.endsWith(tldSuffix)) return false;
  if (net.isIP(lower) !== 0) return !isPrivateRange(lower);
  const ips = await lookupAll(lower);
  return ips.length > 0;
}

// Negative: non-empty default on an allowlist.
const FALLBACK = ["example.com"];
// ok: mcp-ssrf-audit-g8-typescript
const allowedHosts = opts.allowedDomains ?? FALLBACK;

declare function lookupAll(h: string): Promise<{ address: string }[]>;
declare function isPrivateRange(a: string): boolean;
declare function allowAllPrivate(): boolean;
declare const net: any;
declare const tldSuffix: string;
