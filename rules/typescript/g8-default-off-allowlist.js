// Semgrep test fixture for mcp-ssrf-audit-g8-typescript (plain JS variant).

// Positive: env kill switch and the gate that consumes it.
// ruleid: mcp-ssrf-audit-g8-typescript
const DISABLE_SSRF_GUARD = process.env.MCP_FETCH_DISABLE_SSRF_GUARD === "1";

async function isSafeUrl(input) {
  const u = new URL(input);
  // ruleid: mcp-ssrf-audit-g8-typescript
  if (DISABLE_SSRF_GUARD) {
    return { ok: true, url: u };
  }
  const hostname = u.hostname;
  return net.isIP(hostname) === 0;
}

// Positive: allow-private env override with empty default.
// ruleid: mcp-ssrf-audit-g8-typescript
const ALLOW_PRIVATE = process.env.AUTH_FETCH_ALLOW_PRIVATE ?? "";

// Positive: empty-default allowlist and unanchored suffix check.
// ruleid: mcp-ssrf-audit-g8-typescript
const allowed = opts.allowedDomains || [];

function allowlistOk(input) {
  const h = new URL(input).hostname;
  // ruleid: mcp-ssrf-audit-g8-typescript
  return allowed.some((d) => h.endsWith(d));
}

// Negative: benign env reads and anchored matching.
// ok: mcp-ssrf-audit-g8-typescript
const home = process.env.HOME || "";

function anchored(input, allowedList) {
  const h = new URL(input).hostname;
  // ok: mcp-ssrf-audit-g8-typescript
  return allowedList.some((d) => h === d || h.endsWith("." + d));
}
