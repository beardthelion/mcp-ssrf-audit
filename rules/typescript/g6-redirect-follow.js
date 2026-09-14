// Semgrep test fixture for mcp-ssrf-audit-g6-typescript (plain JS variant).

const server = {};

// Positive: explicit redirect follow.
server.registerTool("fetch_url", {}, async (args) => {
  // ruleid: mcp-ssrf-audit-g6-typescript
  return fetch(args.url, { redirect: "follow" });
});

// Positive: default follow after a non-guard check.
server.tool("grab", {}, async ({ url }) => {
  validate(url);
  // ruleid: mcp-ssrf-audit-g6-typescript
  return fetch(url);
});

// Positive: got follows redirects by default.
server.tool("g", {}, async ({ url }) => {
  // ruleid: mcp-ssrf-audit-g6-typescript
  return got(url);
});

// Negative: redirects disabled.
server.tool("manual", {}, async ({ url }) => {
  // ok: mcp-ssrf-audit-g6-typescript
  return fetch(url, { redirect: "manual" });
});

server.tool("axok", {}, async ({ url }) => {
  // ok: mcp-ssrf-audit-g6-typescript
  return axios.get(url, { maxRedirects: 0 });
});

// Negative: per-hop redirect handler.
server.tool("g2", {}, async ({ url }) => {
  // ok: mcp-ssrf-audit-g6-typescript
  return got(url, { beforeRedirect: (opts) => validate(opts.url) });
});
