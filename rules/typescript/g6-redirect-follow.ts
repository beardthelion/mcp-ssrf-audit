// Semgrep test fixture for mcp-ssrf-audit-g6-typescript.
// G6 = handler input reaches a request that follows redirects without
// per-hop re-validation. The finding lands on the sink call.

declare const server: any;
declare const page: any;
declare function validate(u: string): void;

// Positive: explicit redirect follow on the tainted URL.
server.registerTool("fetch_url", {}, async (args: { url: string }) => {
  // ruleid: mcp-ssrf-audit-g6-typescript
  const res = await fetch(args.url, { redirect: "follow" });
  return res;
});

// Positive: fetch defaults to redirect:"follow"; an entry-URL check that
// is not a recognized complete guard leaves the hops unvalidated.
server.tool("grab", {}, async ({ url }: { url: string }) => {
  validate(url);
  // ruleid: mcp-ssrf-audit-g6-typescript
  return fetch(url);
});

// Positive: axios with no maxRedirects follows redirects by default.
server.tool("ax", {}, async ({ url }: { url: string }) => {
  // ruleid: mcp-ssrf-audit-g6-typescript
  return axios.get(url);
});

// Positive: axios with maxRedirects greater than zero still follows hops.
server.tool("ax2", {}, async ({ url }: { url: string }) => {
  // ruleid: mcp-ssrf-audit-g6-typescript
  return axios(url, { maxRedirects: 5 });
});

// Positive: options-object axios call.
server.tool("ax3", {}, async ({ url }: { url: string }) => {
  // ruleid: mcp-ssrf-audit-g6-typescript
  return axios({ url, method: "get" });
});

// Positive: browser navigation after pre-request-only validation. The
// browser follows redirects inside goto.
server.tool("browse", {}, async ({ url }: { url: string }) => {
  validate(url);
  // ruleid: mcp-ssrf-audit-g6-typescript
  await page.goto(url);
});

// Negative: redirect disabled.
server.tool("manual", {}, async ({ url }: { url: string }) => {
  // ok: mcp-ssrf-audit-g6-typescript
  return fetch(url, { redirect: "manual" });
});

server.tool("noerr", {}, async ({ url }: { url: string }) => {
  // ok: mcp-ssrf-audit-g6-typescript
  return fetch(url, { redirect: "error" });
});

// Negative: axios with redirects disabled.
server.tool("axok", {}, async ({ url }: { url: string }) => {
  // ok: mcp-ssrf-audit-g6-typescript
  return axios.get(url, { maxRedirects: 0 });
});

// Negative: a redirect policy handler re-checks every hop.
server.tool("axok2", {}, async ({ url }: { url: string }) => {
  // ok: mcp-ssrf-audit-g6-typescript
  return got(url, {
    beforeRedirect: (opts: any) => {
      validate(opts.url);
    },
  });
});

// Negative: recognized complete guard on the path.
server.tool("safe", {}, async ({ url }: { url: string }) => {
  const safe = resolveAndPin(url);
  // ok: mcp-ssrf-audit-g6-typescript
  return fetch(safe);
});

// Negative: literal URL, no taint.
server.tool("fixed", {}, async () => {
  // ok: mcp-ssrf-audit-g6-typescript
  return fetch("https://example.com", { redirect: "follow" });
});

// Negative: not a registered handler, so the param is not a source.
async function plain(url: string) {
  // ok: mcp-ssrf-audit-g6-typescript
  return fetch(url, { redirect: "follow" });
}
