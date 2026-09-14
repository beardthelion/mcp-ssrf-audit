// Semgrep test fixture for rules/site-probes/typescript-site-probes.ts.
// Annotations are the executable contract (semgrep test). These rules are
// enumerators: every match is a location mark, never a verdict.

declare const server: any;
declare const fetch: any;
declare const axios: any;
declare const page: any;

// ruleid: mcp-ssrf-audit-probe-handler-source-typescript
server.tool("fetch", async ({ url }: { url: string }) => {
  // ruleid: mcp-ssrf-audit-probe-network-sink-typescript
  return fetch(url);
});

// ruleid: mcp-ssrf-audit-probe-handler-source-typescript
server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const url = request.params.arguments.url;
  // ruleid: mcp-ssrf-audit-probe-complete-guard-typescript
  const checked = await safeFetch(url);
  // ruleid: mcp-ssrf-audit-probe-network-sink-typescript
  return axios.get(checked);
});

// ruleid: mcp-ssrf-audit-probe-handler-source-typescript
server.registerTool("browse", async ({ url }: { url: string }) => {
  // ruleid: mcp-ssrf-audit-probe-intervening-validation-typescript
  validateUrl(url);
  // ruleid: mcp-ssrf-audit-probe-intervening-validation-typescript
  if (!ok) {
    throw new Error("blocked");
  }
  // ruleid: mcp-ssrf-audit-probe-network-sink-typescript
  return page.goto(url);
});

function noSurface(url: string): string {
  // ok: mcp-ssrf-audit-probe-handler-source-typescript
  // ok: mcp-ssrf-audit-probe-network-sink-typescript
  return render(url);
}
