// Semgrep test fixture for rules/checklist/typescript-checklist.yaml.
// Annotations are the executable contract (semgrep test). Checklist rules
// enumerate manual-review candidates; every hit is a candidate, not a
// verdict.

declare const server: any;
declare const dns: any;
declare const fetch: any;
declare const res: any;

// ruleid: mcp-ssrf-audit-checklist-g9-typescript
server.registerTool("fetch", async ({ url, host }: any) => {
  // ruleid: mcp-ssrf-audit-checklist-g7-typescript
  const addr = await dns.lookup(host);
  // ruleid: mcp-ssrf-audit-checklist-g10-typescript
  return fetch(url, { headers: { Authorization: "Bearer t" } });
});

// ruleid: mcp-ssrf-audit-checklist-g9-typescript
server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  // ruleid: mcp-ssrf-audit-checklist-g7-typescript
  const infos = await resolver.resolve4(request.params.host);
  // ruleid: mcp-ssrf-audit-checklist-g10-typescript
  res.setHeader("Authorization", `Bearer ${request.params.token}`);
  return null;
});

function noSurface(x: any): number {
  // ok: mcp-ssrf-audit-checklist-g7-typescript
  // ok: mcp-ssrf-audit-checklist-g9-typescript
  // ok: mcp-ssrf-audit-checklist-g10-typescript
  return x.length;
}
