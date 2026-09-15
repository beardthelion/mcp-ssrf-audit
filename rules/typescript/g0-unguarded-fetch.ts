// Semgrep test fixture for mcp-ssrf-audit-g0-typescript.
// Annotations are the executable contract (semgrep test).
// G0 means "no recognized complete guard on the intra-function taint path".
// Weak and unrecognized guards do NOT suppress this rule; classify.py resolves
// the final class at the site per the layered resolution in
// docs/source-sink-matrix.md. Those lines are still positive annotations.

import axios from "axios";
import got from "got";
import fetch from "node-fetch";

// Illustrative MCP server object; the rule keys on the registration method
// name (tool, registerTool, setRequestHandler), not the import.
declare const server: any;
declare const z: any;

// Positive: bare unguarded fetch inside registerTool (AE2 shape).
server.registerTool(
  "fetch",
  { description: "fetch a url", inputSchema: { url: z.string() } },
  async (args: { url: string }) => {
    // ruleid: mcp-ssrf-audit-g0-typescript
    const resp = await fetch(args.url);
    return { content: [{ type: "text", text: await resp.text() }] };
  }
);

// Positive: scheme-only guard still fires (incumbent regression class; the
// weak shape resolves to G1 in classify.py, not silence).
server.tool("read", { url: z.string() }, async (args: { url: string }) => {
  const parsed = new URL(args.url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("bad scheme");
  }
  // ruleid: mcp-ssrf-audit-g0-typescript
  return axios.get(args.url);
});

// Positive: destructured handler argument reaching got.
server.registerTool(
  "grab",
  {},
  async ({ url }: { url: string }) => {
    // ruleid: mcp-ssrf-audit-g0-typescript
    return got(url);
  }
);

// Positive: setRequestHandler (CallToolRequestSchema) source shape.
server.setRequestHandler("CallToolRequestSchema", async (request: any) => {
  const url = request.params.arguments.url;
  // ruleid: mcp-ssrf-audit-g0-typescript
  return fetch(url);
});

// Positive: expression-bodied arrow handler (no braces).
server.registerTool("expr", {}, async (args: { url: string }) =>
  // ruleid: mcp-ssrf-audit-g0-typescript
  fetch(args.url)
);

// Positive: unrecognized helper guard. Not in the complete-guard vocabulary,
// so G0 still fires and classify.py marks the site unrecognized.
server.registerTool("checked", {}, async (args: { url: string }) => {
  if (!checkUrl(args.url)) {
    throw new Error("blocked");
  }
  // ruleid: mcp-ssrf-audit-g0-typescript
  return fetch(args.url);
});

// Negative: recognized complete-guard call (resolve-all + range check +
// pinned connect, in the documented vocabulary) sanitizes the value.
server.registerTool("safe", {}, async (args: { url: string }) => {
  const checked = await resolveAndPin(args.url);
  // ok: mcp-ssrf-audit-g0-typescript
  return fetch(checked);
});

// Negative: recognized complete-guard check-and-throw on a local derived
// from the tainted argument (by-side-effect sanitizer).
server.registerTool("safe2", {}, async (args: { url: string }) => {
  const target = args.url;
  assertPublicUrl(target);
  // ok: mcp-ssrf-audit-g0-typescript
  return fetch(target);
});

// Known ceiling: a check-and-throw validator applied directly to the tainted
// parameter does not suppress the raw finding. Semgrep CE keeps the parameter
// binding tainted for the whole function body, so by-side-effect cannot clear
// it. The raw finding is expected; the complete-guard site probe resolves the
// site to recognized-complete at classify time.
server.registerTool("safe3", {}, async (args: { url: string }) => {
  assertPublicUrl(args.url);
  // ruleid: mcp-ssrf-audit-g0-typescript
  return fetch(args.url);
});

// Negative: hardcoded literal URL is not model-controlled.
server.registerTool("literal", {}, async (args: { url: string }) => {
  // ok: mcp-ssrf-audit-g0-typescript
  return fetch("https://example.com/feed");
});

// Negative: sink outside any recognized handler source.
async function helperFetch(url: string) {
  // ok: mcp-ssrf-audit-g0-typescript
  return fetch(url);
}

// Dispatch-method source: a class-based tool registry where the CallTool
// switch delegates to tool.execute(args) and the sink lives in the method
// body rather than the registration callback.
class NavigateTool {
  async execute(args: { url: string }, ctx: any) {
    // ruleid: mcp-ssrf-audit-g0-typescript
    return page.goto(args.url);
  }
}

// Object-literal dispatch callback (addTool-style registration).
const registry = {
  name: "fetch",
  execute: async (args: { url: string }) => {
    // ruleid: mcp-ssrf-audit-g0-typescript
    return fetch(args.url);
  },
};

// Negative: same method name but the parameter is not a handler-arg name.
class OtherTool {
  async execute(payload: any) {
    // ok: mcp-ssrf-audit-g0-typescript
    return fetch(payload.url);
  }
}
