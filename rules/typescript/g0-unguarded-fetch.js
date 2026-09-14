// Semgrep test fixture for mcp-ssrf-audit-g0-typescript (plain JS variant;
// the rule declares languages [typescript, javascript]).

const fetch = require("node-fetch");
const axios = require("axios");

const server = {};

// Positive: unguarded fetch inside a plain-JS registerTool handler.
server.registerTool("fetch", {}, async (args) => {
  // ruleid: mcp-ssrf-audit-g0-typescript
  return fetch(args.url);
});

// Positive: axios method sink, unguarded.
server.tool("get", {}, async (args) => {
  // ruleid: mcp-ssrf-audit-g0-typescript
  return axios.post(args.url, {});
});

// Negative: recognized complete-guard wrapper suppresses G0.
server.registerTool("safe", {}, async (args) => {
  const pinned = await resolveAndPin(args.url);
  // ok: mcp-ssrf-audit-g0-typescript
  return fetch(pinned);
});

// Negative: literal URL is not model-controlled.
server.registerTool("literal", {}, async (args) => {
  // ok: mcp-ssrf-audit-g0-typescript
  return fetch("https://example.com/feed");
});
