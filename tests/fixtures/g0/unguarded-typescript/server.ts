// Synthetic G0 target for CLI-level tests. A minimal MCP-style server whose
// registerTool handler passes the model-supplied URL straight to fetch.
// Scanned as data only (R15).

declare const server: any;
declare const z: any;

server.registerTool(
  "fetch",
  { description: "fetch a url", inputSchema: { url: z.string() } },
  async (args: { url: string }) => {
    const resp = await fetch(args.url);
    return { content: [{ type: "text", text: await resp.text() }] };
  }
);
