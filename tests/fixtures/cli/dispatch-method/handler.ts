// Synthetic fixture: class-based tool registry shape. The CallTool handler
// delegates to tool.execute(args), and the sink lives inside the method in
// a different file. The dispatch-method source marks the execute() body as
// a handler extent, so the sink resolves as a finding rather than landing
// on the coverage "outside recognized handlers" line.
// Scanned as data only; never executed.

declare const server: any;
declare const CallToolRequestSchema: any;
declare const tools: any;

server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const args = request.params.arguments;
  switch (request.params.name) {
    case "playwright_navigate":
      return await tools.navigation.execute(args, {});
    default:
      throw new Error("unknown tool");
  }
});
