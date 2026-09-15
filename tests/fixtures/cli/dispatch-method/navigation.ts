// The dispatch target: a tool class whose execute() takes the model
// arguments. The sink is here, not in the registered callback.
// Scanned as data only; never executed.

declare const page: any;

export class NavigationTool {
  async execute(args: any, context: any) {
    await page.goto(args.url);
    return { content: [{ type: "text", text: `Navigated to ${args.url}` }] };
  }
}
