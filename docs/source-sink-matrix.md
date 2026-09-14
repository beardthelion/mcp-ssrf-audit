# Source/sink matrix

This file is the documented detection boundary for the deterministic rules
under `rules/`. Every rule in the pack cites this file; the source, sink, and
sanitizer lists below are the contract the rules encode. If a rule and this
document disagree, the document is wrong until the rule changes.

The rules run on Semgrep Community Edition in taint mode. A G0 finding means:
a value derived from an MCP handler argument reaches an outbound request call
within one function body, and no recognized complete-guard call intervenes.

## Sources: MCP tool-handler arguments

A source is any parameter of a function that is registered as an MCP entry
point. The registration shape is the signal; the receiver object is free, so
FastMCP, the low-level SDK server, vendored variants, and `this.server`-style
references all match.

### Python (`mcp-ssrf-audit-g0-python` and later `rules/python/*`)

Any parameter of a function decorated with:

- `@<anything>.tool(...)` or bare `@<anything>.tool`
- `@<anything>.call_tool(...)` or bare `@<anything>.call_tool`
- `@<anything>.get_prompt(...)` or bare `@<anything>.get_prompt`
- Bare-name decorators `@tool`, `@call_tool`, `@get_prompt` (no receiver)

Both `def` and `async def` bodies are covered. A tainted `arguments` dict
taints every value extracted from it (`arguments["url"]`,
`arguments.get("url")`), so low-level `call_tool`/`get_prompt` handlers are
covered without enumerating argument names.

### TypeScript and JavaScript (`mcp-ssrf-audit-g0-typescript` and later `rules/typescript/*`)

Any parameter of a callback passed to a registration method named one of:

- `tool`, `registerTool`, `callTool`, `getPrompt`, `setRequestHandler`,
  `prompt`, `resource`

on any receiver (`server.tool(...)`, `this.server.registerTool(...)`, and so
on). Callback shapes covered: async and sync arrow functions with block or
expression bodies, `function` expressions, and object-destructured parameters
(`async ({ url }) => ...` and `async ({ url }: T) => ...`). The TypeScript
rule declares `languages: [typescript, javascript]` and its fixtures run as
both `.ts` and `.js`.

## Sinks: outbound request calls

A sink is a call expression whose function position matches one of the
shapes below. The finding line is the sink call.

### Python

- Module-level calls: `requests.<method>(...)`, `httpx.<method>(...)`,
  `aiohttp.<method>(...)`, `urllib.request.<method>(...)` (any method name,
  including `urlopen`)
- Bare `urlopen(...)` and `urlretrieve(...)` calls (covers
  `from urllib.request import urlopen`)
- Client-object calls `<receiver>.<method>(...)` where the receiver name
  contains `client` or `session` (case-insensitive: `client`,
  `self.session`, `httpx.AsyncClient()`, `aiohttp.ClientSession()`,
  `self._client`) and the method is one of `get`, `post`, `put`, `delete`,
  `head`, `patch`, `options`, `request`, `stream`, `fetch`, `ws_connect`
- Playwright navigation: `<receiver>.goto(...)` where the receiver name
  contains `page` or `browser`
- Context request clients: `<ctx>.request.<method>(...)` where the method is
  an HTTP verb name (`ctx.request.get` shape)

### TypeScript and JavaScript

- Bare calls named `fetch`, `nodeFetch`, `got`, `axios`, or `request`. The
  `fetch` shape covers both the global and a default `node-fetch` import.
- Method calls `axios.<method>(...)` and `got.<method>(...)` (any method)
- Playwright navigation: `<receiver>.goto(...)` where the receiver name
  contains `page`, `browser`, or `ctx`
- Context request clients: `<ctx>.request.<method>(...)` where the method is
  an HTTP verb name

## Sanitizers: the complete-guard call vocabulary

G0 is suppressed only by a call whose callee name matches the complete-guard
vocabulary. "Complete" means the guard resolves all addresses for the host,
range-checks every resolved address, and connects to the validated address
(pinned connect). Semgrep CE cannot verify that pipeline inside a call, so
the rule recognizes it by name, matching this regular expression:

```text
(?i)((.*[._])?(ssrf|safe_?fetch|safe_?get|safe_?request|assert_?safe|
ensure_?public|require_?public)|.*(public_?url|resolve_?and_?pin|
pinned_?request))[a-z_0-9]*
```

In words: callee names such as `ssrf_guard(...)`, `safe_fetch(...)`,
`safeFetch(...)`, `safe_get(...)`, `assert_safe_url(...)`,
`assertPublicUrl(...)`, `ensure_public_url(...)`, `validate_public_url(...)`,
`resolve_and_pin(...)`, `resolveAndPin(...)`, `pinned_request(...)`, and the
same shapes as methods (`self.assert_public_url(...)`,
`guards.safe_fetch(...)`). The sanitizer is `by-side-effect` with
`focus-metavariable` on the first argument, so it covers both the
return-value form (`checked = validate_public_url(url)`) and the
check-and-throw form (`assert_public_url(target)`).

Everything not in that vocabulary leaves the value tainted. In particular
these do NOT sanitize: `urlparse`, `new URL`, `ipaddress.ip_address`,
`net.isIP`, `is_safe_url`/`isSafeUrl`, `validate_url`, `checkUrl`, string
blocklist helpers, and any other unrecognized name. That is deliberate: a
weak or unrecognized guard must not produce silence. The raw G0 finding
still fires, and the layered site resolution in `classify.py` relabels or
suppresses it.

## Layered site resolution (why weak guards still fire G0)

The taint rules produce raw candidate findings, not verdicts. `classify.py`
resolves each enumerated sink in order: a weak-class finding (G1-G6, G8) at
the same site wins and the G0 finding is suppressed, so a scheme-only site
reports G1 and never double-labels as G0; otherwise a complete-guard probe
hit yields recognized-complete; otherwise an intervening-call probe hit
yields "guard detected, shape unrecognized, manual review"; otherwise the
site is G0. This is why the sanitizer vocabulary above is intentionally
narrow: anything the vocabulary misses must stay tainted so the site can be
classified instead of silently passed.

## Analysis ceiling (what these rules cannot see)

Semgrep CE taint is intra-function. Known blind spots, all documented rather
than papered over:

- Helper-factored guards. A guard that lives in `security.py` or
  `safeFetch.ts` and a sink in the caller do not share a taint path. The
  call to the helper shows up only through the intervening-call probe, so
  the site resolves to unrecognized-guard. Mature codebases will produce
  this verdict often; that is expected, not a miss.
- Helper-factored sinks. `await safeFetch(url)` where `fetch` is called
  inside `safeFetch` produces no sink at all at the handler site. Coverage
  reporting counts handler candidates and sinks separately so this cannot
  read as an empty scan.
- Parameter stickiness. A source parameter stays tainted for the whole
  function body: reassigning it (`url = "literal"`) or check-and-throwing on
  it directly (`assert_public_url(url)` then `requests.get(url)`) does not
  clear the taint. The raw G0 finding fires; the complete-guard site probe
  resolves the site to recognized-complete at classify time. Locals derived
  from the parameter (`target = url`) CAN be cleaned by the check-and-throw
  sanitizer.
- Name-based complete-guard recognition is lexical. A callee name that
  collides with the vocabulary without being a full guard (for example a
  formatter named `public_url`, or a `safe_fetch` that skips range checks)
  produces a false negative.
- Unlisted shapes are blind spots, not findings: handlers registered through
  `add_tool`/entry-point lists rather than decorators or registration
  methods, and network clients not in the sink list (raw `http.request` in
  Node, `urllib3` directly, `urllib.request.OpenerDirector`), are counted by
  the coverage summary, not reported as guarded or unguarded.

## Fixture contract

`semgrep test` treats the co-located fixture files as the executable form of
this matrix:

- `rules/python/g0-unguarded-fetch.py`
- `rules/typescript/g0-unguarded-fetch.ts`
- `rules/typescript/g0-unguarded-fetch.js`

Positive cases (annotated to fire): unguarded sinks in every source shape,
a `urlparse`-only and scheme-only path (the incumbent registry rule's false
negative is our true positive), unrecognized helper guards, and the
parameter-stickiness ceiling case. Negative cases (annotated quiet):
recognized complete-guard calls in both forms, hardcoded literal URLs, and
sinks outside any recognized handler. `tests/fixtures/g0/` holds small
synthetic repos with the same shapes for CLI-level tests.
