# mcp-ssrf-audit

A guard-completeness checker for SSRF defenses in MCP servers. Point it at a
cloned repository and it reports which way each SSRF-relevant site is
incomplete, classified against the G0-G10 taxonomy, not merely whether a
network sink exists.

Sink detection is already claimed territory: the official Semgrep registry
ships an MCP-aware SSRF rule (`ai/ai-best-practices/mcp-ssrf`, distributed in
the `p/mcp` pack) and Cisco's mcp-scanner runs an interprocedural engine. Both
answer a boolean. The 2026 advisory record says the live problem is different:
nearly every MCP SSRF advisory this year is a guard bug (bracket-stripping
mismatches, scheme-only checks, resolved addresses discarded before connect),
not an absent guard. This tool exists to classify partial guards; it does not
claim sink-detection novelty.

Threat model, in two sentences: model-chosen URLs reach server-side fetch
code inside MCP tool handlers. Prompt injection turns those fetches into
internal-network reads (SSRF, CWE-918).

Audience: built first for the researcher auditing third-party MCP servers
(scan a target, read the classified sites, cite the corpus instance as
disclosure evidence), second for MCP server authors and auditors checking one
repository against the taxonomy.

## Install and run

```sh
uvx mcp-ssrf-audit scan /path/to/cloned/repo
```

or install first and keep the entry point:

```sh
pipx install mcp-ssrf-audit
mcp-ssrf-audit scan /path/to/cloned/repo
```

From a source checkout:

```sh
pipx install .
mcp-ssrf-audit scan /path/to/cloned/repo
```

`scan` flags: `--json` (versioned machine output), `--timeout SECONDS`
(per-file Semgrep analysis timeout, default 30). `--version` prints the
package version.

The scan shells out to `semgrep` (pinned to `>=1.177.0,<1.178` in the package
metadata; CI additionally runs the rule tests against latest). It never
executes or installs target-repo code and makes no network calls.
`node_modules`, `dist`, `build`, `vendor`/`vendors`,
`third_party`/`third-party`, `venv`, and `.venv` trees are excluded by
default. A scanned repo cannot hide its own files:
git-ignore handling and target `.semgrepignore` files are disabled, and any
ignore files found are listed in the coverage summary. Findings under test or
example paths are flagged, not dropped.

Exit codes: `0` = clean or checklist-only, `1` = at least one deterministic
finding or unrecognized-guard item, `2` = operational failure.

## What a scan reports

Every recognized MCP handler site resolves to exactly one state, in
precedence order:

1. `deterministic`: a weak-class finding (G1-G6, G8) at the site, or G0
   when the sink is reachable from handler input and nothing validates on
   the path;
2. `recognized_complete`: a call in the known-complete shape set appears in
   the site (rendered scoped to the shipped taxonomy and ruleset version,
   never as an unqualified "safe");
3. `unrecognized_guard`: validation-shaped calls intervene but no rule
   recognizes the shape; reported for manual review, never silent;
4. `no_handler_input_flow` / `handler_no_sink`: recorded in coverage only.

Text output prints deterministic findings grouped by class (each naming the
guard and sink locations), then unrecognized-guard items, then
recognized-complete sites, then the manual-audit checklist for G7/G9/G10,
then a coverage summary: files scanned per language, recognized handler
candidates, sinks found (split into inside/outside recognized handlers),
parse failures, and per-state site counts. A repo with no detected handlers
or sinks reports "no MCP surface detected", a verdict distinct from "sinks
checked, guards complete."

`--json` emits the canonical machine output: `schema_version`
(`mcp-ssrf-audit/v1`), `taxonomy_version` (`g0-g10/v1`), `ruleset_version`,
`semgrep_version`, `target`, `findings`, `checklist`, `coverage`.

## Coverage

"Complete" for every class means the same pipeline: resolve all addresses
for the host, range-check every resolved address, connect to the validated
address (connect-time pinning), and re-validate each redirect hop. The rules
recognize that pipeline by callee name (`ssrf*`, `safe_fetch`/`safeFetch`,
`safe_get`, `safe_request`, `assert_safe*`/`assertSafe*`, `ensure_public*`,
`require_public*`, `*public_url*`/`publicUrl*`, `resolve_and_pin`/`resolveAndPin`,
`pinned_request*`); see `docs/source-sink-matrix.md` for the full source,
sink, and sanitizer vocabulary.

| Class | Advisory anchor | Shapes matched | Complete means | Python | TypeScript |
|-------|-----------------|----------------|----------------|--------|------------|
| G0 no guard | no advisory; `modelcontextprotocol/servers` mcp-server-fetch reference shape | Tainted handler parameter reaches a network sink (`requests.*`, `httpx.*`, `aiohttp.*`, `urllib.request.*`, `urlopen`/`urlretrieve`, `*client*`/`*session*` methods, `page`/`browser` `.goto`, `ctx.request.*`; `fetch`, `nodeFetch`, `got`, `axios`, `request`, `axios.*`/`got.*`, `page`/`browser`/`ctx` `.goto`, `ctx.request.*`) with no complete-guard call on the intra-function path | Route the URL through a complete guard before fetching | deterministic | deterministic |
| G1 scheme-only | CVE-2026-26118 / GHSA-hhfx-wfvq-7g9c | Python: `urlparse`/`urlsplit` `.scheme` membership or equality as the only check on the tainted path (no resolver, `ipaddress`, or hostname/netloc check in the function). TS/JS: protocol allowlist (`["http:","https:"].includes(u.protocol)`) or `startsWith("https://")` with no host- or address-level check in the enclosing block | Check the host, not just the scheme: resolve and range-check | deterministic | deterministic |
| G2 string blocklist | no advisory; [removed] | Python: tainted host compared (`in`, `==`, `startswith`, `endswith`) against internal-name literals (`localhost`, `127.0.0.1`, `169.254.*`, `.internal`/`.local`/`.lan`/`.corp`...) or a blocklist-named collection, with no resolve or `ipaddress` call in the function. TS/JS: literal hostname compares or dotted-quad/loopback regexes in a host context (`.hostname`, `.host`, `new URL`), with no IP parse or resolver call in the block | Parse and resolve the host; range-check every resolved address | deterministic | deterministic |
| G3 IP parse, no DNS | CVE-2026-55526 / GHSA-x44h-65qv-cw74 | Python: `ipaddress.ip_address`/`IPv4Address`/`IPv6Address`/`inet_aton`/`inet_pton` on the tainted host with no DNS resolution in the function. TS/JS: `net.isIP`-family literal check in a block that also performs an outbound request but never resolves | Resolve the hostname and range-check every returned address; a failed literal parse is not "safe" | deterministic | deterministic |
| G4 bracketed IPv6 | CVE-2026-80347; CVE-2026-42260 / GHSA-v228-72c7-fx8j | TS/JS: `net.isIP`/`isIPv4`/`isIPv6`-family call on a `URL.hostname`-derived value with no bracket strip or normalization on the path (`isIP("[::1]")` returns 0 and the private branch is skipped) | Strip `[`/`]` or normalize before the IP-literal check | n/a (TS-specific shape) | deterministic |
| G5 incomplete IPv6 normalization | CVE-2026-49857 / GHSA-pvrj-8cg3-j5f8 | Python: textual `::ffff:` probe or rewrite on the tainted host (`startswith`, `removeprefix`, `replace`, `in`). TS/JS: `::ffff:` prefix branch plus tail extraction (`.slice`/`.substring`/`.substr`) feeding `isIPv4`/`isIP`, which misses hextet-normalized `::ffff:7f00:1`, NAT64 `64:ff9b::`, and 6to4 `2002:` | Parse IPv6 structurally (hextets); cover IPv4-mapped, NAT64, and 6to4; fail closed | deterministic | deterministic |
| G6 no redirect re-validation | CVE-2026-55525 / CVE-2026-55523 / CVE-2026-55524 (GHSA-5r34-2g38-6569, GHSA-8hjw-25cg-g52h, GHSA-vg6p-v9vm-6fgj); also CVE-2026-57115 / GHSA-6h9p-93hq-q7h6 | Python: tainted request that follows redirects (default behavior, `allow_redirects=True`, `follow_redirects=True`, or a client constructed with `follow_redirects=True`) inside a function that also contains a guard-shaped call. TS/JS: `fetch` without `redirect:"manual"`/`"error"`, `axios`/`got` without `maxRedirects:0` or a redirect handler, `page.goto`, `ctx.request.*` | Re-validate every redirect hop before connecting to it | deterministic | deterministic |
| G7 DNS rebinding / TOCTOU | CVE-2026-27826 / GHSA-7r34-79r5-rcc9 | Checklist candidates: resolver call sites. Python: `getaddrinfo`/`gethostbyname*`/`gethostbyaddr` bare or on `socket`/`dns`/`resolver`/`nameserver`/`loop` receivers, plus `resolve*`/`lookup`/`query` methods on those receivers. TS/JS: `lookup`/`resolve*`/`reverse`/`getServers` on `dns`/`resolver`/`nameserver` receivers, plus bare `lookup`/`resolve4`/`resolve6`/`resolveAny`/`reverse`. Verify connect-time pinning by hand | Connect to the validated resolved address, or re-check the connected peer after connect | checklist | checklist |
| G8 weak or default-off allowlist | CVE-2026-80347 (env kill-switch); CVE-2026-49857 / GHSA-pvrj-8cg3-j5f8 (`AUTH_FETCH_ALLOW_PRIVATE`); CVE-2026-55525 (`ALLOW_LOCAL_CRAWL`); [removed] | Python: `startswith`/`endswith`/substring `in`/`re.match` without an end anchor/`re.search` on the tainted URL or host; env-var reads with bypass names (`ALLOW_LOCAL_*`, `DISABLE_SSRF*`, `BYPASS*`, `UNSAFE`...); allowlist-shaped names declared with empty or off defaults (`None`, `[]`, `Field(default=...)`). TS/JS: `process.env` bypass-name reads, bypass-flag `if` gates, allow-everything helper gates, allowlists defaulting empty (`?? []`, `|| {}`), fail-open `length === 0` checks, unanchored `endsWith`/`startsWith` with a non-literal operand in host context | Anchor host comparisons (exact match or dot-boundary suffix); guard on by default; no env bypass on model-supplied input | deterministic | deterministic |
| G9 coverage across entry points | no advisory; [removed] | Checklist candidates: every recognized MCP entry point (Python `@*.tool`/`call_tool`/`get_prompt`; TS/JS `tool`/`registerTool`/`callTool`/`getPrompt`/`setRequestHandler`/`prompt`/`resource`). Verify each path to a sink shares the complete guard | Every entry point that can reach a sink goes through the same complete guard | checklist | checklist |
| G10 credentials on a model-chosen host | no advisory; [removed] | Checklist candidates: credential attach sites (Python `headers=`/`auth=`/credential kwargs, credential-keyed dict literals and subscripts; TS/JS credential-keyed object literals, `headers.set`/`append`/`setHeader` with auth-ish names) | Credentials attach only to operator-fixed hosts, never a model-chosen one | checklist | checklist |

Rule layout: `rules/python/` and `rules/typescript/` carry the deterministic
rules (one rule id per shape, `metadata.guard_class` set per class; the TS
rules declare `languages: [typescript, javascript]` and cover `.js`/`.mjs`/
`.cjs`). `rules/checklist/` carries the G7/G9/G10 candidate enumerators and
`rules/site-probes/` the handler/sink enumerators and guard-shape probes the
CLI resolves against. `docs/source-sink-matrix.md` is the authoritative
detection boundary; every rule cites it.

## Consumption modes

- CLI (above): `uvx mcp-ssrf-audit scan <repo>`, or `pipx install .` from a
  checkout. The wheel force-includes `rules/`, so the installed entry point
  needs no extra rule configuration.
- Raw rule pack from a checkout: `semgrep --config rules/ <repo>` or
  `semgrep scan --config rules/ --json <repo>`. Note the caveat under
  Limitations: raw output includes enumerator and checklist hits.
- Single-file bundle: CI concatenates `rules/` into
  `dist/mcp-ssrf-audit.yaml` on every run. It is a build artifact, not
  committed; any raw URL serving that file works as
  `semgrep --config <raw-url> <repo>`.
- Corpus as a dataset: `corpus/` is consumable independently of the ruleset
  (`manifest.jsonl` per-site labels, generated `EXPECTEDRESULTS.csv`
  file-level rollup, per-instance `metadata.json` with pinned SHAs and
  licenses). Corpus content is CC BY 4.0; vendored snippets remain under
  their upstream licenses (see `corpus/NOTICE`).
- Corpus validation: `mcp-ssrf-audit corpus-validate [--corpus corpus]
  [--json] [--timeout SECONDS]` runs the packaged rules over every labeled
  sample in `manifest.jsonl` and reports per-sample status: `caught`,
  `missed`, `misclassified-extra` (reported, non-gating), `clean`, or
  `precision-failure` (a deterministic finding on a CLEAN instance) for the
  deterministic tier, and `checklist-emitted` / `checklist-missing` for the
  checklist tier. Unmaterialized fetched samples are skipped with a pointer
  to `python3 scripts/fetch_corpus.py` (`--check` verifies pins without
  downloading); a vendored sample missing files is an integrity error.
  Exit codes: 0 fully green, 1 any miss, precision failure, or missing
  checklist emission, 2 operational failure.

## Limitations

- Intra-function, intra-file ceiling (Semgrep CE taint). A guard factored
  into a helper the engine cannot trace resolves to "unrecognized guard,
  manual review", not to a pass. Helper-factored sinks (`fetch` called
  inside `safeFetch`) produce no sink at the handler site at all; the
  coverage summary counts handler candidates and sinks separately so this
  cannot read as an empty scan.
- Parameter stickiness. A tainted handler parameter stays tainted for the
  whole function body: reassigning it or check-and-throwing on it directly
  does not clear taint, so the raw G0 finding fires and is resolved to
  recognized-complete by the site probe at classify time.
- Complete-guard recognition is lexical. A callee name that collides with
  the vocabulary without being a real guard (a `safe_fetch` that skips
  range checks) produces a false negative.
- Unlisted shapes are blind spots, not findings: handlers registered
  through shapes outside the matrix (for example `add_tool` entry-point
  lists) and network clients outside the sink list (`http.request`,
  `urllib3` directly, `urllib.request.OpenerDirector`) appear in coverage
  counts, not as guarded or unguarded verdicts.
- Checklist classes are candidates, not findings. G7, G9, and G10 emit
  sites to verify by hand; correct pinned-connect guards and vacuous ones
  both appear in the G7 list.
- DNS rebinding is checklist-only, and redirect behavior is bounded: G6
  detects a redirect-following call with no re-validation shape around it;
  it does not model actual redirect hops.
- Raw `semgrep --config rules/` output surfaces enumerator and
  checklist-candidate matches as ordinary findings. The `mcp-ssrf-audit`
  CLI is what interprets them into the layered site resolution described
  above; read raw rule output accordingly.

## Corpus provenance

One row per manifest instance; the `vuln`/`patched`/`fetched`/`guarded`
labels give the pinned SHA (8 chars) and expected class set. Full detail lives in
`corpus/manifest.jsonl` and each `metadata.json`.

| Instance | Repo | Pinned states (expected) | Advisory | License | Source |
|----------|------|--------------------------|----------|---------|--------|
| g0-mcp-server-fetch | modelcontextprotocol/servers | vuln d73f99ef (G0) | none (issue 3741) | MIT OR Apache-2.0 | vendored |
| g1-fetcher-mcp-scheme-only | jae-jae/fetcher-mcp | vuln 8754aff6 (G1) | CVE-2026-26118 / GHSA-hhfx-wfvq-7g9c | MIT | vendored |
| ***REMOVED*** | ***REMOVED***/***REMOVED*** | vuln d7131091 (G0+G2) | none | MIT | vendored |
| ***REMOVED*** | ***REMOVED***/***REMOVED*** | fetched b764e88b (G2) | none | none declared | fetched |
| g3-praisonaiagents-spider-hostname | MervinPraison/PraisonAI | vuln 9991e00f (G3+G6); patched 2f9677ab (G6) | CVE-2026-55526 / GHSA-x44h-65qv-cw74 | MIT | vendored |
| g4-kazuph-mcp-fetch-bracketed-ipv6 | kazuph/mcp-fetch | vuln eba4abf2 (G4) | CVE-2026-80347 | MIT | vendored |
| g4-g8-kazuph-mcp-fetch-head | kazuph/mcp-fetch | fetched 418e58aa (G4+G8) | CVE-2026-80347 | MIT | fetched |
| g4-open-websearch-bracketed-ipv6 | Aas-ee/open-webSearch | vuln e29b2357 (G4); patched 8c35c6bb (CLEAN) | CVE-2026-42260 / GHSA-v228-72c7-fx8j | Apache-2.0 | vendored |
| g5-auth-fetch-mcp-ipv6-normalization | ymw0407/auth-fetch-mcp | vuln 42daa70c (G5+G8); patched 177ec5f8 (G8, plus G7 checklist residual) | CVE-2026-49857 / GHSA-pvrj-8cg3-j5f8 | MIT | vendored |
| g6-praisonaiagents-web-crawl-redirect | MervinPraison/PraisonAI | vuln 9991e00f (G6+G8); patched 2f9677ab (G6+G8) | CVE-2026-55525, CVE-2026-55523, CVE-2026-55524 | MIT | vendored |
| ***REMOVED*** | ***REMOVED***/***REMOVED*** | vuln 843819cb (G8) | none | MIT | vendored |
| checklist-mcp-atlassian-g7 | sooperset/mcp-atlassian | vuln 52b9b099 (G7); patched 5cd697df (G7) | CVE-2026-27826 / GHSA-7r34-79r5-rcc9 | MIT | vendored |
| ***REMOVED*** | crewAIInc/crewAI | vuln 894898f8 (G9); patched 894898f8 (CLEAN) | none | MIT | vendored |
| ***REMOVED*** | ***REMOVED***/***REMOVED*** | vuln 765ecdfd (G10) | none | MIT | vendored |
| clean-zcaceres-fetch-mcp | zcaceres/fetch-mcp | guarded 1ddb1a59 (CLEAN) | none | MIT | vendored |
| clean-crewai-scrape-website-tool | crewAIInc/crewAI | guarded 894898f8 (CLEAN) | none | MIT | vendored |
| clean-firecrawl-safe-fetch | firecrawl/firecrawl | fetched b3cc08da (CLEAN) | none | AGPL-3.0 | fetched |
| ***REMOVED*** | ***REMOVED***/***REMOVED*** | fetched 7169bcd0 (G0) | none | MIT | fetched |
| ***REMOVED*** | ***REMOVED*** | fetched 027ecf0a (G0) | none | CC-BY-4.0 | fetched |
| ***REMOVED*** | ***REMOVED***/***REMOVED*** | fetched f425a3ed (G0) | none | MIT | fetched |
| ***REMOVED*** | ***REMOVED***/***REMOVED*** | fetched f425a3ed (G8) | none | MIT | fetched |

## Development

CI (`.github/workflows/ci.yml`) runs `semgrep validate rules/`, `semgrep
test rules/` (the co-located `ruleid:`/`ok:` fixtures are the executable
contract for the matrix), `pytest`, and a check that nothing under
`corpus/` is collected, across the pinned Semgrep floor and latest. It also
builds the `dist/mcp-ssrf-audit.yaml` bundle.

## License

Code: MIT (see `LICENSE`). Corpus content: CC BY 4.0 (see `corpus/LICENSE`);
vendored upstream snippets keep their own licenses (see `corpus/NOTICE`).
