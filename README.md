# mcp-ssrf-audit

Classifies how SSRF defenses in MCP servers are incomplete, not just whether
a network sink exists. Findings are labeled by guard class under the G0-G10
taxonomy; each class is anchored to a real 2026 advisory.

Threat model, in two sentences: model-chosen URLs reach server-side fetch
code in MCP tool handlers. Prompt injection turns those fetches into
internal-network reads (SSRF, CWE-918).

## Install and run

```sh
uvx mcp-ssrf-audit scan /path/to/cloned/repo
```

Or run the rule pack directly on a source checkout:

```sh
semgrep --config rules/ /path/to/cloned/repo
```

## Taxonomy coverage

| Class | Shape | Python | TypeScript |
|-------|-------|--------|------------|
| G0 | No guard | planned | planned |
| G1 | Scheme-only validation | planned | planned |
| G2 | String blocklist of literals | planned | planned |
| G3 | IP-literal parse without DNS resolution | planned | planned |
| G4 | Bracketed IPv6 mishandled by net.isIP | n/a | planned |
| G5 | Incomplete IPv6 normalization | planned | planned |
| G6 | No redirect re-validation | planned | planned |
| G7 | DNS rebinding (resolve-check-connect TOCTOU) | manual checklist | manual checklist |
| G8 | Unanchored or default-off allowlists | planned | planned |
| G9 | Sibling entry points bypass the guarded path | manual checklist | manual checklist |
| G10 | Credentials follow a model-chosen host | manual checklist | manual checklist |

## Limitations

- Analysis is intra-function and intra-file (Semgrep CE ceiling). A guard
  factored into a helper the engine cannot trace reports as
  "unrecognized guard, manual review," never as safe.
- DNS rebinding, redirect-hop re-validation at connect time, and the
  structural classes (G7, G9, G10) are emitted as a manual-audit checklist
  of candidate sites, not as deterministic findings.
- Running the raw rule pack (`semgrep --config rules/`) surfaces
  enumerator and checklist-candidate matches as ordinary findings; the
  `mcp-ssrf-audit` CLI is what interprets them into the three-state
  verdict.

## Corpus

`corpus/` is a labeled dataset of real vulnerable and patched MCP SSRF
guards, vendored or fetched at pinned commits, licensed CC BY 4.0 (see
`corpus/LICENSE` and `corpus/NOTICE`). Code in this repository is MIT.

## License

Code: MIT (see LICENSE). Corpus content: CC BY 4.0 (see corpus/LICENSE).
