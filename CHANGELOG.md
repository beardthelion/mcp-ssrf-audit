# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

## [Unreleased]

### Added

- `mcp-ssrf-audit scan <path>` CLI: runs the packaged Semgrep rule pack over
  a cloned repo and resolves every enumerated sink site into a deterministic
  finding, recognized-complete (version-scoped), unrecognized-guard
  (manual review), or G0. Text output prints findings grouped by class, then
  the G7/G9/G10 manual-audit checklist, then the coverage summary (files
  scanned per language, handler candidates, sinks inside/outside recognized
  handlers, parse failures, site counts, "no MCP surface detected" verdict).
  `--json` emits the versioned schema (`mcp-ssrf-audit/v1`, taxonomy
  `g0-g10/v1`). Exit codes: 0 clean or checklist-only, 1 findings or
  unrecognized guards, 2 operational failure. `--timeout` sets the per-file
  Semgrep timeout.
- Deterministic Semgrep rules for G0-G6 and G8: `rules/python/` (G0, G1,
  G2, G3, G5, G6, and three G8 shapes) and `rules/typescript/`
  (G0-G6 and G8; `languages: [typescript, javascript]`, so `.js`/`.mjs`/
  `.cjs` are covered). Each rule carries `metadata.guard_class` and
  `advisory_refs` anchoring it to a 2026 advisory or live target.
- `rules/checklist/`: search-mode candidate enumerators for the structural
  classes (G7 resolver sites, G9 entry points, G10 credential attach sites),
  emitted only when an MCP surface is detected.
- `rules/site-probes/`: handler-source and network-sink enumerators, the
  complete-guard shape probe, and the intervening-validation probe consumed
  by the layered site resolution.
- `mcp-ssrf-audit corpus-validate` subcommand (`--corpus`, `--json`,
  `--timeout`): runs the packaged rules over every labeled sample in
  `corpus/manifest.jsonl` and reports caught, missed, misclassified-extra,
  clean, and precision-failure statuses; checklist-tier labels are validated
  by checklist emission and reported separately from deterministic
  pass/fail. Unmaterialized fetched samples are skipped; exits 1 on any
  miss, precision failure, or missing checklist emission.
- Labeled corpus under `corpus/` (CC BY 4.0): 21 instances covering every
  claimed class plus CLEAN exemplars, with `manifest.jsonl` per-site labels,
  generated `EXPECTEDRESULTS.csv` rollup, per-instance `metadata.json`, and
  `NOTICE` attribution. `scripts/fetch_corpus.py` materializes fetched
  instances at pinned SHAs.
- `docs/source-sink-matrix.md`: the published detection boundary (handler
  sources, network sinks, complete-guard sanitizer vocabulary, layered
  site resolution, analysis ceiling).
- Scan hardening: target `.gitignore`/`.semgrepignore` files are disabled
  and surfaced in coverage; default excludes cover `node_modules`, `dist`,
  `build`, `vendor`, `third_party`, `venv`, `.venv`; findings under test or
  example paths are flagged, not dropped.
- CI: `semgrep validate`, `semgrep test`, and `pytest` across the pinned
  Semgrep floor and latest; a gate asserting no `corpus/` file is collected
  by pytest; generation of the single-file `dist/mcp-ssrf-audit.yaml` bundle
  for `semgrep --config <raw-url>` consumption.
