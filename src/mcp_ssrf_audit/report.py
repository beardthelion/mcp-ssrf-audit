"""Human text and canonical JSON rendering for scan results (R9, R12, R16, KTD4).

Layout contract: deterministic findings first (grouped by guard class),
then unrecognized-guard items, then recognized-complete sites (always
scoped to the shipped taxonomy and ruleset version), then the
manual-audit checklist, then the coverage summary. A checklist item is
never rendered as a detected bug.

Exit codes: 0 = clean or checklist-only, 1 = any deterministic finding or
unrecognized-guard item, 2 = operational failure (raised before this
module runs).
"""

from __future__ import annotations

import json

SCHEMA_VERSION = "mcp-ssrf-audit/v1"
TAXONOMY_VERSION = "g0-g10/v1"

# Display titles for the taxonomy. Unknown classes fall back to a generic
# label so new class rules integrate without code changes here.
CLASS_TITLES = {
    "G0": "no guard recognized",
    "G1": "scheme-only validation",
    "G2": "string blocklist",
    "G3": "IP parse without DNS resolution",
    "G4": "bracketed IPv6 bypass",
    "G5": "incomplete IPv6 normalization",
    "G6": "missing redirect re-validation",
    "G7": "DNS rebinding / TOCTOU",
    "G8": "unanchored or default-off allowlist",
    "G9": "guard coverage across entry points",
    "G10": "credentials on a model-chosen host",
}

_ACTIONABLE = ("deterministic", "unrecognized_guard")


def _fmt_loc(loc: dict) -> str:
    return f"{loc['path']}:{loc['line']}"


def _fmt_site(site: dict) -> str:
    rng = f"{site['path']}:{site['start_line']}"
    if site["end_line"] != site["start_line"]:
        rng += f"-{site['end_line']}"
    if site.get("site"):
        rng += f"  ({site['site']})"
    return rng


def actionable_sites(result: dict) -> list[dict]:
    return [s for s in result["sites"] if s["resolution"] in _ACTIONABLE]


def exit_code(result: dict) -> int:
    """KTD4: 1 when any deterministic finding or unrecognized item, else 0."""
    return 1 if actionable_sites(result) else 0


def build_json_report(
    result: dict,
    *,
    ruleset_version: str,
    semgrep_version: str | None,
    target: str,
) -> dict:
    """Canonical versioned machine output (KTD4, R16)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "taxonomy_version": TAXONOMY_VERSION,
        "ruleset_version": ruleset_version,
        "semgrep_version": semgrep_version,
        "target": target,
        "findings": [
            s for s in result["sites"] if s["resolution"] in _ACTIONABLE
        ],
        "checklist": result["checklist"],
        "coverage": result["coverage"],
    }


def render_text(
    result: dict,
    *,
    ruleset_version: str,
    semgrep_version: str | None,
    target: str,
) -> str:
    out: list[str] = []
    version = semgrep_version or "unknown"
    out.append(f"mcp-ssrf-audit {ruleset_version} scan of {target} (semgrep {version})")
    out.append("")

    actionable = actionable_sites(result)
    determ = [s for s in actionable if s["resolution"] == "deterministic"]
    unrec = [s for s in actionable if s["resolution"] == "unrecognized_guard"]
    complete = [
        s for s in result["sites"] if s["resolution"] == "recognized_complete"
    ]

    # --- deterministic findings, grouped by class ---
    out.append("Deterministic findings")
    out.append("----------------------")
    if not determ:
        out.append("  none")
    else:
        by_class: dict[str, list[dict]] = {}
        for s in determ:
            for cls in s["classes"]:
                by_class.setdefault(cls, []).append(s)
        for cls in sorted(by_class):
            title = CLASS_TITLES.get(cls, "guard class")
            out.append(f"  [{cls}] {title}")
            for s in by_class[cls]:
                out.append(f"    {_fmt_site(s)}")
                for loc in s["class_locations"].get(cls, []):
                    out.append(f"      guard: {_fmt_loc(loc)}")
                for loc in s["sinks"]:
                    out.append(f"      sink:  {_fmt_loc(loc)}")
                if s["test_path"]:
                    out.append("      (under a test/example path)")
    out.append("")

    # --- unrecognized guards ---
    out.append("Unrecognized guards (manual review required)")
    out.append("--------------------------------------------")
    if not unrec:
        out.append("  none")
    else:
        for s in unrec:
            out.append(
                f"  {_fmt_site(s)}: guard detected, shape unrecognized"
            )
            for loc in s["guard_locations"]:
                out.append(f"    guard candidate: {_fmt_loc(loc)}")
            for loc in s["sinks"]:
                out.append(f"    sink:            {_fmt_loc(loc)}")
            if s["test_path"]:
                out.append("    (under a test/example path)")
    out.append("")

    # --- recognized-complete sites, always version-scoped (R13) ---
    out.append(
        "Recognized-complete sites (matches the known-complete shape set; "
        f"taxonomy {TAXONOMY_VERSION}, ruleset {ruleset_version})"
    )
    out.append("-" * 40)
    if not complete:
        out.append("  none")
    else:
        for s in complete:
            out.append(f"  {_fmt_site(s)}")
            for loc in s["sinks"]:
                out.append(f"    sink: {_fmt_loc(loc)}")
    out.append("")

    # --- manual-audit checklist ---
    out.append("Manual-audit checklist (candidates, not findings)")
    out.append("-------------------------------------------------")
    if not result["checklist"]:
        out.append("  none")
    else:
        for item in result["checklist"]:
            title = CLASS_TITLES.get(item["class"], "guard class")
            out.append(f"  [{item['class']}] {title}")
            out.append(f"    {item['path']}:{item['line']}")
            if item.get("verify"):
                out.append(f"    verify: {item['verify']}")
            if item["test_path"]:
                out.append("    (under a test/example path)")
    out.append("")

    # --- coverage summary (R12) ---
    cov = result["coverage"]
    out.append("Coverage")
    out.append("--------")
    fs = cov["files_scanned"]
    parts = [f"{lang}={n}" for lang, n in fs.items() if lang != "total"]
    out.append(f"  files scanned: {fs['total']} ({', '.join(parts)})")
    out.append(f"  recognized handler candidates: {cov['handler_candidates']}")
    inside = cov["sinks_found"] - len(cov["sinks_outside_recognized_handlers"])
    out.append(
        f"  network sinks found: {cov['sinks_found']} "
        f"(inside recognized handlers: {inside}, "
        f"outside: {len(cov['sinks_outside_recognized_handlers'])})"
    )
    for loc in cov["sinks_outside_recognized_handlers"]:
        out.append(f"    outside recognized handlers: {_fmt_loc(loc)}")
    out.append(f"  parse failures: {len(cov['parse_failures'])}")
    for pf in cov["parse_failures"]:
        where = f"{pf['path']}: " if pf["path"] else ""
        out.append(f"    {where}{pf['message']}")
    if cov["target_ignore_files"]:
        out.append(
            "  target-controlled ignore files present (not honored; tool "
            "excludes and --no-git-ignore apply):"
        )
        for f in cov["target_ignore_files"]:
            out.append(f"    {f}")
    sbr = cov["sites_by_resolution"]
    out.append(
        "  site resolution: "
        + ", ".join(f"{k}={sbr[k]}" for k in sorted(sbr))
        if sbr
        else "  site resolution: none"
    )
    if cov["verdict"] == "no_mcp_surface_detected":
        out.append("  verdict: no MCP surface detected")
    else:
        out.append("  verdict: MCP surface detected")
    return "\n".join(out) + "\n"


def render_json(
    result: dict,
    *,
    ruleset_version: str,
    semgrep_version: str | None,
    target: str,
) -> str:
    return (
        json.dumps(
            build_json_report(
                result,
                ruleset_version=ruleset_version,
                semgrep_version=semgrep_version,
                target=target,
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
