"""Layered site resolution over raw semgrep results (KTD7, R13, R14, R16).

Raw semgrep results are inputs, not verdicts. This module groups them by
enclosing handler (the site) and resolves each site in precedence order:

1. a weak-class deterministic finding (any ``metadata.guard_class`` other
   than the no-guard class) wins; the raw no-guard finding at the same
   site is suppressed so a scheme-only site reports its weak class and
   never double-labels as G0;
2. otherwise a raw no-guard finding plus a *bound* complete-guard probe
   hit yields recognized-complete;
3. otherwise a raw no-guard finding plus a *bound* intervening-validation
   probe hit yields unrecognized-guard ("guard detected, shape
   unrecognized, manual review");
4. otherwise the raw no-guard finding stands as a G0 finding.

A probe hit is *bound* when identifiers in its matched line overlap the
sink call's first-argument identifiers: ``ensure_public_url(url)`` binds
to ``requests.get(url)``; ``pinned_request("https://example.com")`` or
``check_quota(1)`` in the same extent do not, so an unrelated
guard-shaped call can neither launder a site into recognized-complete
nor downgrade it to unrecognized-guard. A complete-guard probe hit with
no raw no-guard finding means the by-side-effect sanitizer cleaned the
tainted value, so the site resolves recognized-complete without the
binding check.

The module is data-driven off rule metadata: it reads
``metadata.guard_class`` and ``metadata.probe_role`` and never names a
rule id, so class rules added later integrate without code changes.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# Probe roles emitted via metadata.probe_role by rules/site-probes and
# rules/checklist.
ROLE_HANDLER = "handler_source"
ROLE_SINK = "network_sink"
ROLE_COMPLETE_GUARD = "complete_guard"
ROLE_INTERVENING = "intervening_validation"
ROLE_CHECKLIST = "checklist"

# The no-guard baseline class. Every other guard_class value on a
# deterministic-tier result is a weak class that outranks it at a site.
NO_GUARD_CLASS = "G0"

RESOLUTION_DETERMINISTIC = "deterministic"
RESOLUTION_RECOGNIZED_COMPLETE = "recognized_complete"
RESOLUTION_UNRECOGNIZED = "unrecognized_guard"
RESOLUTION_NO_FLOW = "no_handler_input_flow"
RESOLUTION_HANDLER_NO_SINK = "handler_no_sink"

# Path segments that flag a finding as living under a test/example tree
# (R15: flagged, never dropped).
_TEST_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "__tests__",
        "spec",
        "specs",
        "e2e",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "demo",
        "demos",
        "docs",
        "doc",
    }
)

_EXT_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Keywords and literals excluded from identifier extraction when binding
# probe hits to sink arguments.
_NONARG_WORDS = frozenset(
    {
        "if", "else", "elif", "raise", "throw", "return", "not", "and",
        "or", "in", "is", "new", "const", "let", "var", "def", "await",
        "async", "for", "while", "try", "except", "finally", "with",
        "True", "False", "None", "true", "false", "null", "undefined",
        "function",
    }
)

# Control characters stripped from matched text before it is rendered as
# a site label or checklist message in terminal output.
_CTRL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def is_test_path(path: str) -> bool:
    """True when ``path`` sits under a test/example tree or names one."""
    p = PurePosixPath(path.replace("\\", "/"))
    lowered = [seg.lower() for seg in p.parts]
    if any(seg in _TEST_SEGMENTS for seg in lowered):
        return True
    name = lowered[-1] if lowered else ""
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def _language_of(path: str) -> str:
    return _EXT_LANGUAGE.get(PurePosixPath(path).suffix.lower(), "other")


def class_sort_key(cls: str) -> tuple[int, str]:
    """Numeric ordering for ``G<N>`` labels so G10 sorts after G9."""
    if len(cls) > 1 and cls[1:].isdigit():
        return (int(cls[1:]), cls)
    return (10**6, cls)


def _loc(result: dict) -> dict:
    start = result.get("start") or {}
    return {
        "path": result.get("path", ""),
        "line": start.get("line", 0),
        "col": start.get("col", 0),
    }


def _extent(result: dict) -> tuple[int, int]:
    start = (result.get("start") or {}).get("line", 0)
    end = (result.get("end") or {}).get("line", start)
    return start, end


def _file_lines(
    rel: str,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> list[str] | None:
    """Read a result file's lines once, cached per resolved path.

    Semgrep reports paths as given on the command line: absolute targets
    yield absolute result paths, relative targets yield cwd-relative
    ones. Try both the raw path and the target-root join.
    """
    candidates = [Path(rel)]
    if target_root is not None:
        candidates.append(target_root / rel)
        try:
            candidates.append(target_root / Path(rel).relative_to(target_root))
        except ValueError:
            pass
    seen: set[str] = set()
    for src in candidates:
        key = str(src)
        if key in seen:
            continue
        seen.add(key)
        if key not in lines_cache:
            try:
                lines_cache[key] = src.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                lines_cache[key] = None
        if lines_cache[key] is not None:
            return lines_cache[key]
    return None


def _hit_text(
    result: dict,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> str:
    """Full source text of the lines spanned by a result's match.

    Prefers the target file so an enclosing assignment target is visible
    (``checked = ensure_public_url(url)``); falls back to semgrep's
    ``extra.lines`` when the file is unreadable.
    """
    start = result.get("start") or {}
    end = result.get("end") or {}
    file_lines = _file_lines(result.get("path", ""), target_root, lines_cache)
    if file_lines is not None:
        s_line, e_line = start.get("line", 0), end.get("line", 0)
        if 0 < s_line <= len(file_lines):
            e_line = min(max(e_line, s_line), len(file_lines))
            return "\n".join(file_lines[s_line - 1 : e_line])
    return (result.get("extra") or {}).get("lines") or ""


def _first_arg_idents(text: str) -> set[str]:
    """Identifiers in the first top-level argument of a call expression.

    For ``requests.get(url, headers=h)`` this is ``{url}``: the URL
    argument, not incidental kwargs. Falls back to every identifier in
    the text when the hit is not a call (e.g. an ``if`` check-and-throw).
    """
    i = text.find("(")
    if i == -1:
        region = text
    else:
        depth = 0
        end = len(text)
        for j in range(i, len(text)):
            c = text[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            elif c == "," and depth == 1:
                end = j
                break
        region = text[i + 1 : end]
    return {
        m for m in _IDENT.findall(region) if m not in _NONARG_WORDS
    }


def _text_idents(text: str) -> set[str]:
    return {
        m for m in _IDENT.findall(text) if m not in _NONARG_WORDS
    }


def _function_hint(
    result: dict,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> str:
    """First line of the matched region, trimmed, for site labeling.

    Semgrep's JSON leaves ``extra.lines`` as "requires login", so the
    label line is read from the target file when a root is given. Control
    characters are stripped: matched text is attacker-controlled bytes on
    its way to a terminal.
    """
    lines = ((result.get("extra") or {}).get("lines") or "").strip()
    if lines and lines != "requires login":
        return _CTRL_CHARS.sub("", lines.splitlines()[0])[:80]
    line_no = (result.get("start") or {}).get("line", 0)
    file_lines = _file_lines(result.get("path", ""), target_root, lines_cache)
    if file_lines is not None and 0 < line_no <= len(file_lines):
        return _CTRL_CHARS.sub("", file_lines[line_no - 1].strip())[:80]
    return ""


@dataclass
class _Site:
    path: str
    start_line: int
    end_line: int
    label: str = ""
    sinks: list[dict] = field(default_factory=list)
    # Raw sink results, kept for argument-identifier binding.
    sink_results: list[dict] = field(default_factory=list)
    # Identifiers from sink first arguments; synthetic sites (a class
    # finding outside every handler extent) seed this from the finding's
    # own call text.
    sink_arg_idents: set[str] = field(default_factory=set)
    # guard_class -> list of finding locations at this site
    class_locations: dict[str, list[dict]] = field(default_factory=dict)
    has_raw_no_guard: bool = False
    no_guard_locations: list[dict] = field(default_factory=list)
    complete_guard_results: list[dict] = field(default_factory=list)
    validation_results: list[dict] = field(default_factory=list)
    resolution: str = ""
    test_path: bool = False

    @property
    def key(self) -> tuple[str, int, int]:
        return (self.path, self.start_line, self.end_line)

    @property
    def classes(self) -> list[str]:
        return sorted(self.class_locations, key=class_sort_key)

    def to_record(self) -> dict:
        guards: list[dict] = []
        for r in self.complete_guard_results + self.validation_results:
            loc = _loc(r)
            if loc not in guards:
                guards.append(loc)
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "site": self.label,
            "resolution": self.resolution,
            "classes": self.classes,
            "class_locations": {
                cls: self.class_locations[cls]
                for cls in sorted(self.class_locations, key=class_sort_key)
            },
            "sinks": self.sinks,
            "guard_locations": guards,
            "test_path": self.test_path,
        }


def classify_results(
    scan_data: dict,
    *,
    target_ignore_files: list[str] | None = None,
    excluded_dirs: list[str] | None = None,
    target_root: str | Path | None = None,
) -> dict:
    """Resolve raw semgrep JSON into sites, checklist, and coverage.

    ``scan_data`` is the parsed semgrep ``--json`` payload. Returns a dict
    with keys ``sites``, ``checklist``, ``coverage``.
    """
    root = Path(target_root) if target_root is not None else None
    results = scan_data.get("results") or []

    handlers: dict[str, list[dict]] = {}
    sinks: dict[str, list[dict]] = {}
    complete_hits: dict[str, list[dict]] = {}
    validation_hits: dict[str, list[dict]] = {}
    checklist_hits: list[dict] = []
    class_findings: list[tuple[str, dict]] = []

    for r in results:
        meta = (r.get("extra") or {}).get("metadata") or {}
        role = meta.get("probe_role")
        guard_class = meta.get("guard_class")
        path = r.get("path", "")
        if role == ROLE_HANDLER:
            handlers.setdefault(path, []).append(r)
        elif role == ROLE_SINK:
            sinks.setdefault(path, []).append(r)
        elif role == ROLE_COMPLETE_GUARD:
            complete_hits.setdefault(path, []).append(r)
        elif role == ROLE_INTERVENING:
            validation_hits.setdefault(path, []).append(r)
        elif role == ROLE_CHECKLIST or meta.get("tier") == "checklist":
            checklist_hits.append(r)
        elif guard_class:
            class_findings.append((str(guard_class), r))
        # Results with neither probe_role nor guard_class are foreign to
        # the pack and ignored by the pipeline.

    # Build sites: one per handler extent, then attach sinks, probes, and
    # class findings whose lines fall inside the extent.
    sites: dict[tuple[str, int, int], _Site] = {}
    sites_by_path: dict[str, list[_Site]] = {}
    lines_cache: dict[str, list[str] | None] = {}

    def site_for(path: str, line: int) -> _Site | None:
        best: _Site | None = None
        for s in sites_by_path.get(path, ()):
            if s.start_line <= line <= s.end_line:
                if best is None or (s.end_line - s.start_line) < (
                    best.end_line - best.start_line
                ):
                    best = s
        return best

    for path, hs in handlers.items():
        for h in hs:
            start, end = _extent(h)
            key = (path, start, end)
            if key not in sites:
                site = _Site(
                    path=path,
                    start_line=start,
                    end_line=end,
                    label=_function_hint(h, root, lines_cache),
                    test_path=is_test_path(path),
                )
                sites[key] = site
                sites_by_path.setdefault(path, []).append(site)

    sinks_outside_handlers: list[dict] = []
    for path, ss in sinks.items():
        for s in ss:
            loc = _loc(s)
            site = site_for(path, loc["line"])
            if site is None:
                sinks_outside_handlers.append(loc)
            elif loc not in site.sinks:
                site.sinks.append(loc)
                site.sink_results.append(s)

    for path, hs in complete_hits.items():
        for h in hs:
            loc = _loc(h)
            site = site_for(path, loc["line"])
            if site is not None and loc not in [
                _loc(r) for r in site.complete_guard_results
            ]:
                site.complete_guard_results.append(h)

    for path, vs in validation_hits.items():
        for v in vs:
            loc = _loc(v)
            site = site_for(path, loc["line"])
            if site is not None and loc not in [
                _loc(r) for r in site.validation_results
            ]:
                site.validation_results.append(v)

    for cls, f in class_findings:
        loc = _loc(f)
        site = site_for(f.get("path", ""), loc["line"])
        if site is None:
            # A deterministic finding outside every recognized handler
            # extent still must not go silent: give it a synthetic site
            # spanning the finding itself.
            start, end = _extent(f)
            site = _Site(
                path=f.get("path", ""),
                start_line=start,
                end_line=end,
                label=_function_hint(f, root, lines_cache),
                test_path=is_test_path(f.get("path", "")),
            )
            # The finding's own call is the site's sink for binding:
            # guard arguments must overlap its first-argument identifiers.
            site.sink_arg_idents = _first_arg_idents(
                _hit_text(f, root, lines_cache)
            )
            sites[site.key] = site
            sites_by_path.setdefault(site.path, []).append(site)
        if cls == NO_GUARD_CLASS:
            site.has_raw_no_guard = True
            if loc not in site.no_guard_locations:
                site.no_guard_locations.append(loc)
        else:
            site.class_locations.setdefault(cls, [])
            if loc not in site.class_locations[cls]:
                site.class_locations[cls].append(loc)

    # Layered resolution per site (precedence: weak class > bound
    # recognized-complete > bound unrecognized-guard > raw no-guard).
    # Sites with a sink but no tainted handler-input flow are recorded,
    # not reported. Binding: probe hits only upgrade or downgrade a
    # no-guard site when their matched line shares an identifier with a
    # sink call's first argument, so a guard-shaped call on an unrelated
    # value can neither launder the site into recognized-complete nor
    # relabel it unrecognized-guard.
    for site in sites.values():
        if (
            not site.sinks
            and not site.class_locations
            and not site.has_raw_no_guard
        ):
            # Handler with no enumerated sink: a surface marker only.
            site.resolution = RESOLUTION_HANDLER_NO_SINK
            continue
        sink_args = site.sink_arg_idents or {
            ident
            for s in site.sink_results
            for ident in _first_arg_idents(
                _hit_text(s, root, lines_cache)
            )
        }

        def bound(results: list[dict]) -> bool:
            if not sink_args:
                return False
            return any(
                _text_idents(_hit_text(r, root, lines_cache)) & sink_args
                for r in results
            )

        if site.class_locations:
            site.resolution = RESOLUTION_DETERMINISTIC
        elif site.has_raw_no_guard:
            if bound(site.complete_guard_results):
                site.resolution = RESOLUTION_RECOGNIZED_COMPLETE
            elif bound(site.validation_results):
                site.resolution = RESOLUTION_UNRECOGNIZED
            else:
                site.class_locations[NO_GUARD_CLASS] = [
                    dict(s) for s in site.no_guard_locations
                ]
                site.resolution = RESOLUTION_DETERMINISTIC
        elif site.complete_guard_results:
            # No raw no-guard finding means the by-side-effect sanitizer
            # cleaned the tainted value itself; the guard vocabulary was
            # seen at this site.
            site.resolution = RESOLUTION_RECOGNIZED_COMPLETE
        else:
            site.resolution = RESOLUTION_NO_FLOW

    ordered_sites = sorted(sites.values(), key=lambda s: s.key)
    site_records = [s.to_record() for s in ordered_sites]

    # Checklist items, deduplicated by (class, path, line). Emitted when
    # anything SSRF-relevant was detected: a recognized handler, a network
    # sink, or a checklist candidate itself (KTD6 keeps wholly empty scans
    # quiet, and counting candidates keeps checklist-tier corpus instances
    # validatable per R17).
    checklist: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for r in checklist_hits:
        meta = (r.get("extra") or {}).get("metadata") or {}
        loc = _loc(r)
        key = (str(meta.get("guard_class") or "?"), loc["path"], loc["line"])
        if key in seen:
            continue
        seen.add(key)
        checklist.append(
            {
                "class": key[0],
                "path": loc["path"],
                "line": loc["line"],
                "verify": meta.get("verify") or "",
                "message": ((r.get("extra") or {}).get("message") or "").strip(),
                "test_path": is_test_path(loc["path"]),
            }
        )
    checklist.sort(key=lambda i: (class_sort_key(i["class"]), i["path"], i["line"]))

    # Coverage (R12). "MCP surface" for the verdict means recognized
    # handlers, network sinks, or checklist candidates -- all three are
    # SSRF-relevant evidence.
    scanned = (scan_data.get("paths") or {}).get("scanned") or []
    by_lang = Counter(_language_of(p) for p in scanned)

    handler_candidates = sum(len(v) for v in handlers.values())
    sinks_found = sum(len(v) for v in sinks.values())
    mcp_surface = (
        handler_candidates > 0 or sinks_found > 0 or bool(checklist)
    )

    parse_failures = [
        {
            "path": e.get("path") or "",
            "message": e.get("message") or str(e.get("type") or e),
        }
        for e in (scan_data.get("errors") or [])
        if isinstance(e, dict)
    ]

    # A scan that produced only errors analyzed nothing: "no MCP surface
    # detected" would claim the files were analyzed and clean, so an
    # all-failed run reports analysis_incomplete (the CLI maps that to
    # the operational-failure exit code).
    if mcp_surface:
        verdict = "surface_detected"
    elif not scanned and parse_failures:
        verdict = "analysis_incomplete"
    else:
        verdict = "no_mcp_surface_detected"

    by_resolution = Counter(s["resolution"] for s in site_records)

    coverage = {
        "files_scanned": {
            "total": len(scanned),
            **{lang: by_lang[lang] for lang in sorted(by_lang)},
        },
        "handler_candidates": handler_candidates,
        "sinks_found": sinks_found,
        "sinks_outside_recognized_handlers": sorted(
            sinks_outside_handlers, key=lambda l: (l["path"], l["line"])
        ),
        "parse_failures": parse_failures,
        "checklist_candidates": len(checklist),
        "target_ignore_files": list(target_ignore_files or []),
        "excluded_dirs": sorted(excluded_dirs or []),
        "sites": site_records,
        "sites_by_resolution": by_resolution,
        "verdict": verdict,
    }
    return {"sites": site_records, "checklist": checklist, "coverage": coverage}
