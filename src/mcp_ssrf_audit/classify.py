"""Layered site resolution over raw semgrep results (KTD7, R13, R14, R16).

Raw semgrep results are inputs, not verdicts. This module groups them by
enclosing handler (the site) and resolves each site in precedence order:

1. a weak-class deterministic finding (any ``metadata.guard_class`` other
   than the no-guard class) wins; the raw no-guard finding at the same
   site is suppressed so a scheme-only site reports its weak class and
   never double-labels as G0;
2. otherwise a complete-guard probe hit yields recognized-complete;
3. otherwise an intervening-validation probe hit yields
   unrecognized-guard ("guard detected, shape unrecognized, manual
   review");
4. otherwise the site is a no-guard finding.

The module is data-driven off rule metadata: it reads
``metadata.guard_class`` and ``metadata.probe_role`` and never names a
rule id, so class rules added later integrate without code changes.
"""

from __future__ import annotations

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
    return {
        "path": result.get("path", ""),
        "line": result.get("start", {}).get("line", 0),
        "col": result.get("start", {}).get("col", 0),
    }


def _extent(result: dict) -> tuple[int, int]:
    start = result.get("start", {}).get("line", 0)
    end = result.get("end", {}).get("line", start)
    return start, end


def _function_hint(
    result: dict,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> str:
    """First line of the matched region, trimmed, for site labeling.

    Semgrep's JSON leaves ``extra.lines`` as "requires login", so the
    label line is read from the target file when a root is given. Each
    file's lines are loaded at most once per call into ``lines_cache``.
    """
    lines = ((result.get("extra") or {}).get("lines") or "").strip()
    if lines and lines != "requires login":
        return lines.splitlines()[0][:80]
    line_no = result.get("start", {}).get("line", 0)
    rel = result.get("path", "")
    # Semgrep reports paths as given on the command line: absolute targets
    # yield absolute result paths, relative targets yield cwd-relative
    # ones. Try both the raw path and the target-root join.
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
        file_lines = lines_cache[key]
        if file_lines is not None and 0 < line_no <= len(file_lines):
            return file_lines[line_no - 1].strip()[:80]
    return ""


@dataclass
class _Site:
    path: str
    start_line: int
    end_line: int
    label: str = ""
    sinks: list[dict] = field(default_factory=list)
    # guard_class -> list of finding locations at this site
    class_locations: dict[str, list[dict]] = field(default_factory=dict)
    has_raw_no_guard: bool = False
    no_guard_locations: list[dict] = field(default_factory=list)
    complete_guard_hits: list[dict] = field(default_factory=list)
    validation_hits: list[dict] = field(default_factory=list)
    resolution: str = ""
    test_path: bool = False

    @property
    def key(self) -> tuple[str, int, int]:
        return (self.path, self.start_line, self.end_line)

    @property
    def classes(self) -> list[str]:
        return sorted(self.class_locations)

    def to_record(self) -> dict:
        guards: list[dict] = []
        for loc in self.complete_guard_hits + self.validation_hits:
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
                cls: locs for cls, locs in sorted(self.class_locations.items())
            },
            "sinks": self.sinks,
            "guard_locations": guards,
            "test_path": self.test_path,
        }


def classify_results(
    scan_data: dict,
    *,
    target_ignore_files: list[str] | None = None,
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

    for path, hs in complete_hits.items():
        for h in hs:
            loc = _loc(h)
            site = site_for(path, loc["line"])
            if site is not None and loc not in site.complete_guard_hits:
                site.complete_guard_hits.append(loc)

    for path, vs in validation_hits.items():
        for v in vs:
            loc = _loc(v)
            site = site_for(path, loc["line"])
            if site is not None and loc not in site.validation_hits:
                site.validation_hits.append(loc)

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

    # Layered resolution per site (precedence: weak class > recognized
    # complete > unrecognized guard > no guard). Sites with a sink but no
    # tainted handler-input flow are recorded, not reported.
    for site in sites.values():
        if not site.sinks and not site.class_locations and not site.has_raw_no_guard:
            # Handler with no enumerated sink: a surface marker only.
            site.resolution = RESOLUTION_HANDLER_NO_SINK
            continue
        if site.class_locations:
            site.resolution = RESOLUTION_DETERMINISTIC
        elif site.has_raw_no_guard:
            if site.complete_guard_hits:
                site.resolution = RESOLUTION_RECOGNIZED_COMPLETE
            elif site.validation_hits:
                site.resolution = RESOLUTION_UNRECOGNIZED
            else:
                site.class_locations[NO_GUARD_CLASS] = [
                    dict(s) for s in site.no_guard_locations
                ]
                site.resolution = RESOLUTION_DETERMINISTIC
        elif site.complete_guard_hits:
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
    # handlers or network sinks; checklist emission additionally counts
    # checklist candidates as surface evidence.
    scanned = (scan_data.get("paths") or {}).get("scanned") or []
    by_lang = Counter(_language_of(p) for p in scanned)

    handler_candidates = sum(len(v) for v in handlers.values())
    sinks_found = sum(len(v) for v in sinks.values())
    mcp_surface = handler_candidates > 0 or sinks_found > 0

    parse_failures = [
        {
            "path": e.get("path") or "",
            "message": e.get("message") or str(e.get("type") or e),
        }
        for e in (scan_data.get("errors") or [])
    ]

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
        "sites": site_records,
        "sites_by_resolution": by_resolution,
        "verdict": (
            "surface_detected" if mcp_surface else "no_mcp_surface_detected"
        ),
    }
    return {"sites": site_records, "checklist": checklist, "coverage": coverage}
