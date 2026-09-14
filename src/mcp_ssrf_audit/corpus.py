"""Corpus-validation harness (F2, R6, R17, R18, KTD5).

``corpus-validate`` runs the packaged rule pack over every labeled corpus
sample in ``manifest.jsonl`` and compares the expected guard-class set to
the classes the scan pipeline (runner + classify) actually reports.

Evaluation semantics, per the plan:

- Each manifest row is a sample. Its ``expected`` set applies to the
  sample as a whole: an expected class is caught when it is attributed to
  at least one resolved site inside any of the sample's ``corpus_paths``
  files. Per-file attribution is reported for diff-ability.
- ``expected: ["CLEAN"]`` rows are first-class (R18): any deterministic
  finding class reported on any of the sample's files is a
  *precision failure*.
- Non-CLEAN deterministic rows: expected classes absent from the reported
  set are *missed*; reported deterministic classes outside the expected
  set are *misclassified-extra*. Per the plan's gating rule ("exit
  nonzero on any miss or precision failure"), a misclassified-extra is
  reported but does not fail the run.
- ``tier: "checklist"`` rows are validated by checklist emission (R17):
  the row passes when its expected checklist classes appear in the
  emitted manual-audit checklist for the sample's files. Checklist rows
  are reported under their own heading and never mixed into the
  deterministic pass/fail counts. A missing checklist emission fails the
  run (the corpus is not fully green). A ``CLEAN`` checklist-tier row is
  evaluated on the same precision semantics as a deterministic CLEAN row.
- Deterministic findings on a non-CLEAN checklist row are reported as
  ``extra-deterministic`` on the sample line (same non-gating treatment
  as misclassified-extra).
- ``unrecognized_guard`` site resolutions are not deterministic findings:
  they are counted and shown as notes (manual review), never as misses or
  precision failures.
- Fetched samples whose files are not materialized under
  ``corpus/_fetched/`` are skipped with an explicit line pointing at
  ``scripts/fetch_corpus.py``. Skips are not failures. A vendored sample
  with missing files is a corpus-integrity error (exit 2).

Exit codes (KTD4 conventions extended to the harness): 0 fully green,
1 any missed expected class, any CLEAN precision failure, or any missing
checklist emission, 2 operational failure (bad corpus, missing manifest,
semgrep failure). Output ordering is deterministic (samples sorted by
sample_id, files sorted by path, classes sorted numerically).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from mcp_ssrf_audit import classify, runner

SCHEMA_VERSION = "mcp-ssrf-audit-corpus/v1"
TAXONOMY_VERSION = "g0-g10/v1"

MANIFEST_NAME = "manifest.jsonl"
CLEAN = "CLEAN"

STATUS_CAUGHT = "caught"
STATUS_MISSED = "missed"
STATUS_EXTRA = "misclassified-extra"
STATUS_CLEAN = "clean"
STATUS_PRECISION = "precision-failure"
STATUS_CHECKLIST_EMITTED = "checklist-emitted"
STATUS_CHECKLIST_MISSING = "checklist-missing"

_REQUIRED_FIELDS = (
    "sample_id",
    "instance_id",
    "repo",
    "sha",
    "language",
    "expected",
    "tier",
    "source",
)
_VALID_TIERS = ("deterministic", "checklist")
_VALID_SOURCES = ("vendored", "fetched")


class CorpusError(Exception):
    """Operational failure: bad corpus layout, manifest, or scan."""


def _class_sort_key(cls: str) -> tuple[int, str]:
    if len(cls) > 1 and cls[1:].isdigit():
        return (int(cls[1:]), cls)
    return (10**6, cls)


def _sorted_classes(classes) -> list[str]:
    return sorted(classes, key=_class_sort_key)


def _fmt_set(classes) -> str:
    return "{" + ",".join(_sorted_classes(classes)) + "}"


def load_manifest(corpus_dir: Path) -> list[dict]:
    """Parse and minimally validate ``<corpus_dir>/manifest.jsonl``."""
    manifest = corpus_dir / MANIFEST_NAME
    if not corpus_dir.is_dir():
        raise CorpusError(f"corpus directory does not exist: {corpus_dir}")
    if not manifest.is_file():
        raise CorpusError(f"corpus manifest not found: {manifest}")
    rows: list[dict] = []
    with manifest.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusError(
                    f"{manifest}:{lineno}: invalid JSON: {exc}"
                ) from exc
            _validate_row(row, manifest, lineno)
            rows.append(row)
    if not rows:
        raise CorpusError(f"{manifest}: no samples")
    return rows


def _validate_row(row: dict, manifest: Path, lineno: int) -> None:
    where = f"{manifest}:{lineno}"
    if not isinstance(row, dict):
        raise CorpusError(f"{where}: row is not a JSON object")
    for key in _REQUIRED_FIELDS:
        if key not in row:
            raise CorpusError(f"{where}: missing required field {key!r}")
    if row["tier"] not in _VALID_TIERS:
        raise CorpusError(
            f"{where}: tier must be one of {_VALID_TIERS}, "
            f"got {row['tier']!r}"
        )
    if row["source"] not in _VALID_SOURCES:
        raise CorpusError(
            f"{where}: source must be one of {_VALID_SOURCES}, "
            f"got {row['source']!r}"
        )
    expected = row["expected"]
    if not isinstance(expected, list) or not expected:
        raise CorpusError(f"{where}: expected must be a nonempty list")
    for cls in expected:
        if cls != CLEAN and not (
            isinstance(cls, str)
            and len(cls) > 1
            and cls[0] == "G"
            and cls[1:].isdigit()
        ):
            raise CorpusError(
                f"{where}: expected entries must be 'CLEAN' or 'G<N>', "
                f"got {cls!r}"
            )
    if CLEAN in expected and len(expected) > 1:
        raise CorpusError(f"{where}: CLEAN cannot be combined with G-classes")
    corpus_paths = row.get("corpus_paths")
    if not isinstance(corpus_paths, list) or not corpus_paths:
        raise CorpusError(f"{where}: corpus_paths must be a nonempty list")


def resolve_corpus_paths(
    corpus_dir: Path, row: dict
) -> list[tuple[str, Path | None]]:
    """Map a row's ``corpus_paths`` to on-disk files.

    Returns ``(display_path, resolved_path_or_None)`` pairs. Manifest paths
    are repo-relative (``corpus/<instance>/...``); they resolve against the
    corpus directory by stripping the leading ``corpus/`` component, with
    a fallback to the corpus dir's parent for layouts that keep the
    prefix literal. ``display_path`` is the manifest string, kept stable
    for output regardless of where the corpus lives.
    """
    out: list[tuple[str, Path | None]] = []
    for raw in row["corpus_paths"]:
        p = PurePosixPath(str(raw))
        parts = list(p.parts)
        rel = PurePosixPath(*parts[1:]) if parts and parts[0] == "corpus" else p
        candidates = [corpus_dir / rel, corpus_dir.parent / p]
        resolved = next((c for c in candidates if c.is_file()), None)
        out.append((str(p), resolved))
    return out


@dataclass
class FileScan:
    """What the pipeline reported for one corpus file."""

    classes: set[str] = field(default_factory=set)
    checklist: set[str] = field(default_factory=set)
    unrecognized_sites: int = 0
    semgrep_version: str | None = None


def scan_file(
    path: Path,
    *,
    timeout: float = runner.DEFAULT_TIMEOUT,
    rules_dir: str | Path | None = None,
) -> FileScan:
    """Scan one corpus file and reduce the classified result to sets.

    Reuses the scan pipeline verbatim: ``runner.run_scan`` for the semgrep
    invocation and ``classify.classify_results`` for site resolution.
    Corpus content is data to the engine only; it is never imported or
    executed.
    """
    run = runner.run_scan(path, timeout=timeout, rules_dir=rules_dir)
    result = classify.classify_results(
        run.data,
        target_ignore_files=run.target_ignore_files,
        target_root=run.target,
    )
    fs = FileScan(semgrep_version=run.semgrep_version)
    for site in result["sites"]:
        if site["resolution"] == "deterministic":
            fs.classes.update(site["classes"])
        elif site["resolution"] == "unrecognized_guard":
            fs.unrecognized_sites += 1
    for item in result["checklist"]:
        fs.checklist.add(item["class"])
    return fs


def _evaluate(
    row: dict,
    files: list[tuple[str, FileScan]],
) -> dict:
    """Compute the verdict record for one materialized sample."""
    expected = set(row["expected"])
    reported: set[str] = set()
    emitted: set[str] = set()
    unrecognized = 0
    for _path, fs in files:
        reported |= fs.classes
        emitted |= fs.checklist
        unrecognized += fs.unrecognized_sites

    missing = expected - reported
    extra = reported - expected
    notes: list[str] = []
    if unrecognized:
        notes.append(
            f"{unrecognized} unrecognized-guard site(s) "
            "(manual review, not a finding)"
        )

    if expected == {CLEAN}:
        status = STATUS_PRECISION if reported else STATUS_CLEAN
    elif row["tier"] == "checklist":
        checklist_missing = expected - emitted
        status = (
            STATUS_CHECKLIST_MISSING
            if checklist_missing
            else STATUS_CHECKLIST_EMITTED
        )
        if reported:
            notes.append(
                f"extra-deterministic={_fmt_set(reported)} "
                "(deterministic classes on a checklist-tier sample; "
                "reported, non-gating)"
            )
    else:
        if missing:
            status = STATUS_MISSED
        elif extra:
            status = STATUS_EXTRA
        else:
            status = STATUS_CAUGHT

    if expected == {CLEAN}:
        missing_set: set[str] = set()
    elif row["tier"] == "checklist":
        missing_set = expected - emitted
    else:
        missing_set = missing

    return {
        "sample_id": row["sample_id"],
        "instance_id": row["instance_id"],
        "repo": row["repo"],
        "sha": row["sha"],
        "language": row["language"],
        "tier": row["tier"],
        "source": row["source"],
        "expected": _sorted_classes(expected),
        "reported": _sorted_classes(reported),
        "checklist_emitted": _sorted_classes(emitted),
        "missing": _sorted_classes(missing_set),
        "extra": _sorted_classes(extra),
        "status": status,
        "notes": notes,
        "files": [
            {
                "path": path,
                "classes": _sorted_classes(fs.classes),
                "checklist": _sorted_classes(fs.checklist),
                "unrecognized_sites": fs.unrecognized_sites,
            }
            for path, fs in files
        ],
    }


def validate_corpus(
    corpus_dir: str | Path,
    *,
    timeout: float = runner.DEFAULT_TIMEOUT,
    rules_dir: str | Path | None = None,
    scan_fn=None,
) -> dict:
    """Run the rule pack over every materialized corpus sample.

    ``scan_fn`` is injectable for tests: it takes a ``Path`` and returns a
    :class:`FileScan`. The default is :func:`scan_file`, which drives the
    real runner/classify pipeline.
    """
    corpus_dir = Path(corpus_dir)
    rows = load_manifest(corpus_dir)
    if scan_fn is None:
        def scan_one(path: Path) -> FileScan:
            return scan_file(path, timeout=timeout, rules_dir=rules_dir)
    else:
        scan_one = scan_fn

    cache: dict[str, FileScan] = {}

    def scan_cached(path: Path) -> FileScan:
        key = str(path)
        if key not in cache:
            cache[key] = scan_one(path)
        return cache[key]

    samples: list[dict] = []
    skipped: list[dict] = []
    semgrep_version: str | None = None

    for row in sorted(rows, key=lambda r: r["sample_id"]):
        paths = resolve_corpus_paths(corpus_dir, row)
        missing_paths = [disp for disp, res in paths if res is None]
        if missing_paths:
            if row["source"] == "fetched":
                skipped.append(
                    {
                        "sample_id": row["sample_id"],
                        "instance_id": row["instance_id"],
                        "tier": row["tier"],
                        "reason": "not materialized",
                        "missing": sorted(missing_paths),
                    }
                )
                continue
            raise CorpusError(
                f"vendored sample {row['sample_id']} is missing files: "
                + ", ".join(missing_paths)
            )
        scans: list[tuple[str, FileScan]] = []
        try:
            for disp, res in sorted(paths, key=lambda t: t[0]):
                fs = scan_cached(res)
                semgrep_version = semgrep_version or fs.semgrep_version
                scans.append((disp, fs))
        except runner.ScanError as exc:
            raise CorpusError(
                f"scan failed for sample {row['sample_id']}: {exc}"
            ) from exc
        samples.append(_evaluate(row, scans))

    samples.sort(key=lambda s: s["sample_id"])
    skipped.sort(key=lambda s: s["sample_id"])

    det = [s for s in samples if s["tier"] == "deterministic"]
    chk = [s for s in samples if s["tier"] == "checklist"]

    def count(sample_list, status) -> int:
        return sum(1 for s in sample_list if s["status"] == status)

    # Per-class rollup (F2: misses and misclassifications reported per
    # class). Deterministic classes count caught/missed/extra across
    # non-CLEAN samples; checklist classes count emitted/missing.
    det_by_class: dict[str, dict] = {}
    for s in det:
        if s["expected"] == [CLEAN]:
            continue
        for cls in s["expected"]:
            d = det_by_class.setdefault(
                cls, {"expected": 0, "caught": 0, "missed": 0, "extra": 0}
            )
            d["expected"] += 1
            if cls in s["reported"]:
                d["caught"] += 1
            else:
                d["missed"] += 1
        for cls in s["extra"]:
            d = det_by_class.setdefault(
                cls, {"expected": 0, "caught": 0, "missed": 0, "extra": 0}
            )
            d["extra"] += 1
    chk_by_class: dict[str, dict] = {}
    for s in chk:
        if s["expected"] == [CLEAN]:
            continue
        for cls in s["expected"]:
            d = chk_by_class.setdefault(
                cls, {"expected": 0, "emitted": 0, "missing": 0}
            )
            d["expected"] += 1
            if cls in s["checklist_emitted"]:
                d["emitted"] += 1
            else:
                d["missing"] += 1

    summary = {
        "deterministic": {
            "total": len(det),
            "caught": count(det, STATUS_CAUGHT),
            "missed": count(det, STATUS_MISSED),
            "misclassified_extra": count(det, STATUS_EXTRA),
            "clean": count(det, STATUS_CLEAN),
            "precision_failure": count(det, STATUS_PRECISION),
            "by_class": {
                cls: det_by_class[cls] for cls in _sorted_classes(det_by_class)
            },
        },
        "checklist": {
            "total": len(chk),
            "emitted": count(chk, STATUS_CHECKLIST_EMITTED),
            "missing": count(chk, STATUS_CHECKLIST_MISSING),
            "clean": count(chk, STATUS_CLEAN),
            "precision_failure": count(chk, STATUS_PRECISION),
            "by_class": {
                cls: chk_by_class[cls] for cls in _sorted_classes(chk_by_class)
            },
        },
        "skipped": len(skipped),
        "manifest_samples": len(rows),
    }
    failures = (
        summary["deterministic"]["missed"]
        + summary["deterministic"]["precision_failure"]
        + summary["checklist"]["missing"]
        + summary["checklist"]["precision_failure"]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "taxonomy_version": TAXONOMY_VERSION,
        "corpus": str(corpus_dir),
        "semgrep_version": semgrep_version,
        "samples": samples,
        "skipped": skipped,
        "summary": summary,
        "failures": failures,
        "result": "fail" if failures else "pass",
    }


def exit_code(report: dict) -> int:
    """0 fully green, 1 any miss/precision-failure/checklist-miss."""
    return 1 if report["failures"] else 0


def _render_sample_line(sample: dict) -> list[str]:
    s = sample
    lines = []
    expected = (
        CLEAN if s["expected"] == [CLEAN] else _fmt_set(s["expected"])
    )
    if s["tier"] == "checklist" and s["expected"] != [CLEAN]:
        head = (
            f"  {s['status']:<19} {s['sample_id']:<52} "
            f"expected={expected:<10} emitted={_fmt_set(s['checklist_emitted'])}"
        )
    else:
        head = (
            f"  {s['status']:<19} {s['sample_id']:<52} "
            f"expected={expected:<10} reported={_fmt_set(s['reported'])}"
        )
    if s["missing"]:
        head += f" missing={_fmt_set(s['missing'])}"
    if s["extra"]:
        head += f" extra={_fmt_set(s['extra'])}"
    lines.append(head)
    for f in s["files"]:
        detail = f"      {f['path']}"
        parts = []
        if f["classes"]:
            parts.append(f"deterministic={_fmt_set(f['classes'])}")
        if f["checklist"]:
            parts.append(f"checklist={_fmt_set(f['checklist'])}")
        if f["unrecognized_sites"]:
            parts.append(
                f"unrecognized-guard-sites={f['unrecognized_sites']}"
            )
        if parts:
            detail += " -> " + " ".join(parts)
        else:
            detail += " -> {}"
        lines.append(detail)
    for note in s["notes"]:
        lines.append(f"      note: {note}")
    return lines


def render_text(report: dict, *, ruleset_version: str) -> str:
    out: list[str] = []
    version = report["semgrep_version"] or "unknown"
    out.append(
        f"mcp-ssrf-audit {ruleset_version} corpus-validate "
        f"(semgrep {version})"
    )
    n_det = report["summary"]["deterministic"]["total"]
    n_chk = report["summary"]["checklist"]["total"]
    out.append(
        f"corpus: {report['corpus']} "
        f"({report['summary']['manifest_samples']} manifest samples: "
        f"{n_det} deterministic, {n_chk} checklist, "
        f"{report['summary']['skipped']} skipped)"
    )
    out.append("")

    det = [s for s in report["samples"] if s["tier"] == "deterministic"]
    out.append("Deterministic samples")
    out.append("---------------------")
    if not det:
        out.append("  none")
    for s in det:
        out.extend(_render_sample_line(s))
    out.append("")

    chk = [s for s in report["samples"] if s["tier"] == "checklist"]
    out.append(
        "Checklist-tier samples (manual verification required; "
        "never counted in deterministic pass/fail)"
    )
    out.append(
        "----------------------------------------------------------------"
        "----------------"
    )
    if not chk:
        out.append("  none")
    for s in chk:
        out.extend(_render_sample_line(s))
    out.append("")

    out.append(
        "Skipped (not materialized; fetch via scripts/fetch_corpus.py)"
    )
    out.append("-------------------------------------------------------------")
    if not report["skipped"]:
        out.append("  none")
    for s in report["skipped"]:
        out.append(f"  skipped             {s['sample_id']}")
    out.append("")

    d = report["summary"]["deterministic"]
    c = report["summary"]["checklist"]
    out.append("Summary")
    out.append("-------")
    out.append(
        f"  deterministic: {d['total']} samples: {d['caught']} caught, "
        f"{d['missed']} missed, {d['misclassified_extra']} "
        f"misclassified-extra, {d['clean']} clean, "
        f"{d['precision_failure']} precision-failure"
    )
    out.append(
        f"  checklist:     {c['total']} samples: {c['emitted']} emitted, "
        f"{c['missing']} missing, {c['clean']} clean, "
        f"{c['precision_failure']} precision-failure"
    )
    if d["by_class"]:
        out.append("  deterministic by class:")
        for cls, bc in d["by_class"].items():
            out.append(
                f"    {cls}: expected={bc['expected']} caught={bc['caught']} "
                f"missed={bc['missed']} extra={bc['extra']}"
            )
    if c["by_class"]:
        out.append("  checklist by class:")
        for cls, bc in c["by_class"].items():
            out.append(
                f"    {cls}: expected={bc['expected']} emitted={bc['emitted']} "
                f"missing={bc['missing']}"
            )
    out.append(f"  skipped:       {report['summary']['skipped']}")
    if report["result"] == "pass":
        out.append("  result: PASS")
    else:
        out.append(f"  result: FAIL ({report['failures']} gating failure(s))")
    return "\n".join(out) + "\n"


def render_json(report: dict, *, ruleset_version: str) -> str:
    doc = dict(report)
    doc["ruleset_version"] = ruleset_version
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"
