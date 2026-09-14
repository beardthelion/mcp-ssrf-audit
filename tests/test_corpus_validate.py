"""Unit tests for corpus.py: the corpus-validate harness (R6, R17, R18).

Comparison/diff tests inject a fake ``scan_fn`` so no semgrep process is
needed. The smoke test at the bottom runs the real pipeline (runner +
classify + semgrep) against a tiny synthetic corpus directory.
"""

import json
from pathlib import Path

import pytest

from mcp_ssrf_audit import corpus
from mcp_ssrf_audit.cli import main


def write_corpus(tmp_path: Path, rows: list[dict], files: dict[str, str]):
    """Materialize a synthetic corpus dir under tmp_path/"corpus".

    ``rows`` are manifest dicts; ``files`` maps corpus-relative paths
    (e.g. "g0-x/vulnerable/srv.py") to file contents. Manifest
    ``corpus_paths`` are written as "corpus/<key>" to match the real
    manifest's repo-relative convention.
    """
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    for rel, content in files.items():
        p = corpus_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    manifest = corpus_dir / "manifest.jsonl"
    manifest.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n"
    )
    return corpus_dir


def mk_row(
    sample_id,
    corpus_paths,
    expected,
    *,
    tier="deterministic",
    source="vendored",
    language="python",
    instance_id=None,
):
    return {
        "sample_id": sample_id,
        "instance_id": instance_id or sample_id.split(":")[0],
        "repo": "example/repo",
        "sha": "0" * 40,
        "language": language,
        "expected": expected,
        "tier": tier,
        "source": source,
        "corpus_paths": corpus_paths,
        "paths": ["x.py"],
        "line_range": [1, 5],
        "advisory_refs": [],
        "license_spdx": "MIT",
        "last_verified": "2026-09-14",
        "fetched_with": None,
    }


def fake_scan(mapping):
    """scan_fn returning FileScans keyed by the file's name suffix."""

    def scan(path: Path) -> corpus.FileScan:
        for suffix, spec in mapping.items():
            if suffix in str(path):
                return corpus.FileScan(
                    classes=set(spec.get("classes", ())),
                    checklist=set(spec.get("checklist", ())),
                    unrecognized_sites=spec.get("unrecognized", 0),
                    semgrep_version="1.177.0",
                )
        return corpus.FileScan(semgrep_version="1.177.0")

    return scan


def sample(report, sample_id):
    return next(s for s in report["samples"] if s["sample_id"] == sample_id)


def test_caught_all_green(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("g0-x:vulnerable", ["corpus/g0-x/vulnerable/srv.py"], ["G0"])],
        {"g0-x/vulnerable/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": {"G0"}}})
    )
    s = sample(rep, "g0-x:vulnerable")
    assert s["status"] == "caught"
    assert rep["result"] == "pass"
    assert corpus.exit_code(rep) == 0


def test_forced_miss_gates(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("g1-x:vulnerable", ["corpus/g1-x/vulnerable/srv.py"], ["G1"])],
        {"g1-x/vulnerable/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": set()}})
    )
    s = sample(rep, "g1-x:vulnerable")
    assert s["status"] == "missed"
    assert s["missing"] == ["G1"]
    assert rep["summary"]["deterministic"]["missed"] == 1
    assert corpus.exit_code(rep) == 1


def test_multi_valued_expected_requires_all(tmp_path):
    row = mk_row(
        "g26-x:vulnerable", ["corpus/g26-x/vulnerable/srv.py"], ["G2", "G6"]
    )
    corpus_dir = write_corpus(
        tmp_path, [row], {"g26-x/vulnerable/srv.py": "x"}
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": {"G2"}}})
    )
    s = sample(rep, "g26-x:vulnerable")
    assert s["status"] == "missed"
    assert s["missing"] == ["G6"]
    assert corpus.exit_code(rep) == 1

    rep2 = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": {"G2", "G6"}}})
    )
    assert sample(rep2, "g26-x:vulnerable")["status"] == "caught"
    assert corpus.exit_code(rep2) == 0


def test_multi_file_row_union(tmp_path):
    # Expected classes may be split across the row's files; the union
    # across corpus_paths is what is compared.
    row = mk_row(
        "g-multi:vulnerable",
        ["corpus/g-multi/vulnerable/a.py", "corpus/g-multi/vulnerable/b.py"],
        ["G2", "G6"],
    )
    corpus_dir = write_corpus(
        tmp_path,
        [row],
        {"g-multi/vulnerable/a.py": "x", "g-multi/vulnerable/b.py": "y"},
    )
    rep = corpus.validate_corpus(
        corpus_dir,
        scan_fn=fake_scan(
            {"a.py": {"classes": {"G2"}}, "b.py": {"classes": {"G6"}}}
        ),
    )
    s = sample(rep, "g-multi:vulnerable")
    assert s["status"] == "caught"
    assert s["files"][0]["classes"] == ["G2"]
    assert s["files"][1]["classes"] == ["G6"]


def test_extra_class_is_misclassified_not_gating(tmp_path):
    # Plan text: exit nonzero on miss or precision failure. An extra
    # deterministic class on a non-CLEAN row is reported as
    # misclassified-extra but does not fail the run.
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("g1-x:vulnerable", ["corpus/g1-x/vulnerable/srv.py"], ["G1"])],
        {"g1-x/vulnerable/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir,
        scan_fn=fake_scan({"srv.py": {"classes": {"G1", "G6"}}}),
    )
    s = sample(rep, "g1-x:vulnerable")
    assert s["status"] == "misclassified-extra"
    assert s["extra"] == ["G6"]
    assert rep["summary"]["deterministic"]["misclassified_extra"] == 1
    assert corpus.exit_code(rep) == 0


def test_clean_precision_failure_gates(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("clean-x:guarded", ["corpus/clean-x/guarded/srv.py"], ["CLEAN"])],
        {"clean-x/guarded/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": {"G0"}}})
    )
    s = sample(rep, "clean-x:guarded")
    assert s["status"] == "precision-failure"
    assert rep["summary"]["deterministic"]["precision_failure"] == 1
    assert corpus.exit_code(rep) == 1


def test_clean_pass(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("clean-x:guarded", ["corpus/clean-x/guarded/srv.py"], ["CLEAN"])],
        {"clean-x/guarded/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": set()}})
    )
    assert sample(rep, "clean-x:guarded")["status"] == "clean"
    assert corpus.exit_code(rep) == 0


def test_unrecognized_guard_is_note_not_finding(tmp_path):
    # An unrecognized-guard site on a CLEAN row is manual-review signal,
    # not a deterministic finding: no precision failure.
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("clean-x:guarded", ["corpus/clean-x/guarded/srv.py"], ["CLEAN"])],
        {"clean-x/guarded/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir,
        scan_fn=fake_scan({"srv.py": {"unrecognized": 2}}),
    )
    s = sample(rep, "clean-x:guarded")
    assert s["status"] == "clean"
    assert any("unrecognized-guard" in n for n in s["notes"])
    assert corpus.exit_code(rep) == 0


def test_checklist_emitted_and_missing(tmp_path):
    rows = [
        mk_row(
            "chk-g7:vulnerable",
            ["corpus/chk-g7/vulnerable/srv.py"],
            ["G7"],
            tier="checklist",
        ),
        mk_row(
            "chk-g9:vulnerable",
            ["corpus/chk-g9/vulnerable/srv.py"],
            ["G9"],
            tier="checklist",
        ),
    ]
    corpus_dir = write_corpus(
        tmp_path,
        rows,
        {
            "chk-g7/vulnerable/srv.py": "x",
            "chk-g9/vulnerable/srv.py": "y",
        },
    )
    rep = corpus.validate_corpus(
        corpus_dir,
        scan_fn=fake_scan({"chk-g7": {"checklist": {"G7"}}}),
    )
    assert sample(rep, "chk-g7:vulnerable")["status"] == "checklist-emitted"
    s9 = sample(rep, "chk-g9:vulnerable")
    assert s9["status"] == "checklist-missing"
    assert s9["missing"] == ["G9"]
    # checklist rows never enter deterministic counts
    assert rep["summary"]["deterministic"]["total"] == 0
    assert rep["summary"]["checklist"]["missing"] == 1
    assert corpus.exit_code(rep) == 1


def test_checklist_all_emitted_passes(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [
            mk_row(
                "chk-g7:vulnerable",
                ["corpus/chk-g7/vulnerable/srv.py"],
                ["G7"],
                tier="checklist",
            )
        ],
        {"chk-g7/vulnerable/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"checklist": {"G7"}}})
    )
    assert sample(rep, "chk-g7:vulnerable")["status"] == "checklist-emitted"
    assert corpus.exit_code(rep) == 0


def test_checklist_clean_row_precision_failure(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [
            mk_row(
                "chk:patched",
                ["corpus/chk/patched/srv.py"],
                ["CLEAN"],
                tier="checklist",
            )
        ],
        {"chk/patched/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": {"G0"}}})
    )
    assert sample(rep, "chk:patched")["status"] == "precision-failure"
    assert rep["summary"]["checklist"]["precision_failure"] == 1
    assert corpus.exit_code(rep) == 1


def test_deterministic_extra_on_checklist_row_reported_not_gating(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [
            mk_row(
                "chk-g7:vulnerable",
                ["corpus/chk-g7/vulnerable/srv.py"],
                ["G7"],
                tier="checklist",
            )
        ],
        {"chk-g7/vulnerable/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir,
        scan_fn=fake_scan(
            {"srv.py": {"classes": {"G0"}, "checklist": {"G7"}}}
        ),
    )
    s = sample(rep, "chk-g7:vulnerable")
    assert s["status"] == "checklist-emitted"
    assert s["extra"] == ["G0"]
    assert any("extra-deterministic" in n for n in s["notes"])
    assert corpus.exit_code(rep) == 0


def test_unmaterialized_fetched_skipped(tmp_path):
    rows = [
        mk_row(
            "live-x:fetched",
            ["corpus/_fetched/live-x/srv.py"],
            ["G0"],
            source="fetched",
        ),
        mk_row("g0-y:vulnerable", ["corpus/g0-y/vulnerable/srv.py"], ["G0"]),
    ]
    corpus_dir = write_corpus(
        tmp_path, rows, {"g0-y/vulnerable/srv.py": "x"}
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": {"G0"}}})
    )
    assert rep["skipped"] == [
        {
            "sample_id": "live-x:fetched",
            "instance_id": "live-x",
            "tier": "deterministic",
            "reason": "not materialized",
            "missing": ["corpus/_fetched/live-x/srv.py"],
        }
    ]
    assert rep["summary"]["skipped"] == 1
    assert corpus.exit_code(rep) == 0


def test_vendored_missing_file_is_corpus_error(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("g0-x:vulnerable", ["corpus/g0-x/vulnerable/srv.py"], ["G0"])],
        {},
    )
    with pytest.raises(corpus.CorpusError, match="missing files"):
        corpus.validate_corpus(corpus_dir, scan_fn=fake_scan({}))


def test_missing_manifest_is_corpus_error(tmp_path):
    (tmp_path / "corpus").mkdir()
    with pytest.raises(corpus.CorpusError, match="manifest"):
        corpus.validate_corpus(tmp_path / "corpus", scan_fn=fake_scan({}))


def test_malformed_manifest_line(tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "manifest.jsonl").write_text("{not json}\n")
    with pytest.raises(corpus.CorpusError, match="invalid JSON"):
        corpus.validate_corpus(corpus_dir, scan_fn=fake_scan({}))


def test_bad_expected_label_rejected(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("bad:x", ["corpus/bad/x.py"], ["GX"])],
        {"bad/x.py": "x"},
    )
    with pytest.raises(corpus.CorpusError, match="expected"):
        corpus.validate_corpus(corpus_dir, scan_fn=fake_scan({}))


def test_output_is_deterministic(tmp_path):
    rows = [
        mk_row("b:vulnerable", ["corpus/b/vulnerable/srv.py"], ["G0"]),
        mk_row("a:vulnerable", ["corpus/a/vulnerable/srv.py"], ["G1"]),
    ]
    corpus_dir = write_corpus(
        tmp_path,
        rows,
        {"a/vulnerable/srv.py": "x", "b/vulnerable/srv.py": "y"},
    )
    scan = fake_scan(
        {"a/": {"classes": {"G1"}}, "b/": {"classes": {"G0"}}}
    )
    rep1 = corpus.validate_corpus(corpus_dir, scan_fn=scan)
    rep2 = corpus.validate_corpus(corpus_dir, scan_fn=scan)
    assert corpus.render_text(rep1, ruleset_version="0.1.0") == (
        corpus.render_text(rep2, ruleset_version="0.1.0")
    )
    # samples sorted by sample_id regardless of manifest order
    assert [s["sample_id"] for s in rep1["samples"]] == [
        "a:vulnerable",
        "b:vulnerable",
    ]


def test_render_json_shape(tmp_path):
    corpus_dir = write_corpus(
        tmp_path,
        [mk_row("g0-x:vulnerable", ["corpus/g0-x/vulnerable/srv.py"], ["G0"])],
        {"g0-x/vulnerable/srv.py": "x"},
    )
    rep = corpus.validate_corpus(
        corpus_dir, scan_fn=fake_scan({"srv.py": {"classes": {"G0"}}})
    )
    doc = json.loads(corpus.render_json(rep, ruleset_version="0.1.0"))
    assert doc["schema_version"] == corpus.SCHEMA_VERSION
    assert doc["ruleset_version"] == "0.1.0"
    assert doc["taxonomy_version"] == corpus.TAXONOMY_VERSION
    for key in ("samples", "skipped", "summary", "failures", "result"):
        assert key in doc


def test_text_sections_and_headings(tmp_path):
    rows = [
        mk_row("chk-g7:vulnerable", ["corpus/chk/v/s.py"], ["G7"], tier="checklist"),
        mk_row("g0-x:vulnerable", ["corpus/g0-x/v/s.py"], ["G0"]),
    ]
    corpus_dir = write_corpus(
        tmp_path,
        rows,
        {"chk/v/s.py": "x", "g0-x/v/s.py": "y"},
    )
    rep = corpus.validate_corpus(
        corpus_dir,
        scan_fn=fake_scan(
            {"chk/v": {"checklist": {"G7"}}, "g0-x": {"classes": {"G0"}}}
        ),
    )
    text = corpus.render_text(rep, ruleset_version="0.1.0")
    i_det = text.index("Deterministic samples")
    i_chk = text.index("Checklist-tier samples")
    i_skip = text.index("Skipped")
    i_sum = text.index("Summary")
    assert i_det < i_chk < i_skip < i_sum
    assert "manual verification required" in text
    # checklist sample must not appear in the deterministic section
    det_section = text[i_det:i_chk]
    assert "chk-g7:vulnerable" not in det_section
    assert "result: PASS" in text


# --- smoke test: real pipeline over a synthetic corpus dir ---

G0_FIXTURE = '''\
import requests

mcp = None


@mcp.tool()
async def fetch_tool(url: str) -> str:
    return requests.get(url).text
'''


def test_smoke_real_semgrep_caught(tmp_path, capsys):
    corpus_dir = write_corpus(
        tmp_path,
        [
            mk_row(
                "g0-smoke:vulnerable",
                ["corpus/g0-smoke/vulnerable/srv.py"],
                ["G0"],
            )
        ],
        {"g0-smoke/vulnerable/srv.py": G0_FIXTURE},
    )
    code = main(["corpus-validate", "--corpus", str(corpus_dir)])
    out = capsys.readouterr().out
    assert "g0-smoke:vulnerable" in out
    assert "caught" in out
    assert code == 0


def test_smoke_real_semgrep_forced_miss(tmp_path, capsys):
    corpus_dir = write_corpus(
        tmp_path,
        [
            mk_row(
                "g5-smoke:vulnerable",
                ["corpus/g5-smoke/vulnerable/srv.py"],
                ["G5"],
            )
        ],
        {"g5-smoke/vulnerable/srv.py": G0_FIXTURE},
    )
    code = main(["corpus-validate", "--corpus", str(corpus_dir)])
    out = capsys.readouterr().out
    assert "missed" in out
    assert "missing={G5}" in out
    assert code == 1
