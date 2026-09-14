"""Unit tests for report.py rendering and exit-code mapping."""

import json

from mcp_ssrf_audit import report


def site(
    path="srv.py",
    start=10,
    end=14,
    resolution="deterministic",
    classes=("G0",),
    sinks=((13, 1),),
    guards=(),
    test_path=False,
):
    return {
        "path": path,
        "start_line": start,
        "end_line": end,
        "site": f"def fetch_{start}(url):",
        "resolution": resolution,
        "classes": list(classes),
        "class_locations": {
            c: [{"path": path, "line": start + 1, "col": 1}] for c in classes
        },
        "sinks": [{"path": path, "line": ln, "col": c} for ln, c in sinks],
        "guard_locations": [
            {"path": path, "line": ln, "col": c} for ln, c in guards
        ],
        "test_path": test_path,
    }


def result(sites=None, checklist=None, coverage=None):
    return {
        "sites": sites or [],
        "checklist": checklist or [],
        "coverage": coverage
        or {
            "files_scanned": {"total": 1, "python": 1},
            "handler_candidates": 0,
            "sinks_found": 0,
            "sinks_outside_recognized_handlers": [],
            "parse_failures": [],
            "target_ignore_files": [],
            "sites": sites or [],
            "sites_by_resolution": {},
            "verdict": "no_mcp_surface_detected",
        },
    }


def test_exit_code_clean():
    assert report.exit_code(result()) == 0


def test_exit_code_checklist_only_is_clean():
    r = result(
        checklist=[{"class": "G7", "path": "a.py", "line": 3, "verify": "v", "message": "", "test_path": False}]
    )
    assert report.exit_code(r) == 0


def test_exit_code_deterministic():
    r = result(sites=[site()])
    assert report.exit_code(r) == 1


def test_exit_code_unrecognized():
    r = result(sites=[site(resolution="unrecognized_guard", classes=())])
    assert report.exit_code(r) == 1


def test_exit_code_recognized_complete_is_clean():
    r = result(sites=[site(resolution="recognized_complete", classes=())])
    assert report.exit_code(r) == 0


def test_json_schema_versioned():
    r = result(sites=[site()])
    doc = report.build_json_report(
        r, ruleset_version="0.1.0", semgrep_version="1.177.0", target="/tmp/x"
    )
    for key in (
        "schema_version",
        "taxonomy_version",
        "ruleset_version",
        "semgrep_version",
        "findings",
        "checklist",
        "coverage",
    ):
        assert key in doc
    assert doc["ruleset_version"] == "0.1.0"
    assert doc["semgrep_version"] == "1.177.0"
    # JSON round-trips
    json.dumps(doc)
    assert doc["findings"][0]["classes"] == ["G0"]


def test_json_findings_exclude_recognized_complete():
    r = result(
        sites=[
            site(resolution="recognized_complete", classes=()),
            site(resolution="unrecognized_guard", classes=(), guards=((12, 1),)),
        ]
    )
    doc = report.build_json_report(
        r, ruleset_version="0.1.0", semgrep_version=None, target="t"
    )
    assert [f["resolution"] for f in doc["findings"]] == ["unrecognized_guard"]
    # recognized-complete is still named in coverage.sites
    resolutions = {s["resolution"] for s in doc["coverage"]["sites"]}
    assert "recognized_complete" in resolutions


def test_text_ordering_and_sections():
    r = result(
        sites=[
            site(classes=("G1",)),
            site(
                path="srv.py",
                start=30,
                end=36,
                resolution="unrecognized_guard",
                classes=(),
                guards=((31, 5),),
            ),
            site(
                path="srv.py",
                start=40,
                end=44,
                resolution="recognized_complete",
                classes=(),
            ),
        ],
        checklist=[
            {
                "class": "G7",
                "path": "srv.py",
                "line": 33,
                "verify": "pin it",
                "message": "",
                "test_path": False,
            }
        ],
        coverage={
            "files_scanned": {"total": 1, "python": 1},
            "handler_candidates": 3,
            "sinks_found": 3,
            "sinks_outside_recognized_handlers": [],
            "parse_failures": [],
            "target_ignore_files": [".semgrepignore"],
            "sites": [],
            "sites_by_resolution": {"deterministic": 1},
            "verdict": "surface_detected",
        },
    )
    text = report.render_text(
        r, ruleset_version="0.1.0", semgrep_version="1.177.0", target="/t"
    )
    i_find = text.index("Deterministic findings")
    i_unrec = text.index("Unrecognized guards")
    i_compl = text.index("Recognized-complete sites")
    i_check = text.index("Manual-audit checklist")
    i_cov = text.index("Coverage")
    assert i_find < i_unrec < i_compl < i_check < i_cov
    assert "[G1] scheme-only validation" in text
    assert "guard detected, shape unrecognized" in text
    assert "verify: pin it" in text
    assert "not honored" in text
    # recognized-complete rendered scoped to taxonomy/ruleset versions
    assert "known-complete shape set" in text
    assert "g0-g10/v1" in text
    assert "0.1.0" in text
    assert "verdict: MCP surface detected" in text


def test_text_no_surface_verdict():
    r = result()
    text = report.render_text(
        r, ruleset_version="0.1.0", semgrep_version="1.177.0", target="/t"
    )
    assert "verdict: no MCP surface detected" in text
    assert "  none" in text


def test_text_flags_test_path():
    r = result(sites=[site(path="tests/x.py", test_path=True)])
    text = report.render_text(
        r, ruleset_version="0.1.0", semgrep_version="1.177.0", target="/t"
    )
    assert "test/example path" in text
