"""Unit tests for classify.py layered site resolution (KTD7).

All inputs are synthetic semgrep JSON payloads; no semgrep invocation.
"""

from mcp_ssrf_audit.classify import classify_results, is_test_path


def mk_result(check_id, path, start, end=None, metadata=None, message=""):
    """Build a synthetic semgrep result entry."""
    if end is None:
        end = start
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start, "col": 1, "offset": 0},
        "end": {"line": end, "col": 1, "offset": 0},
        "extra": {
            "message": message,
            "severity": "INFO",
            "metadata": metadata or {},
            "lines": f"def handler_{start}(url):",
        },
    }


def handler(path, start, end):
    return mk_result(
        "probe.handler", path, start, end, {"probe_role": "handler_source"}
    )


def sink(path, line):
    return mk_result("probe.sink", path, line, metadata={"probe_role": "network_sink"})


def complete(path, line):
    return mk_result(
        "probe.complete", path, line, metadata={"probe_role": "complete_guard"}
    )


def validation(path, line):
    return mk_result(
        "probe.validation",
        path,
        line,
        metadata={"probe_role": "intervening_validation"},
    )


def finding(cls, path, line):
    return mk_result("rules.python.some-weak-rule", path, line, metadata={"guard_class": cls})


def checklist_hit(cls, path, line, verify="verify thing"):
    return mk_result(
        "rules.checklist.cand",
        path,
        line,
        metadata={"guard_class": cls, "tier": "checklist", "probe_role": "checklist", "verify": verify},
    )


def scan(results, scanned=None, errors=None):
    return {
        "version": "1.177.0",
        "results": results,
        "errors": errors or [],
        "paths": {"scanned": scanned or []},
    }


def test_g0_site_no_probes():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 14),
                sink("srv.py", 13),
                finding("G0", "srv.py", 13),
            ],
            scanned=["srv.py"],
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G0"]
    assert site["sinks"] == [{"path": "srv.py", "line": 13, "col": 1}]


def test_weak_class_suppresses_g0():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 16),
                sink("srv.py", 15),
                finding("G0", "srv.py", 15),
                finding("G1", "srv.py", 12),
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G1"]
    assert "G0" not in site["class_locations"]


def test_multi_class_site():
    # R14: a site carries a set of classes.
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 20),
                sink("srv.py", 19),
                finding("G0", "srv.py", 19),
                finding("G2", "srv.py", 12),
                finding("G6", "srv.py", 18),
                finding("G2", "srv.py", 12),  # duplicate line dedups
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G2", "G6"]
    assert len(site["class_locations"]["G2"]) == 1


def test_weak_class_beats_complete_probe():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 20),
                sink("srv.py", 19),
                finding("G0", "srv.py", 19),
                finding("G1", "srv.py", 12),
                complete("srv.py", 11),
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G1"]


def test_recognized_complete():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 14),
                sink("srv.py", 13),
                finding("G0", "srv.py", 13),
                complete("srv.py", 12),
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "recognized_complete"
    assert site["classes"] == []


def test_recognized_complete_without_raw_finding():
    # by-side-effect sanitizer cleaned the derived local: no raw G0, but
    # the complete-guard probe still resolves the site.
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 14),
                sink("srv.py", 13),
                complete("srv.py", 12),
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "recognized_complete"


def test_unrecognized_guard():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 14),
                sink("srv.py", 13),
                finding("G0", "srv.py", 13),
                validation("srv.py", 12),
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "unrecognized_guard"
    assert site["guard_locations"] == [{"path": "srv.py", "line": 12, "col": 1}]


def test_sink_with_no_tainted_flow():
    result = classify_results(
        scan([handler("srv.py", 10, 14), sink("srv.py", 13)])
    )
    [site] = result["sites"]
    assert site["resolution"] == "no_handler_input_flow"


def test_handler_without_sink_is_surface_only():
    result = classify_results(scan([handler("srv.py", 10, 14)]))
    [site] = result["sites"]
    assert site["resolution"] == "handler_no_sink"
    assert result["coverage"]["handler_candidates"] == 1


def test_sink_outside_handler_listed_in_coverage():
    result = classify_results(
        scan([handler("srv.py", 10, 14), sink("srv.py", 13), sink("util.py", 5)])
    )
    assert result["coverage"]["sinks_found"] == 2
    outside = result["coverage"]["sinks_outside_recognized_handlers"]
    assert outside == [{"path": "util.py", "line": 5, "col": 1}]


def test_orphan_class_finding_gets_synthetic_site():
    # A deterministic finding outside every handler extent still resolves.
    result = classify_results(scan([finding("G2", "odd.py", 7)]))
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G2"]


def test_two_sinks_one_site_grouped():
    # R16 dedup: two sinks sharing one guarded site produce one site
    # record naming both sink locations.
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 16),
                sink("srv.py", 14),
                sink("srv.py", 15),
                finding("G0", "srv.py", 14),
                finding("G0", "srv.py", 15),
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G0"]
    assert {s["line"] for s in site["sinks"]} == {14, 15}


def test_nested_handler_extent_prefers_innermost():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 30),
                handler("srv.py", 15, 20),
                sink("srv.py", 18),
                finding("G0", "srv.py", 18),
            ]
        )
    )
    inner = [s for s in result["sites"] if s["start_line"] == 15][0]
    outer = [s for s in result["sites"] if s["start_line"] == 10][0]
    assert inner["resolution"] == "deterministic"
    assert outer["resolution"] == "handler_no_sink"


def test_checklist_quiet_on_empty_scan():
    # Wholly empty scan: no checklist (KTD6).
    result = classify_results(scan([], scanned=["readme.md"]))
    assert result["checklist"] == []
    assert result["coverage"]["verdict"] == "no_mcp_surface_detected"


def test_checklist_candidate_counts_as_surface_for_emission():
    # A checklist candidate alone (e.g. a resolver call in a guard-util
    # file with no handler or sink in the scanned slice) still emits, so
    # checklist-tier corpus instances stay validatable (R17). Checklist
    # evidence is itself MCP surface: the verdict must not claim "no MCP
    # surface detected" next to a nonempty checklist.
    result = classify_results(scan([checklist_hit("G7", "x.py", 3)]))
    assert len(result["checklist"]) == 1
    assert result["coverage"]["verdict"] == "surface_detected"


def test_checklist_emitted_with_surface():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 14),
                sink("srv.py", 13),
                checklist_hit("G7", "srv.py", 12, verify="pin it"),
                checklist_hit("G7", "srv.py", 12, verify="pin it"),
                checklist_hit("G10", "srv.py", 13),
            ]
        )
    )
    items = result["checklist"]
    assert [(i["class"], i["line"]) for i in items] == [("G7", 12), ("G10", 13)]
    assert items[0]["verify"] == "pin it"


def test_coverage_counts_and_verdict():
    result = classify_results(
        scan(
            [handler("a.py", 1, 5), sink("a.py", 3)],
            scanned=["a.py", "b.ts", "c.js", "d.txt"],
            errors=[{"path": "d.txt", "message": "parse error"}],
        )
    )
    cov = result["coverage"]
    assert cov["files_scanned"] == {
        "total": 4,
        "javascript": 1,
        "other": 1,
        "python": 1,
        "typescript": 1,
    }
    assert cov["parse_failures"] == [{"path": "d.txt", "message": "parse error"}]
    assert cov["verdict"] == "surface_detected"


def test_empty_scan_verdict():
    result = classify_results(scan([], scanned=["readme.md"]))
    cov = result["coverage"]
    assert cov["verdict"] == "no_mcp_surface_detected"
    assert cov["files_scanned"]["total"] == 1
    assert result["sites"] == []
    assert result["checklist"] == []


def test_target_ignore_files_surfaced():
    result = classify_results(
        scan([handler("a.py", 1, 5)], scanned=["a.py"]),
        target_ignore_files=[".semgrepignore"],
    )
    assert result["coverage"]["target_ignore_files"] == [".semgrepignore"]


def test_test_path_flagged_not_dropped():
    result = classify_results(
        scan(
            [
                handler("tests/x.py", 10, 14),
                sink("tests/x.py", 13),
                finding("G0", "tests/x.py", 13),
            ]
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["test_path"] is True


def test_is_test_path():
    assert is_test_path("src/tests/test_server.py")
    assert is_test_path("pkg/__tests__/x.ts")
    assert is_test_path("examples/demo/server.py")
    assert is_test_path("lib/foo.spec.ts")
    assert is_test_path("lib/foo_test.py")
    assert not is_test_path("src/server.py")
    assert not is_test_path("src/contest.py")


def mk_result_with_lines(check_id, path, start, lines, metadata=None):
    """Result whose matched source text is supplied explicitly."""
    r = mk_result(check_id, path, start, metadata=metadata)
    r["extra"]["lines"] = lines
    return r


def test_unrelated_complete_guard_does_not_launder_site():
    # A guard-shaped call on an unrelated value in the same handler must
    # not launder a raw unguarded fetch into recognized-complete.
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 16),
                mk_result_with_lines(
                    "probe.sink",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"probe_role": "network_sink"},
                ),
                mk_result_with_lines(
                    "rules.python.g0",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"guard_class": "G0"},
                ),
                mk_result_with_lines(
                    "probe.complete",
                    "srv.py",
                    12,
                    '    base = pinned_request("https://example.com")',
                    {"probe_role": "complete_guard"},
                ),
            ],
            scanned=["srv.py"],
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G0"]


def test_bound_complete_guard_resolves_recognized():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 16),
                mk_result_with_lines(
                    "probe.sink",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"probe_role": "network_sink"},
                ),
                mk_result_with_lines(
                    "rules.python.g0",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"guard_class": "G0"},
                ),
                mk_result_with_lines(
                    "probe.complete",
                    "srv.py",
                    12,
                    "    url = ensure_public_url(url)",
                    {"probe_role": "complete_guard"},
                ),
            ],
            scanned=["srv.py"],
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "recognized_complete"


def test_unrelated_validation_probe_does_not_downgrade():
    # A check on an unrelated identifier is not evidence of URL
    # validation; the site stays G0 rather than unrecognized-guard.
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 16),
                mk_result_with_lines(
                    "probe.sink",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"probe_role": "network_sink"},
                ),
                mk_result_with_lines(
                    "rules.python.g0",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"guard_class": "G0"},
                ),
                mk_result_with_lines(
                    "probe.validation",
                    "srv.py",
                    12,
                    "    check_quota(user_id)",
                    {"probe_role": "intervening_validation"},
                ),
            ],
            scanned=["srv.py"],
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G0"]


def test_bound_validation_probe_is_unrecognized():
    result = classify_results(
        scan(
            [
                handler("srv.py", 10, 16),
                mk_result_with_lines(
                    "probe.sink",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"probe_role": "network_sink"},
                ),
                mk_result_with_lines(
                    "rules.python.g0",
                    "srv.py",
                    15,
                    "    return requests.get(url).text",
                    {"guard_class": "G0"},
                ),
                mk_result_with_lines(
                    "probe.validation",
                    "srv.py",
                    12,
                    "    url = check_allowlist(url)",
                    {"probe_role": "intervening_validation"},
                ),
            ],
            scanned=["srv.py"],
        )
    )
    [site] = result["sites"]
    assert site["resolution"] == "unrecognized_guard"


def test_null_result_locations_do_not_crash():
    # Malformed semgrep records (start/end null or missing) degrade to
    # line 0 rather than AttributeError.
    r = mk_result("rules.python.g0", "srv.py", 5, metadata={"guard_class": "G0"})
    r["start"] = None
    r["end"] = None
    result = classify_results(scan([r], scanned=["srv.py"]))
    [site] = result["sites"]
    assert site["resolution"] == "deterministic"
    assert site["classes"] == ["G0"]


def test_all_errors_no_scanned_is_analysis_incomplete():
    result = classify_results(
        scan([], scanned=[], errors=[{"path": "a.py", "message": "boom"}])
    )
    assert result["coverage"]["verdict"] == "analysis_incomplete"


def test_errors_with_scanned_files_keep_surface_verdict():
    result = classify_results(
        scan(
            [handler("a.py", 1, 5)],
            scanned=["a.py"],
            errors=[{"path": "b.py", "message": "parse error"}],
        )
    )
    assert result["coverage"]["verdict"] == "surface_detected"
    assert result["coverage"]["parse_failures"] == [
        {"path": "b.py", "message": "parse error"}
    ]


def test_excluded_dirs_surfaced_in_coverage():
    result = classify_results(
        scan([handler("a.py", 1, 5)], scanned=["a.py"]),
        excluded_dirs=["vendor", "dist"],
    )
    assert result["coverage"]["excluded_dirs"] == ["dist", "vendor"]


def test_sites_sorted_by_path_line():
    result = classify_results(
        scan(
            [
                handler("b.py", 1, 5),
                sink("b.py", 3),
                finding("G0", "b.py", 3),
                handler("a.py", 10, 15),
                sink("a.py", 13),
                finding("G0", "a.py", 13),
            ]
        )
    )
    assert [(s["path"], s["start_line"]) for s in result["sites"]] == [
        ("a.py", 10),
        ("b.py", 1),
    ]
