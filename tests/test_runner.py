"""Unit tests for runner.py: the semgrep subprocess boundary (R8, R15).

Subprocess behavior is tested with a mocked ``subprocess.run``; the
command-construction and target-walk tests need no semgrep at all.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_ssrf_audit import runner


def test_build_command_disables_target_evasion(tmp_path):
    cmd = runner.build_command(tmp_path, Path("/rules"), 30.0)
    assert "--no-git-ignore" in cmd
    assert "--x-ignore-semgrepignore-files" in cmd
    assert "--disable-nosem" in cmd
    assert "--metrics=off" in cmd
    assert "--disable-version-check" in cmd
    assert "--json" in cmd


def test_build_command_fractional_timeout(tmp_path):
    # A fractional --timeout must reach semgrep intact, not truncate to 0.
    cmd = runner.build_command(tmp_path, Path("/rules"), 0.5)
    i = cmd.index("--timeout")
    assert cmd[i + 1] == "0.5"


def test_run_scan_rejects_nonpositive_timeout(tmp_path):
    with pytest.raises(runner.ScanError, match="positive"):
        runner.run_scan(tmp_path, timeout=0)
    with pytest.raises(runner.ScanError, match="positive"):
        runner.run_scan(tmp_path, timeout=-3)


def test_run_scan_missing_target(tmp_path):
    with pytest.raises(runner.ScanError, match="does not exist"):
        runner.run_scan(tmp_path / "nope")


def _proc(stdout="{}", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["semgrep"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_process_timeout_becomes_scan_error(tmp_path):
    with patch.object(
        runner.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=1),
    ):
        with pytest.raises(runner.ScanError, match="did not finish"):
            runner.run_scan(tmp_path, rules_dir="/rules")


def test_process_timeout_forwarded_to_subprocess(tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return _proc(stdout='{"results": [], "errors": [], "paths": {}}')

    with patch.object(runner.subprocess, "run", side_effect=fake_run):
        runner.run_scan(tmp_path, rules_dir="/rules", process_timeout=7)
    assert captured["timeout"] == 7
    assert captured["errors"] == "replace"


def test_nonzero_exit_is_scan_error(tmp_path):
    with patch.object(
        runner.subprocess, "run", return_value=_proc(returncode=3)
    ):
        with pytest.raises(runner.ScanError, match="status 3"):
            runner.run_scan(tmp_path, rules_dir="/rules")


def test_malformed_json_is_scan_error(tmp_path):
    with patch.object(
        runner.subprocess, "run", return_value=_proc(stdout="{oops")
    ):
        with pytest.raises(runner.ScanError, match="not parseable JSON"):
            runner.run_scan(tmp_path, rules_dir="/rules")


def test_missing_results_field_is_scan_error(tmp_path):
    with patch.object(
        runner.subprocess, "run", return_value=_proc(stdout="[]")
    ):
        with pytest.raises(runner.ScanError, match="results"):
            runner.run_scan(tmp_path, rules_dir="/rules")


def test_walk_lists_ignore_files_and_excluded_dirs(tmp_path):
    (tmp_path / ".semgrepignore").write_text("x\n")
    (tmp_path / ".gitignore").write_text("y\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / ".gitignore").write_text("z\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / ".semgrepignore").write_text("w\n")

    ignore_files, excluded, truncated = runner.find_target_controlled_files(
        tmp_path
    )
    assert ignore_files == [".gitignore", ".semgrepignore", "src/.semgrepignore"]
    assert excluded == ["node_modules"]
    assert truncated is False


def test_walk_truncation_marks_listing(tmp_path):
    for i in range(runner._WALK_CAP + 5):
        d = tmp_path / f"d{i}"
        d.mkdir()
        (d / ".gitignore").write_text("x\n")

    ignore_files, _excluded, truncated = runner.find_target_controlled_files(
        tmp_path
    )
    assert truncated is True
    assert len(ignore_files) == runner._WALK_CAP


def test_run_scan_appends_truncation_marker(tmp_path):
    for i in range(runner._WALK_CAP + 5):
        d = tmp_path / f"d{i}"
        d.mkdir()
        (d / ".gitignore").write_text("x\n")

    def fake_run(cmd, **kwargs):
        return _proc(stdout='{"results": [], "errors": [], "paths": {}}')

    with patch.object(runner.subprocess, "run", side_effect=fake_run):
        run = runner.run_scan(tmp_path, rules_dir="/rules")
    assert run.ignore_list_truncated is True
    assert run.target_ignore_files[-1] == "... (listing truncated)"
