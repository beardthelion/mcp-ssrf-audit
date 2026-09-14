"""End-to-end scan tests against the committed fixture targets.

These drive the real semgrep subprocess through cli.main, so they also
guard the fixture trees under tests/fixtures/ against going stale.
"""

import shutil
from pathlib import Path

import pytest

from mcp_ssrf_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures"

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep binary not on PATH"
)


def test_scan_unguarded_python_reports_g0(capsys):
    code = main(["scan", str(FIXTURES / "g0" / "unguarded-python")])
    assert code == 1
    assert "[G0]" in capsys.readouterr().out


def test_scan_unguarded_typescript_reports_class(capsys):
    # The fixture's fetch follows redirects, so KTD7 precedence resolves
    # the site to G6 rather than the suppressed raw G0.
    code = main(["scan", str(FIXTURES / "g0" / "unguarded-typescript")])
    assert code == 1
    assert "[G6]" in capsys.readouterr().out


def test_scan_complete_guard_python_clean(capsys):
    code = main(["scan", str(FIXTURES / "g0" / "complete-guard-python")])
    assert code == 0
    out = capsys.readouterr().out
    assert "[G0]" not in out
    assert "recognized-complete" in out or "Recognized-complete" in out


def test_scan_unrecognized_guard(capsys):
    code = main(["scan", str(FIXTURES / "cli" / "unrecognized-guard-python")])
    assert code == 1
    assert "shape unrecognized" in capsys.readouterr().out


def test_scan_empty_dir_reports_no_surface(capsys, tmp_path):
    code = main(["scan", str(tmp_path)])
    assert code == 0
    assert "no MCP surface detected" in capsys.readouterr().out


def test_scan_missing_target_fails():
    assert main(["scan", str(FIXTURES / "does-not-exist")]) == 2


def test_scan_vendored_dir_excluded(capsys):
    code = main(["scan", str(FIXTURES / "cli" / "vendored-skip")])
    assert code == 0
    assert "files scanned: 0" in capsys.readouterr().out


def test_scan_target_ignore_files_not_honored(capsys):
    # The fixture ships .gitignore/.semgrepignore contents that would hide
    # server.py; the tool must scan it anyway and surface the files.
    code = main(["scan", str(FIXTURES / "cli" / "ignore-evasion")])
    assert code == 1
    out = capsys.readouterr().out
    assert "ignore files present" in out or ".semgrepignore" in out
