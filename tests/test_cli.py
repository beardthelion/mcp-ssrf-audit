from mcp_ssrf_audit.cli import main


def test_version():
    assert main(["--version"]) == 0


def test_help_no_command():
    assert main([]) == 0
