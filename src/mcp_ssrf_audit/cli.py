"""mcp-ssrf-audit command line interface."""

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-ssrf-audit",
        description=(
            "Classify SSRF guard completeness in MCP servers "
            "(G0-G10 taxonomy)."
        ),
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a local repository path")
    scan.add_argument("path", help="path to a cloned repository")
    scan.add_argument("--json", action="store_true", help="emit JSON output")

    cv = sub.add_parser("corpus-validate", help="run rules against the labeled corpus")
    cv.add_argument(
        "--corpus",
        default="corpus",
        help="path to the corpus directory (default: corpus/)",
    )
    cv.add_argument("--json", action="store_true", help="emit JSON output")

    args = parser.parse_args(argv)
    if args.version:
        from mcp_ssrf_audit import __version__

        print(__version__)
        return 0
    if args.command in ("scan", "corpus-validate"):
        print("not implemented", file=sys.stderr)
        return 2
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
