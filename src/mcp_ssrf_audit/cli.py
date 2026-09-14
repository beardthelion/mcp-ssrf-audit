"""mcp-ssrf-audit command line interface.

`scan <path>` runs the semgrep rule pack over a local repository, resolves
each network-sink site against the G0-G10 taxonomy, and prints findings,
then the manual-audit checklist, then the coverage summary. Exit codes
(KTD4): 2 operational failure, 1 when any deterministic finding or
unrecognized-guard item is present, 0 otherwise.
"""

from __future__ import annotations

import argparse
import sys

from mcp_ssrf_audit import __version__
from mcp_ssrf_audit import classify, corpus, report, runner


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        run = runner.run_scan(args.path, timeout=args.timeout)
    except runner.ScanError as exc:
        print(f"mcp-ssrf-audit: {exc}", file=sys.stderr)
        return 2

    result = classify.classify_results(
        run.data,
        target_ignore_files=run.target_ignore_files,
        target_root=run.target,
    )
    if args.json:
        sys.stdout.write(
            report.render_json(
                result,
                ruleset_version=__version__,
                semgrep_version=run.semgrep_version,
                target=str(run.target),
            )
        )
    else:
        sys.stdout.write(
            report.render_text(
                result,
                ruleset_version=__version__,
                semgrep_version=run.semgrep_version,
                target=str(run.target),
            )
        )
    return report.exit_code(result)


def _cmd_corpus_validate(args: argparse.Namespace) -> int:
    try:
        rep = corpus.validate_corpus(args.corpus, timeout=args.timeout)
    except corpus.CorpusError as exc:
        print(f"mcp-ssrf-audit: {exc}", file=sys.stderr)
        return 2
    except runner.ScanError as exc:
        print(f"mcp-ssrf-audit: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.write(corpus.render_json(rep, ruleset_version=__version__))
    else:
        sys.stdout.write(corpus.render_text(rep, ruleset_version=__version__))
    return corpus.exit_code(rep)


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
    scan.add_argument(
        "--timeout",
        type=float,
        default=runner.DEFAULT_TIMEOUT,
        help="per-file semgrep analysis timeout in seconds (default: %(default)s)",
    )

    cv = sub.add_parser("corpus-validate", help="run rules against the labeled corpus")
    cv.add_argument(
        "--corpus",
        default="corpus",
        help="path to the corpus directory (default: corpus/)",
    )
    cv.add_argument("--json", action="store_true", help="emit JSON output")
    cv.add_argument(
        "--timeout",
        type=float,
        default=runner.DEFAULT_TIMEOUT,
        help="per-file semgrep analysis timeout in seconds (default: %(default)s)",
    )

    args = parser.parse_args(argv)
    if args.version:
        print(__version__)
        return 0
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "corpus-validate":
        return _cmd_corpus_validate(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
