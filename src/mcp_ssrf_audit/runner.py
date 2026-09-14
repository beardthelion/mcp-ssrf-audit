"""Semgrep invocation and JSON parsing for mcp-ssrf-audit.

The runner owns the operational contract (R8, R15):

- one subprocess call: ``semgrep scan --config <packaged rules> --json``
- target-controlled ignore mechanisms are disabled: ``--no-git-ignore``
  stops git/gitignore handling and ``--x-ignore-semgrepignore-files``
  stops ``.semgrepignore`` files inside the target from hiding code.
  Only this tool's own exclude list applies.
- no target code is executed or installed, and the scan makes no network
  calls (``--metrics=off --disable-version-check``).
- semgrep's stderr is forwarded verbatim; a nonzero exit, an unparseable
  stdout, or a missing binary raises :class:`ScanError` which the CLI maps
  to exit code 2. Semgrep's top-level ``errors`` array on a successful
  run is left in the parsed JSON for the coverage summary to consume.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Directories the tool always excludes (R15). Both the bare directory name
# and a nested-path glob are passed; semgrep treats --exclude patterns with
# gitignore-style syntax, and the belt-and-suspenders pair keeps the
# exclusion working regardless of how the pattern is resolved.
DEFAULT_EXCLUDES = (
    "node_modules",
    "dist",
    "build",
    "vendor",
    "vendors",
    "third_party",
    "third-party",
    "venv",
    ".venv",
)

# Ignore-file names a scanned repo may ship. They are never honored (the
# flags above defeat them, and --disable-nosem defeats inline
# ``# nosemgrep`` suppression comments) but their presence is surfaced in
# the coverage summary so an evasion attempt is visible rather than
# silent.
TARGET_IGNORE_FILENAMES = (".semgrepignore", ".gitignore")

DEFAULT_TIMEOUT = 30.0

# Wall-clock bound on the whole semgrep subprocess. The --timeout flag
# passed to semgrep limits per-rule-per-file analysis only; a hung engine
# (pathological file, engine bug) would otherwise block run_scan
# forever. Generous on purpose: large monorepo scans are legitimate.
DEFAULT_PROCESS_TIMEOUT = 1800.0

_IGNORE_WALK_SKIP_DIRS = frozenset(DEFAULT_EXCLUDES) | {".git", "__pycache__"}


class ScanError(Exception):
    """Operational failure: missing binary, nonzero exit, bad JSON."""


@dataclass
class ScanRun:
    """Parsed result of one semgrep invocation."""

    data: dict
    semgrep_version: str | None
    rules_dir: Path
    target: Path
    # .semgrepignore/.gitignore files present inside the target (ignored by
    # the scan, reported in coverage).
    target_ignore_files: list[str] = field(default_factory=list)
    # Directories matching DEFAULT_EXCLUDES present in the target (skipped
    # by the scan, reported in coverage so hiding code under
    # vendor/dist/build/node_modules is visible).
    excluded_dirs: list[str] = field(default_factory=list)
    # True when the ignore/excluded listing hit its cap and was cut short.
    ignore_list_truncated: bool = False


def default_rules_dir() -> Path:
    """Locate the rule tree.

    The wheel force-includes ``rules/`` as ``mcp_ssrf_audit/rules`` (KTD3);
    in a source checkout the canonical tree is the repo-root ``rules/``.
    """
    try:
        import importlib.resources as resources

        packaged = resources.files("mcp_ssrf_audit") / "rules"
        if packaged.is_dir():
            return Path(str(packaged))
    except Exception:
        pass
    # src/mcp_ssrf_audit/runner.py -> parents[2] is the repo root.
    checkout = Path(__file__).resolve().parents[2] / "rules"
    if checkout.is_dir():
        return checkout
    raise ScanError(
        "cannot locate the packaged rule tree (looked for "
        "mcp_ssrf_audit/rules package data and a repo-root rules/ directory)"
    )


def build_command(
    target: Path, rules_dir: Path, timeout: float
) -> list[str]:
    cmd = [
        "semgrep",
        "scan",
        "--config",
        str(rules_dir),
        "--json",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--disable-nosem",
        "--metrics=off",
        "--disable-version-check",
        "--timeout",
        f"{timeout:g}",
    ]
    for name in DEFAULT_EXCLUDES:
        cmd += ["--exclude", name]
        cmd += ["--exclude", f"*/{name}/*"]
    cmd.append(str(target))
    return cmd


_WALK_CAP = 200


def find_target_controlled_files(
    target: Path,
) -> tuple[list[str], list[str], bool]:
    """Walk the target and list ignore files plus tool-excluded dirs.

    Returns ``(ignore_files, excluded_dirs, truncated)``. The ignore files
    are never honored (the scan flags defeat them); both lists exist so an
    evasion attempt -- a .semgrepignore, or code tucked under
    node_modules/dist/vendor -- is visible in coverage rather than
    silent. The walk respects the same exclude dirs so a vendored
    node_modules tree does not make this quadratic, and stops at
    ``_WALK_CAP`` total entries with ``truncated`` set.
    """
    ignore_files: list[str] = []
    excluded: list[str] = []
    truncated = False
    if target.is_file():
        return ignore_files, excluded, truncated
    try:
        for dirpath, dirnames, filenames in os.walk(target):
            kept = []
            for d in dirnames:
                if d in _IGNORE_WALK_SKIP_DIRS:
                    if d in DEFAULT_EXCLUDES:
                        try:
                            excluded.append(
                                str(Path(dirpath, d).relative_to(target))
                            )
                        except ValueError:
                            excluded.append(str(Path(dirpath) / d))
                else:
                    kept.append(d)
            dirnames[:] = kept
            for name in filenames:
                if name in TARGET_IGNORE_FILENAMES:
                    p = Path(dirpath) / name
                    try:
                        ignore_files.append(str(p.relative_to(target)))
                    except ValueError:
                        ignore_files.append(str(p))
            if len(ignore_files) + len(excluded) >= _WALK_CAP:
                truncated = True
                break
    except OSError:
        pass
    return sorted(ignore_files), sorted(excluded), truncated


def run_scan(
    target: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    process_timeout: float = DEFAULT_PROCESS_TIMEOUT,
    rules_dir: str | Path | None = None,
) -> ScanRun:
    """Run semgrep over ``target`` and return the parsed JSON payload.

    ``timeout`` bounds semgrep's per-rule-per-file analysis time (the
    ``--timeout`` flag). ``process_timeout`` is the wall-clock bound on
    the whole subprocess so a hung engine cannot block the caller.

    Raises :class:`ScanError` on any operational failure (caller maps to
    exit code 2).
    """
    target = Path(target)
    if not target.exists():
        raise ScanError(f"scan target does not exist: {target}")
    if timeout <= 0:
        raise ScanError(
            f"--timeout must be positive seconds, got {timeout}"
        )
    rules = Path(rules_dir) if rules_dir is not None else default_rules_dir()
    cmd = build_command(target, rules, timeout)
    env = dict(os.environ, SEMGREP_SEND_METRICS="off")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=process_timeout,
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(
            f"semgrep did not finish within {process_timeout:g}s "
            "(engine-level timeout)"
        ) from exc
    except FileNotFoundError as exc:
        raise ScanError(
            "semgrep executable not found on PATH; install the "
            "mcp-ssrf-audit package dependencies (semgrep>=1.177)"
        ) from exc
    except OSError as exc:
        raise ScanError(f"failed to launch semgrep: {exc}") from exc

    # Forward semgrep's own stderr so parse errors and warnings stay
    # visible to the operator.
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        if not proc.stderr.endswith("\n"):
            sys.stderr.write("\n")

    if proc.returncode != 0:
        raise ScanError(
            f"semgrep exited with status {proc.returncode}"
        )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScanError(
            f"semgrep stdout was not parseable JSON: {exc}"
        ) from exc
    if not isinstance(data, dict) or "results" not in data:
        raise ScanError("semgrep JSON output has no 'results' field")

    ignore_files, excluded_dirs, truncated = find_target_controlled_files(
        target
    )
    if truncated:
        ignore_files.append("... (listing truncated)")
    return ScanRun(
        data=data,
        semgrep_version=data.get("version"),
        rules_dir=rules,
        target=target,
        target_ignore_files=ignore_files,
        excluded_dirs=excluded_dirs,
        ignore_list_truncated=truncated,
    )
