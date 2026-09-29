"""
SecureMailScope — Minimal CLI (Phase 0: version/help/status only).

Phase 0 scope:
  securemailscope --version
  securemailscope --help
  securemailscope status

All analysis, ingestion, dashboard, and ML commands are reserved for
later phases and will raise UnsupportedPhaseError if invoked.
"""

from __future__ import annotations

import argparse
import sys

from securemailscope import __version__
from securemailscope.constants import (
    CURRENT_PHASE,
    DEFAULT_ANALYSIS_MODE,
    PROJECT_NAME,
)


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="securemailscope",
        description=(
            f"{PROJECT_NAME} — AI-Assisted Cryptographic Security Posture "
            "Assessment for Secure Email Communications.\n"
            "Current State: Phase 0 — Foundation Only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROJECT_NAME} {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser(
        "status",
        help="Print current project status and component availability.",
    )
    return parser


def _print_status() -> None:
    """Print the current project status to stdout."""
    print(f"Project: {PROJECT_NAME}")
    print(f"Version: {__version__}")
    print(f"Analysis Mode: {DEFAULT_ANALYSIS_MODE}")
    print(f"Current Phase: {CURRENT_PHASE}")
    print("Core Analysis: not implemented")
    print("Dashboard: not implemented")
    print("ML Model: not implemented")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the securemailscope CLI.

    Args:
        argv: Optional argument list (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 on success).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        _print_status()
        return 0

    if args.command is None:
        parser.print_help()
        return 0

    # Unreachable in Phase 0 — all known commands handled above.
    parser.error(f"Unknown command: {args.command!r}")
    return 1  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
