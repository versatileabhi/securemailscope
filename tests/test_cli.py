"""
Tests — CLI behaviour.

Phase 0 acceptance criteria:
  - `python -m securemailscope --version` exits 0 and prints '0.1.0'.
  - `python -m securemailscope status` exits 0.
  - Status output contains 'Analysis Mode: offline'.
  - Status output contains 'Core Analysis: not implemented'.
"""

from __future__ import annotations

import subprocess
import sys

from securemailscope.cli import main


def test_version_flag_exits_zero() -> None:
    """--version must exit with code 0."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_version_flag_prints_version() -> None:
    """--version must print '0.1.0' in output."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "--version"],
        capture_output=True,
        text=True,
    )
    assert "0.1.0" in result.stdout


def test_status_exits_zero() -> None:
    """status command must exit with code 0."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "status"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_status_contains_analysis_mode() -> None:
    """Status output must contain 'Analysis Mode: offline'."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "status"],
        capture_output=True,
        text=True,
    )
    assert "Analysis Mode: offline" in result.stdout


def test_status_contains_core_analysis_not_implemented() -> None:
    """Status output must contain 'Core Analysis: not implemented'."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "status"],
        capture_output=True,
        text=True,
    )
    assert "Core Analysis: not implemented" in result.stdout


def test_status_contains_dashboard_not_implemented() -> None:
    """Status output must contain 'Dashboard: not implemented'."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "status"],
        capture_output=True,
        text=True,
    )
    assert "Dashboard: not implemented" in result.stdout


def test_status_contains_ml_not_implemented() -> None:
    """Status output must contain 'ML Model: not implemented'."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "status"],
        capture_output=True,
        text=True,
    )
    assert "ML Model: not implemented" in result.stdout


def test_status_contains_current_phase() -> None:
    """Status output must contain 'Current Phase: 3'."""
    result = subprocess.run(
        [sys.executable, "-m", "securemailscope", "status"],
        capture_output=True,
        text=True,
    )
    assert "Current Phase: 3" in result.stdout


def test_main_status_returns_zero() -> None:
    """main(['status']) must return 0 when called programmatically."""
    assert main(["status"]) == 0


def test_main_no_args_returns_zero() -> None:
    """main([]) must return 0 (prints help) when called with no args."""
    assert main([]) == 0
