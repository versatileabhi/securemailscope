"""
Tests — Phase 2 Zeek discovery and availability check.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from securemailscope.zeek.discovery import ZeekAvailability, discover_zeek


def test_discover_zeek_unavailable_when_shutil_which_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """discover_zeek returns available=False when Zeek is absent from PATH."""
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    avail = discover_zeek()
    assert isinstance(avail, ZeekAvailability)
    assert avail.available is False
    assert avail.executable_path is None
    assert avail.version is None
    assert "not found" in (avail.error or "")


def test_discover_zeek_missing_configured_path(tmp_path: Path) -> None:
    """Configured Zeek path that does not exist returns available=False safely."""
    missing_binary = tmp_path / "fake_zeek_nonexistent"
    avail = discover_zeek(configured_path=missing_binary)

    assert avail.available is False
    assert avail.version is None
    assert "not found" in (avail.error or "")


def test_discover_zeek_directory_configured_path(tmp_path: Path) -> None:
    """Configured Zeek path that is a directory returns available=False."""
    dir_path = tmp_path / "zeek_dir"
    dir_path.mkdir()

    avail = discover_zeek(configured_path=dir_path)
    assert avail.available is False
    assert avail.version is None
    assert "directory" in (avail.error or "")


def test_discover_zeek_calls_version_with_shell_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """discover_zeek must invoke [candidate, '--version'] with shell=False."""
    recorded_calls: list[dict] = []

    def mock_run(cmd, **kwargs):
        recorded_calls.append({"cmd": cmd, "kwargs": kwargs})
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="zeek version 6.0.4\n",
            stderr="",
        )

    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/zeek")
    monkeypatch.setattr("subprocess.run", mock_run)

    avail = discover_zeek()
    assert avail.available is True
    assert avail.version == "zeek version 6.0.4"
    assert avail.executable_path == "/usr/local/bin/zeek"

    assert len(recorded_calls) == 1
    call = recorded_calls[0]
    assert call["cmd"] == ["/usr/local/bin/zeek", "--version"]
    assert call["kwargs"].get("shell") is False
    assert call["kwargs"].get("capture_output") is True


def test_discover_zeek_version_non_zero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """discover_zeek returns available=False if --version exits non-zero."""
    def mock_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=127,
            stdout="",
            stderr="command not found or missing shared lib",
        )

    monkeypatch.setattr("shutil.which", lambda cmd: "/opt/zeek/bin/zeek")
    monkeypatch.setattr("subprocess.run", mock_run)

    avail = discover_zeek()
    assert avail.available is False
    assert avail.version is None
    assert "exited with code 127" in (avail.error or "")


def test_discover_zeek_timeout_handled_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """discover_zeek handles subprocess.TimeoutExpired without crashing."""
    def mock_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)

    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/zeek")
    monkeypatch.setattr("subprocess.run", mock_run)

    avail = discover_zeek(timeout_seconds=5)
    assert avail.available is False
    assert avail.version is None
    assert "timed out" in (avail.error or "")


def test_discover_zeek_oserror_handled_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """discover_zeek handles OSError (e.g. PermissionError or invalid binary)."""
    def mock_run(cmd, **kwargs):
        raise OSError("Exec format error")

    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/zeek")
    monkeypatch.setattr("subprocess.run", mock_run)

    avail = discover_zeek()
    assert avail.available is False
    assert "Failed to execute" in (avail.error or "")
