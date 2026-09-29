"""
Tests — Phase 2 offline Zeek runner and command construction.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from securemailscope.schemas.evidence import EvidenceMetadata
from securemailscope.schemas.zeek import PHASE_2_LIMITATIONS
from securemailscope.zeek.discovery import ZeekAvailability
from securemailscope.zeek.runner import (
    build_offline_zeek_command,
    run_zeek_offline,
)


@pytest.fixture()
def valid_evidence(tmp_path: Path) -> EvidenceMetadata:
    """Fixture providing an accepted Phase 1 evidence record with staged capture."""
    job_id = "job_20260929T120000Z_abcdef12"
    runtime_root = tmp_path / "runtime"
    upload_dir = runtime_root / "uploads" / job_id
    upload_dir.mkdir(parents=True)

    capture_file = upload_dir / "traffic.pcap"
    capture_file.write_bytes(b"\xd4\xc3\xb2\xa1synthetic-pcap-payload")

    return EvidenceMetadata(
        job_id=job_id,
        original_file_name="traffic.pcap",
        staged_file_name="traffic.pcap",
        extension=".pcap",
        file_size_bytes=len(capture_file.read_bytes()),
        sha256="abc123sha256digest",
        ingestion_timestamp_utc="2026-09-29T12:00:00Z",
        analysis_mode="offline",
        status="accepted",
    )


def test_build_offline_zeek_command_default(tmp_path: Path) -> None:
    """Default command uses -r, sets Log::default_logdir, excludes -C and -i."""
    staged = tmp_path / "capture.pcap"
    log_dir = tmp_path / "logs"

    cmd = build_offline_zeek_command(
        zeek_executable="/opt/zeek/bin/zeek",
        staged_capture_path=staged,
        log_directory=log_dir,
    )

    assert isinstance(cmd, tuple)
    assert cmd[0] == "/opt/zeek/bin/zeek"
    assert "-r" in cmd
    assert "-i" not in cmd
    assert "-C" not in cmd
    assert str(staged) in cmd
    assert f"Log::default_logdir={log_dir}" in cmd


def test_build_offline_zeek_command_with_checksum_override(tmp_path: Path) -> None:
    """Command includes -C only when ignore_invalid_ip_checksums is explicitly True."""
    staged = tmp_path / "capture.pcap"
    log_dir = tmp_path / "logs"

    cmd = build_offline_zeek_command(
        zeek_executable="zeek",
        staged_capture_path=staged,
        log_directory=log_dir,
        ignore_invalid_ip_checksums=True,
    )

    assert "-C" in cmd
    assert cmd.index("-C") < cmd.index("-r")


def test_runner_rejects_non_accepted_evidence(tmp_path: Path) -> None:
    """Runner returns invalid_evidence_reference if status is not 'accepted'."""
    evidence = EvidenceMetadata(
        job_id="job_invalid",
        original_file_name="bad.pcap",
        staged_file_name="bad.pcap",
        extension=".pcap",
        file_size_bytes=10,
        sha256="fakehash",
        ingestion_timestamp_utc="2026-09-29T12:00:00Z",
        status="rejected",  # Not accepted
    )

    result = run_zeek_offline(evidence, runtime_root_path=tmp_path / "runtime")
    assert result.status == "invalid_evidence_reference"
    assert result.zeek_available is False


def test_runner_rejects_non_offline_evidence(tmp_path: Path) -> None:
    """Runner returns invalid_evidence_reference if analysis_mode is not 'offline'."""
    evidence = EvidenceMetadata(
        job_id="job_invalid",
        original_file_name="bad.pcap",
        staged_file_name="bad.pcap",
        extension=".pcap",
        file_size_bytes=10,
        sha256="fakehash",
        ingestion_timestamp_utc="2026-09-29T12:00:00Z",
        analysis_mode="live",  # Not offline
        status="accepted",
    )

    result = run_zeek_offline(evidence, runtime_root_path=tmp_path / "runtime")
    assert result.status == "invalid_evidence_reference"


def test_runner_rejects_missing_staged_capture(tmp_path: Path) -> None:
    """Runner returns invalid_evidence_reference if staged file does not exist."""
    evidence = EvidenceMetadata(
        job_id="job_ghost",
        original_file_name="ghost.pcap",
        staged_file_name="ghost.pcap",
        extension=".pcap",
        file_size_bytes=10,
        sha256="fakehash",
        ingestion_timestamp_utc="2026-09-29T12:00:00Z",
        status="accepted",
    )

    result = run_zeek_offline(evidence, runtime_root_path=tmp_path / "runtime")
    assert result.status == "invalid_evidence_reference"
    assert "not found" in (result.stderr_summary or "")


def test_runner_zeek_unavailable_creates_no_log_directory(
    tmp_path: Path,
    valid_evidence: EvidenceMetadata,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runner returns zeek_unavailable and does not create log directory."""
    runtime_root = tmp_path / "runtime"
    monkeypatch.setattr(
        "securemailscope.zeek.runner.discover_zeek",
        lambda configured_path=None: ZeekAvailability(
            available=False,
            executable_path=None,
            version=None,
            error="Zeek binary not found",
        ),
    )

    result = run_zeek_offline(valid_evidence, runtime_root_path=runtime_root)
    assert result.status == "zeek_unavailable"
    assert result.zeek_available is False

    # Verify log directory was NOT created
    log_dir = runtime_root / "zeek_logs" / valid_evidence.job_id
    assert not log_dir.exists()


def test_runner_mocked_success(
    tmp_path: Path,
    valid_evidence: EvidenceMetadata,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mocked successful Zeek process returns status='completed' and exit_code=0."""
    runtime_root = tmp_path / "runtime"
    recorded_calls: list[dict] = []

    monkeypatch.setattr(
        "securemailscope.zeek.runner.discover_zeek",
        lambda configured_path=None: ZeekAvailability(
            available=True,
            executable_path="/usr/bin/zeek",
            version="zeek 6.0.4",
            error=None,
        ),
    )

    def mock_subprocess_run(cmd, **kwargs):
        recorded_calls.append({"cmd": cmd, "kwargs": kwargs})
        # Simulate Zeek producing a log file in cwd
        cwd = Path(kwargs["cwd"])
        (cwd / "conn.log").write_text("#separator \\x09\n", encoding="utf-8")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="processing complete",
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    result = run_zeek_offline(
        valid_evidence,
        runtime_root_path=runtime_root,
        timeout_seconds=60,
    )

    assert result.status == "completed"
    assert result.exit_code == 0
    assert result.zeek_available is True
    assert result.zeek_version == "zeek 6.0.4"
    assert result.timed_out is False
    assert result.log_directory_name == valid_evidence.job_id
    assert result.stdout_summary == "processing complete"

    # Limitations verified
    assert PHASE_2_LIMITATIONS[0] in result.limitations
    assert PHASE_2_LIMITATIONS[1] in result.limitations

    # Subprocess options verified
    assert len(recorded_calls) == 1
    call = recorded_calls[0]
    assert call["kwargs"]["shell"] is False
    assert call["kwargs"]["timeout"] == 60
    assert call["kwargs"]["cwd"] == runtime_root / "zeek_logs" / valid_evidence.job_id

    # Verify log file was preserved
    log_file = runtime_root / "zeek_logs" / valid_evidence.job_id / "conn.log"
    assert log_file.exists()


def test_runner_mocked_non_zero_exit(
    tmp_path: Path,
    valid_evidence: EvidenceMetadata,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mocked non-zero Zeek process returns status='failed' and exit_code."""
    runtime_root = tmp_path / "runtime"

    monkeypatch.setattr(
        "securemailscope.zeek.runner.discover_zeek",
        lambda configured_path=None: ZeekAvailability(
            available=True,
            executable_path="/usr/bin/zeek",
            version="zeek 6.0.4",
            error=None,
        ),
    )

    def mock_subprocess_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr="fatal error: failed to open trace file",
        )

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    result = run_zeek_offline(valid_evidence, runtime_root_path=runtime_root)
    assert result.status == "failed"
    assert result.exit_code == 1
    assert "fatal error" in (result.stderr_summary or "")


def test_runner_mocked_timeout(
    tmp_path: Path,
    valid_evidence: EvidenceMetadata,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mocked timeout returns status='timed_out' with timed_out=True."""
    runtime_root = tmp_path / "runtime"

    monkeypatch.setattr(
        "securemailscope.zeek.runner.discover_zeek",
        lambda configured_path=None: ZeekAvailability(
            available=True,
            executable_path="/usr/bin/zeek",
            version="zeek 6.0.4",
            error=None,
        ),
    )

    def mock_subprocess_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=cmd,
            timeout=10,
            output="partial output",
            stderr="process killed after timeout",
        )

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    result = run_zeek_offline(
        valid_evidence,
        runtime_root_path=runtime_root,
        timeout_seconds=10,
    )

    assert result.status == "timed_out"
    assert result.timed_out is True
    assert result.exit_code is None
    assert "process killed after timeout" in (result.stderr_summary or "")
