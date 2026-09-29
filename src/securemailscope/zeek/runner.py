"""
SecureMailScope — Offline Zeek runner.

Executes Zeek in an isolated local directory against Phase 1 staged captures
using passive file-reading flags (-r) only.
"""

from __future__ import annotations

import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from securemailscope.paths import (
    ensure_within_directory,
    ensure_within_runtime,
    job_zeek_log_dir,
    runtime_root,
)
from securemailscope.schemas.evidence import EvidenceMetadata
from securemailscope.schemas.zeek import ZeekRunResult
from securemailscope.zeek.discovery import discover_zeek

MAX_SUMMARY_LENGTH: int = 2000


def build_offline_zeek_command(
    *,
    zeek_executable: str | Path,
    staged_capture_path: Path,
    log_directory: Path,
    ignore_invalid_ip_checksums: bool = False,
) -> tuple[str, ...]:
    """Construct a safe, offline-only Zeek command argument list.

    Args:
        zeek_executable: Path or name of Zeek binary.
        staged_capture_path: Path to staged PCAP/PCAPNG file.
        log_directory: Target directory for Zeek log files.
        ignore_invalid_ip_checksums: If True, adds -C to ignore checksum errors.

    Returns:
        Tuple of string arguments ready for subprocess execution.
    """
    cmd: list[str] = [str(zeek_executable)]

    # -C is an analyst-controlled compatibility option for packet captures
    # with hardware checksum offloading; it is omitted by default.
    if ignore_invalid_ip_checksums:
        cmd.append("-C")

    # -r forces offline file reading; no live interface (-i) is ever permitted.
    cmd.extend([
        "-r",
        str(staged_capture_path),
        f"Log::default_logdir={log_directory}",
    ])

    return tuple(cmd)


def run_zeek_offline(
    evidence: EvidenceMetadata,
    *,
    zeek_path: str | Path | None = None,
    runtime_root_path: Path | None = None,
    timeout_seconds: int = 120,
    ignore_invalid_ip_checksums: bool = False,
    now_utc: datetime | None = None,
) -> ZeekRunResult:
    """Run Zeek offline against an accepted Phase 1 evidence capture.

    Args:
        evidence: EvidenceMetadata record from Phase 1.
        zeek_path: Optional explicit path to Zeek executable.
        runtime_root_path: Optional override for runtime directory root.
        timeout_seconds: Process execution timeout in seconds.
        ignore_invalid_ip_checksums: If True, passes -C to Zeek.
        now_utc: Optional override for current UTC timestamp.

    Returns:
        ZeekRunResult record documenting the process execution outcome.
    """
    if now_utc is None:
        effective_utc = datetime.now(UTC)
    elif now_utc.tzinfo is None:
        effective_utc = now_utc.replace(tzinfo=UTC)
    else:
        effective_utc = now_utc.astimezone(UTC)

    started_at_str = effective_utc.isoformat()

    # 1. Validate EvidenceMetadata
    is_valid_evidence = (
        isinstance(evidence, EvidenceMetadata)
        and evidence.status == "accepted"
        and evidence.analysis_mode == "offline"
        and bool(evidence.job_id)
        and "/" not in evidence.job_id
        and "\\" not in evidence.job_id
        and evidence.job_id not in (".", "..")
    )
    if not is_valid_evidence:
        return ZeekRunResult(
            job_id=getattr(evidence, "job_id", "invalid_job"),
            status="invalid_evidence_reference",
            zeek_available=False,
            zeek_version=None,
            command=(),
            log_directory_name=None,
            started_at_utc=started_at_str,
            completed_at_utc=started_at_str,
            duration_seconds=0.0,
            exit_code=None,
            timed_out=False,
            ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
            stdout_summary=None,
            stderr_summary="Invalid or rejected EvidenceMetadata provided.",
        )

    root = runtime_root(runtime_root_path)

    # 2. Locate and verify staged capture file
    upload_job_dir = (root / "uploads" / evidence.job_id).resolve()
    try:
        ensure_within_runtime(upload_job_dir, root)
    except Exception as exc:
        return ZeekRunResult(
            job_id=evidence.job_id,
            status="invalid_evidence_reference",
            zeek_available=False,
            zeek_version=None,
            command=(),
            log_directory_name=None,
            started_at_utc=started_at_str,
            completed_at_utc=started_at_str,
            duration_seconds=0.0,
            exit_code=None,
            timed_out=False,
            ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
            stdout_summary=None,
            stderr_summary=f"Staged upload path containment failure: {exc}",
        )

    staged_capture_path = (upload_job_dir / evidence.staged_file_name).resolve()
    try:
        ensure_within_directory(staged_capture_path, upload_job_dir)
    except Exception as exc:
        return ZeekRunResult(
            job_id=evidence.job_id,
            status="invalid_evidence_reference",
            zeek_available=False,
            zeek_version=None,
            command=(),
            log_directory_name=None,
            started_at_utc=started_at_str,
            completed_at_utc=started_at_str,
            duration_seconds=0.0,
            exit_code=None,
            timed_out=False,
            ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
            stdout_summary=None,
            stderr_summary=f"Staged capture path containment violation: {exc}",
        )

    if not staged_capture_path.exists() or not staged_capture_path.is_file():
        return ZeekRunResult(
            job_id=evidence.job_id,
            status="invalid_evidence_reference",
            zeek_available=False,
            zeek_version=None,
            command=(),
            log_directory_name=None,
            started_at_utc=started_at_str,
            completed_at_utc=started_at_str,
            duration_seconds=0.0,
            exit_code=None,
            timed_out=False,
            ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
            stdout_summary=None,
            stderr_summary=(
                f"Staged capture file not found: {staged_capture_path.name}"
            ),
        )

    # 3. Discover Zeek binary
    zeek_info = discover_zeek(configured_path=zeek_path)
    if not zeek_info.available or zeek_info.executable_path is None:
        return ZeekRunResult(
            job_id=evidence.job_id,
            status="zeek_unavailable",
            zeek_available=False,
            zeek_version=None,
            command=(),
            log_directory_name=None,
            started_at_utc=started_at_str,
            completed_at_utc=started_at_str,
            duration_seconds=0.0,
            exit_code=None,
            timed_out=False,
            ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
            stdout_summary=None,
            stderr_summary=zeek_info.error or "Zeek executable unavailable.",
        )

    # 4. Prepare isolated output directory (only after Zeek is confirmed available)
    log_dir = job_zeek_log_dir(evidence.job_id, root)
    log_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_offline_zeek_command(
        zeek_executable=zeek_info.executable_path,
        staged_capture_path=staged_capture_path,
        log_directory=log_dir,
        ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
    )

    # 5. Execute Zeek
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=log_dir,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
            shell=False,
        )
        duration = round(time.perf_counter() - t0, 3)
        completed_at_str = datetime.now(UTC).isoformat()

        stdout_trimmed = (proc.stdout or "").strip()[:MAX_SUMMARY_LENGTH] or None
        stderr_trimmed = (proc.stderr or "").strip()[:MAX_SUMMARY_LENGTH] or None

        status = "completed" if proc.returncode == 0 else "failed"

        return ZeekRunResult(
            job_id=evidence.job_id,
            status=status,
            zeek_available=True,
            zeek_version=zeek_info.version,
            command=cmd,
            log_directory_name=log_dir.name,
            started_at_utc=started_at_str,
            completed_at_utc=completed_at_str,
            duration_seconds=duration,
            exit_code=proc.returncode,
            timed_out=False,
            ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
            stdout_summary=stdout_trimmed,
            stderr_summary=stderr_trimmed,
        )

    except subprocess.TimeoutExpired as exc:
        duration = round(time.perf_counter() - t0, 3)
        completed_at_str = datetime.now(UTC).isoformat()
        stdout_txt = (
            (exc.stdout or "").strip()[:MAX_SUMMARY_LENGTH]
            if isinstance(exc.stdout, str)
            else None
        )
        stderr_txt = (
            (exc.stderr or "").strip()[:MAX_SUMMARY_LENGTH]
            if isinstance(exc.stderr, str)
            else None
        )
        return ZeekRunResult(
            job_id=evidence.job_id,
            status="timed_out",
            zeek_available=True,
            zeek_version=zeek_info.version,
            command=cmd,
            log_directory_name=log_dir.name,
            started_at_utc=started_at_str,
            completed_at_utc=completed_at_str,
            duration_seconds=duration,
            exit_code=None,
            timed_out=True,
            ignore_invalid_ip_checksums=ignore_invalid_ip_checksums,
            stdout_summary=stdout_txt or None,
            stderr_summary=stderr_txt or f"Zeek timed out after {timeout_seconds}s.",
        )
