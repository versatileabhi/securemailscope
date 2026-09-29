"""
Tests — Phase 2 ZeekRunResult schema.
"""

from __future__ import annotations

import json

from securemailscope.schemas.zeek import PHASE_2_LIMITATIONS, ZeekRunResult


def test_zeek_run_result_serialization_round_trip() -> None:
    """ZeekRunResult serializes to dict/JSON and deserializes correctly."""
    result = ZeekRunResult(
        job_id="job_20260929T120000Z_abcdef12",
        status="completed",
        zeek_available=True,
        zeek_version="zeek 6.0.4",
        command=("zeek", "-r", "sample.pcap", "Log::default_logdir=logs"),
        log_directory_name="job_20260929T120000Z_abcdef12",
        started_at_utc="2026-09-29T12:00:00Z",
        completed_at_utc="2026-09-29T12:00:05Z",
        duration_seconds=5.123,
        exit_code=0,
        timed_out=False,
        ignore_invalid_ip_checksums=False,
        stdout_summary="success",
        stderr_summary=None,
    )

    d = result.to_dict()
    assert d["job_id"] == "job_20260929T120000Z_abcdef12"
    assert d["status"] == "completed"
    assert isinstance(d["command"], list)
    assert d["metadata_schema_version"] == "1.0"
    assert PHASE_2_LIMITATIONS[0] in d["limitations"]

    j = result.to_json()
    parsed = json.loads(j)
    assert parsed["job_id"] == result.job_id
    assert parsed["exit_code"] == 0

    restored = ZeekRunResult.from_dict(d)
    assert restored.job_id == result.job_id
    assert restored.command == result.command
    assert restored.exit_code == result.exit_code
    assert restored.status == result.status
