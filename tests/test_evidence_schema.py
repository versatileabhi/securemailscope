"""
Tests — Phase 1 EvidenceMetadata schema.
"""

from __future__ import annotations

import json

from securemailscope.schemas.evidence import (
    PHASE_1_LIMITATION_TEXT,
    EvidenceMetadata,
)


def test_evidence_metadata_defaults_and_serialization() -> None:
    """EvidenceMetadata must enforce Phase 1 literals and serialize cleanly."""
    evidence = EvidenceMetadata(
        job_id="job_20260929T120000Z_abcdef12",
        original_file_name="capture.pcap",
        staged_file_name="capture.pcap",
        extension=".pcap",
        file_size_bytes=1024,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ingestion_timestamp_utc="2026-09-29T12:00:00+00:00",
    )

    assert evidence.analysis_mode == "offline"
    assert evidence.status == "accepted"
    assert evidence.coverage == "insufficient"
    assert evidence.attribution == "not_proven"
    assert evidence.source_path_disclosed is False
    assert evidence.metadata_schema_version == "1.0"
    assert PHASE_1_LIMITATION_TEXT in evidence.limitations

    # Dict serialization
    d = evidence.to_dict()
    assert d["job_id"] == "job_20260929T120000Z_abcdef12"
    assert d["analysis_mode"] == "offline"
    assert d["coverage"] == "insufficient"

    # JSON serialization
    j = evidence.to_json()
    parsed = json.loads(j)
    assert parsed["job_id"] == evidence.job_id
    assert parsed["status"] == "accepted"

    # Round-trip from_dict
    restored = EvidenceMetadata.from_dict(d)
    assert restored == evidence
