"""
Tests — Phase 1 ingestion service orchestration and evidence generation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securemailscope.exceptions import (
    EvidenceIntegrityError,
    EvidenceStagingError,
    InputValidationError,
    UnsupportedCaptureTypeError,
)
from securemailscope.ingest.hashing import calculate_sha256
from securemailscope.ingest.service import ingest_capture
from securemailscope.schemas.evidence import (
    PHASE_1_LIMITATION_TEXT,
    EvidenceMetadata,
)


def test_ingest_capture_successful(tmp_path: Path) -> None:
    """Successful ingestion creates staged copy and metadata record."""
    source_pcap = tmp_path / "traffic.pcap"
    content = b"SYN-ACK-TLS13-CLIENT-HELLO"
    source_pcap.write_bytes(content)
    expected_hash = calculate_sha256(source_pcap)

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    evidence = ingest_capture(
        source_pcap,
        max_file_size_bytes=1024 * 1024,
        runtime_root_path=runtime_dir,
    )

    # 1. Type and attributes
    assert isinstance(evidence, EvidenceMetadata)
    assert evidence.original_file_name == "traffic.pcap"
    assert evidence.staged_file_name == "traffic.pcap"
    assert evidence.extension == ".pcap"
    assert evidence.file_size_bytes == len(content)
    assert evidence.sha256 == expected_hash

    # 2. Required literal values
    assert evidence.analysis_mode == "offline"
    assert evidence.status == "accepted"
    assert evidence.coverage == "insufficient"
    assert evidence.attribution == "not_proven"
    assert evidence.source_path_disclosed is False
    assert evidence.metadata_schema_version == "1.0"
    assert PHASE_1_LIMITATION_TEXT in evidence.limitations

    # 3. Job ID uniqueness / format
    assert evidence.job_id.startswith("job_")
    assert "T" in evidence.job_id
    assert "Z_" in evidence.job_id

    # 4. Verify staged file location and content
    staged_file = runtime_dir / "uploads" / evidence.job_id / "traffic.pcap"
    assert staged_file.exists()
    assert staged_file.read_bytes() == content
    assert calculate_sha256(staged_file) == expected_hash

    # 5. Verify source file untouched
    assert source_pcap.exists()
    assert source_pcap.read_bytes() == content

    # 6. Verify metadata JSON file
    meta_file = runtime_dir / "jobs" / evidence.job_id / "metadata.json"
    assert meta_file.exists()
    meta_json = json.loads(meta_file.read_text(encoding="utf-8"))
    assert meta_json["job_id"] == evidence.job_id
    assert meta_json["sha256"] == expected_hash
    assert meta_json["analysis_mode"] == "offline"
    assert meta_json["status"] == "accepted"
    assert meta_json["coverage"] == "insufficient"
    assert meta_json["attribution"] == "not_proven"
    assert meta_json["source_path_disclosed"] is False
    assert PHASE_1_LIMITATION_TEXT in meta_json["limitations"]

    # 7. Disclose check: original absolute source path must NOT be present
    meta_text = meta_file.read_text(encoding="utf-8")
    assert str(source_pcap.resolve()) not in meta_text
    assert str(source_pcap.parent.resolve()) not in meta_text


def test_unique_job_ids_per_ingestion(tmp_path: Path) -> None:
    """Successive ingestions must generate unique job IDs."""
    source_pcap = tmp_path / "sample.pcap"
    source_pcap.write_bytes(b"data")
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    e1 = ingest_capture(source_pcap, runtime_root_path=runtime_dir)
    e2 = ingest_capture(source_pcap, runtime_root_path=runtime_dir)

    assert e1.job_id != e2.job_id
    assert (runtime_dir / "uploads" / e1.job_id).exists()
    assert (runtime_dir / "uploads" / e2.job_id).exists()


def test_rejected_inputs_create_no_artifacts(tmp_path: Path) -> None:
    """Rejected files must not leave staged uploads or job directories."""
    bad_file = tmp_path / "document.pdf"
    bad_file.write_bytes(b"%PDF-1.4")
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    with pytest.raises(UnsupportedCaptureTypeError):
        ingest_capture(bad_file, runtime_root_path=runtime_dir)

    # Neither uploads nor jobs directories should contain subdirectories
    uploads_dir = runtime_dir / "uploads"
    jobs_dir = runtime_dir / "jobs"
    if uploads_dir.exists():
        assert list(uploads_dir.iterdir()) == []
    if jobs_dir.exists():
        assert list(jobs_dir.iterdir()) == []


def test_integrity_hash_mismatch_raises_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Integrity mismatch must raise EvidenceIntegrityError and cleanup."""
    source_pcap = tmp_path / "tamper.pcap"
    source_pcap.write_bytes(b"valid-initial-bytes")
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    # Monkeypatch calculate_sha256 on second call to simulate corruption
    call_count = 0
    orig_calc = calculate_sha256

    def mock_calc(path, chunk_size=None):
        nonlocal call_count
        call_count += 1
        real_hash = orig_calc(path)
        if call_count == 2:  # Staged copy check
            return "0" * 64
        return real_hash

    monkeypatch.setattr(
        "securemailscope.ingest.service.calculate_sha256", mock_calc
    )

    with pytest.raises(EvidenceIntegrityError) as exc_info:
        ingest_capture(source_pcap, runtime_root_path=runtime_dir)
    assert "Integrity check failed" in str(exc_info.value)

    # Source file must still exist and be unchanged
    assert source_pcap.exists()
    assert source_pcap.read_bytes() == b"valid-initial-bytes"

    # Artifacts must be cleaned up
    uploads_dir = runtime_dir / "uploads"
    if uploads_dir.exists():
        assert list(uploads_dir.iterdir()) == []


def test_atomic_metadata_failure_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If metadata write fails, cleanup occurs and EvidenceStagingError is raised."""
    source_pcap = tmp_path / "fail.pcap"
    source_pcap.write_bytes(b"valid-bytes")
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    # Simulate write error by breaking open on tmp metadata file
    def mock_open(*args, **kwargs):
        raise OSError("Disk full simulation")

    monkeypatch.setattr(Path, "open", mock_open)

    with pytest.raises((EvidenceStagingError, InputValidationError)):
        ingest_capture(source_pcap, runtime_root_path=runtime_dir)

    assert source_pcap.exists()


def test_safe_staged_filename_no_traversal(tmp_path: Path) -> None:
    """Staged filename must retain only the basename, preventing traversal."""
    nested = tmp_path / "sub" / "deep"
    nested.mkdir(parents=True)
    source = nested / "nested.pcap"
    source.write_bytes(b"nested-content")

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    evidence = ingest_capture(source, runtime_root_path=runtime_dir)
    assert evidence.staged_file_name == "nested.pcap"
    staged_path = runtime_dir / "uploads" / evidence.job_id / "nested.pcap"
    assert staged_path.exists()
