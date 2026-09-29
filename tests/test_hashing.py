"""
Tests — Phase 1 chunked SHA-256 hashing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from securemailscope.ingest.hashing import HASH_CHUNK_SIZE_BYTES, calculate_sha256


def test_calculate_sha256_known_sequence(tmp_path: Path) -> None:
    """calculate_sha256 must match known SHA-256 digest for fixed bytes."""
    data = b"SecureMailScope forensic capture test payload 2026"
    expected = hashlib.sha256(data).hexdigest().lower()

    sample = tmp_path / "test.pcap"
    sample.write_bytes(data)

    computed = calculate_sha256(sample)
    assert computed == expected
    assert isinstance(computed, str)
    assert len(computed) == 64
    assert computed == computed.lower()


def test_calculate_sha256_chunked_reads(tmp_path: Path) -> None:
    """calculate_sha256 must produce identical digest when chunk size is small."""
    data = b"0123456789abcdefghijklmnopqrstuvwxyz" * 100  # 3600 bytes
    expected = hashlib.sha256(data).hexdigest().lower()

    sample = tmp_path / "chunked.pcap"
    sample.write_bytes(data)

    # Use very small chunk size to force multiple iterations
    computed = calculate_sha256(sample, chunk_size=17)
    assert computed == expected


def test_reject_non_positive_chunk_size(tmp_path: Path) -> None:
    """calculate_sha256 must reject chunk_size <= 0 with ValueError."""
    sample = tmp_path / "valid.pcap"
    sample.write_bytes(b"content")

    with pytest.raises(ValueError) as exc0:
        calculate_sha256(sample, chunk_size=0)
    assert "positive integer" in str(exc0.value)

    with pytest.raises(ValueError) as exc_neg:
        calculate_sha256(sample, chunk_size=-1024)
    assert "positive integer" in str(exc_neg.value)


def test_calculate_sha256_file_not_found(tmp_path: Path) -> None:
    """calculate_sha256 must raise FileNotFoundError if file is missing."""
    missing = tmp_path / "missing.pcap"
    with pytest.raises(FileNotFoundError):
        calculate_sha256(missing)


def test_calculate_sha256_directory_rejected(tmp_path: Path) -> None:
    """calculate_sha256 must raise IsADirectoryError if path is a directory."""
    folder = tmp_path / "test_dir"
    folder.mkdir()
    with pytest.raises(IsADirectoryError):
        calculate_sha256(folder)


def test_default_chunk_size_is_one_mebibyte() -> None:
    """Default chunk size constant must be exactly 1024 * 1024 bytes."""
    assert HASH_CHUNK_SIZE_BYTES == 1024 * 1024
