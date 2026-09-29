"""
Tests — Phase 1 capture candidate validator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securemailscope.exceptions import (
    CaptureTooLargeError,
    EmptyCaptureError,
    InputValidationError,
    UnsupportedCaptureTypeError,
)
from securemailscope.ingest.validator import (
    PHASE_1_VALIDATION_LIMITATION,
    ValidatedCapture,
    validate_capture_file,
)


def test_accept_non_empty_pcap(tmp_path: Path) -> None:
    """Validator must accept a non-empty .pcap file."""
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")  # minimal synthetic bytes

    result = validate_capture_file(pcap)
    assert isinstance(result, ValidatedCapture)
    assert result.original_path == pcap.resolve()
    assert result.original_file_name == "sample.pcap"
    assert result.extension == ".pcap"
    assert result.file_size_bytes == 8
    assert result.limitation == PHASE_1_VALIDATION_LIMITATION


def test_accept_non_empty_pcapng(tmp_path: Path) -> None:
    """Validator must accept a non-empty .pcapng file."""
    pcapng = tmp_path / "capture.pcapng"
    pcapng.write_bytes(b"\x0a\x0d\x0d\x0a\x14\x00\x00\x00")

    result = validate_capture_file(pcapng)
    assert isinstance(result, ValidatedCapture)
    assert result.extension == ".pcapng"
    assert result.file_size_bytes == 8


def test_accept_uppercase_extensions(tmp_path: Path) -> None:
    """Validator must accept uppercase .PCAP and .PCAPNG extensions."""
    pcap_upper = tmp_path / "UPPER.PCAP"
    pcap_upper.write_bytes(b"test-pcap-content")

    pcapng_upper = tmp_path / "UPPER.PCAPNG"
    pcapng_upper.write_bytes(b"test-pcapng-content")

    res1 = validate_capture_file(pcap_upper)
    assert res1.extension == ".pcap"

    res2 = validate_capture_file(pcapng_upper)
    assert res2.extension == ".pcapng"


def test_reject_unsupported_extension(tmp_path: Path) -> None:
    """Validator must reject unsupported file extensions (e.g. .txt, .cap, .tar)."""
    txt_file = tmp_path / "evidence.txt"
    txt_file.write_bytes(b"some text data")

    with pytest.raises(UnsupportedCaptureTypeError) as exc_info:
        validate_capture_file(txt_file)
    assert "Unsupported capture file extension" in str(exc_info.value)


def test_reject_missing_file(tmp_path: Path) -> None:
    """Validator must reject a path that does not exist."""
    missing = tmp_path / "nonexistent.pcap"
    with pytest.raises(InputValidationError) as exc_info:
        validate_capture_file(missing)
    assert "does not exist" in str(exc_info.value)


def test_reject_directory_input(tmp_path: Path) -> None:
    """Validator must reject a directory path even if named with .pcap extension."""
    fake_dir = tmp_path / "folder.pcap"
    fake_dir.mkdir()

    with pytest.raises(InputValidationError) as exc_info:
        validate_capture_file(fake_dir)
    assert "is a directory" in str(exc_info.value)


def test_reject_zero_byte_capture(tmp_path: Path) -> None:
    """Validator must reject a 0-byte file with EmptyCaptureError."""
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(b"")

    with pytest.raises(EmptyCaptureError) as exc_info:
        validate_capture_file(empty_pcap)
    assert "empty" in str(exc_info.value)


def test_reject_oversized_capture(tmp_path: Path) -> None:
    """Validator must reject a file that exceeds max_file_size_bytes."""
    large_pcap = tmp_path / "large.pcap"
    large_pcap.write_bytes(b"A" * 1024)  # 1024 bytes

    # Set threshold to 512 bytes
    with pytest.raises(CaptureTooLargeError) as exc_info:
        validate_capture_file(large_pcap, max_file_size_bytes=512)
    assert "exceeds maximum allowed size" in str(exc_info.value)


def test_reject_none_or_empty_path() -> None:
    """Validator must reject None or blank string paths."""
    with pytest.raises(InputValidationError):
        validate_capture_file(None)  # type: ignore[arg-type]

    with pytest.raises(InputValidationError):
        validate_capture_file("   ")
