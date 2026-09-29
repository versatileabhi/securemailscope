"""
SecureMailScope — Local file input validation for PCAP/PCAPNG evidence.

Phase 1 validates file-level eligibility only. It does not verify
PCAP/PCAPNG internal structure or parse packet contents.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from securemailscope.exceptions import (
    CaptureTooLargeError,
    EmptyCaptureError,
    InputValidationError,
    UnsupportedCaptureTypeError,
)

SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({".pcap", ".pcapng"})
DEFAULT_MAX_FILE_SIZE_BYTES: int = 100 * 1024 * 1024  # 100 MiB default limit
PHASE_1_VALIDATION_LIMITATION: str = (
    "Phase 1 validates file-level eligibility only. It does not verify "
    "PCAP/PCAPNG internal structure or parse packet contents."
)


@dataclass(frozen=True)
class ValidatedCapture:
    """Represents a validated candidate capture file prior to staging.

    Attributes:
        original_path: Absolute resolved path of the original input file.
        original_file_name: Base filename of the original input.
        extension: File extension (lowercase, including leading dot).
        file_size_bytes: Size of the file in bytes.
        limitation: Explicit disclaimer regarding validation scope.
    """

    original_path: Path
    original_file_name: str
    extension: str
    file_size_bytes: int
    limitation: str = PHASE_1_VALIDATION_LIMITATION


def validate_capture_file(
    input_path: str | Path,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
) -> ValidatedCapture:
    """Validate basic file-level eligibility of a candidate PCAP/PCAPNG file.

    Phase 1 validates file-level eligibility only. It does not verify
    PCAP/PCAPNG internal structure or parse packet contents.

    Args:
        input_path: Candidate file path as a string or Path.
        max_file_size_bytes: Maximum permitted file size in bytes.

    Returns:
        ValidatedCapture instance containing sanitized file metadata.

    Raises:
        InputValidationError: If path is missing, is a directory, or unreadable.
        UnsupportedCaptureTypeError: If extension is not .pcap or .pcapng.
        EmptyCaptureError: If file size is 0 bytes.
        CaptureTooLargeError: If file size exceeds max_file_size_bytes.
    """
    if input_path is None:
        raise InputValidationError("Input path cannot be None.")

    raw_path_str = str(input_path).strip()
    if not raw_path_str:
        raise InputValidationError("Input path cannot be empty.")

    try:
        path = Path(input_path).expanduser().resolve()
    except Exception as exc:
        raise InputValidationError(
            f"Invalid path representation: {input_path}"
        ) from exc

    if not path.exists():
        raise InputValidationError(f"Candidate file does not exist: {path}")

    if path.is_dir():
        raise InputValidationError(
            f"Candidate path is a directory, not a file: {path}"
        )

    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise UnsupportedCaptureTypeError(
            f"Unsupported capture file extension '{path.suffix}'. "
            f"Only {sorted(SUPPORTED_EXTENSIONS)} are supported."
        )

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputValidationError(
            f"Unable to access file metadata for '{path}': {exc}"
        ) from exc

    if size == 0:
        raise EmptyCaptureError(f"Capture file is empty (0 bytes): {path}")

    if size > max_file_size_bytes:
        raise CaptureTooLargeError(
            f"Capture file size ({size} bytes) exceeds maximum allowed size "
            f"({max_file_size_bytes} bytes): {path}"
        )

    # Check file readability
    try:
        with path.open("rb") as f:
            f.read(1)
    except (PermissionError, OSError) as exc:
        raise InputValidationError(
            f"Candidate file is not readable: {path}"
        ) from exc

    return ValidatedCapture(
        original_path=path,
        original_file_name=path.name,
        extension=ext,
        file_size_bytes=size,
    )
