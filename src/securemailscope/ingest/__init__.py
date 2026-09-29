"""
SecureMailScope — Ingest sub-package.

Provides local PCAP/PCAPNG candidate file validation, chunked SHA-256
evidence hashing, and safe local staging.
"""

from securemailscope.ingest.hashing import HASH_CHUNK_SIZE_BYTES, calculate_sha256
from securemailscope.ingest.service import ingest_capture
from securemailscope.ingest.validator import (
    DEFAULT_MAX_FILE_SIZE_BYTES,
    SUPPORTED_EXTENSIONS,
    ValidatedCapture,
    validate_capture_file,
)

__all__ = [
    "DEFAULT_MAX_FILE_SIZE_BYTES",
    "HASH_CHUNK_SIZE_BYTES",
    "SUPPORTED_EXTENSIONS",
    "ValidatedCapture",
    "calculate_sha256",
    "ingest_capture",
    "validate_capture_file",
]
