"""
SecureMailScope — Evidence integrity hashing.

Calculates SHA-256 digests using chunked binary reading to avoid
loading large PCAP captures entirely into memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

HASH_CHUNK_SIZE_BYTES: int = 1024 * 1024  # 1 MiB chunk size


def calculate_sha256(
    path: str | Path,
    chunk_size: int = HASH_CHUNK_SIZE_BYTES,
) -> str:
    """Compute the SHA-256 hexadecimal digest of a file using chunked reads.

    Args:
        path: Path to the target file.
        chunk_size: Number of bytes to read per chunk (must be positive).

    Returns:
        Lowercase hexadecimal SHA-256 digest string.

    Raises:
        ValueError: If chunk_size is not a positive integer.
        FileNotFoundError: If the specified file does not exist.
        IsADirectoryError: If the specified path is a directory.
    """
    if chunk_size <= 0:
        raise ValueError(
            f"chunk_size must be a positive integer, got {chunk_size}"
        )

    file_path = Path(path).resolve()
    if not file_path.exists():
        raise FileNotFoundError(
            f"Cannot calculate SHA-256: file does not exist: {file_path}"
        )
    if file_path.is_dir():
        raise IsADirectoryError(f"Cannot calculate SHA-256 on a directory: {file_path}")

    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest().lower()
