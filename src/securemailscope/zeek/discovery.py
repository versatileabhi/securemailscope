"""
SecureMailScope — Zeek discovery and availability checking.

Discovers whether Zeek is installed locally and verifies its version
without making network connections or installing external packages.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ZeekAvailability:
    """Represents the discovery and availability status of Zeek.

    Attributes:
        available: True if Zeek was discovered and responded to --version.
        executable_path: Path to the discovered Zeek binary, or None.
        version: Normalized Zeek version string, or None.
        error: Safe, concise error description if unavailable, or None.
    """

    available: bool
    executable_path: str | None
    version: str | None
    error: str | None


def discover_zeek(
    configured_path: str | Path | None = None,
    *,
    timeout_seconds: int = 10,
) -> ZeekAvailability:
    """Discover local Zeek binary and verify its version.

    Searches the configured path if specified, otherwise checks the system PATH
    via shutil.which. Does not search arbitrary filesystem trees or download binaries.

    Args:
        configured_path: Optional explicit path to a local Zeek executable.
        timeout_seconds: Maximum time in seconds to wait for `zeek --version`.

    Returns:
        ZeekAvailability record indicating availability and version details.
    """
    candidate: str | None = None

    if configured_path is not None and str(configured_path).strip():
        p = Path(configured_path).expanduser().resolve()
        if not p.exists() or p.is_dir():
            return ZeekAvailability(
                available=False,
                executable_path=str(p),
                version=None,
                error="Configured Zeek executable not found or is a directory.",
            )
        candidate = str(p)
    else:
        candidate = shutil.which("zeek")
        if candidate is None and sys.platform.startswith("win"):
            candidate = shutil.which("zeek.exe")

    if candidate is None:
        return ZeekAvailability(
            available=False,
            executable_path=None,
            version=None,
            error="Zeek executable not found on system PATH.",
        )

    cmd = [candidate, "--version"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return ZeekAvailability(
            available=False,
            executable_path=candidate,
            version=None,
            error=f"Zeek version command timed out after {timeout_seconds}s.",
        )
    except OSError as exc:
        return ZeekAvailability(
            available=False,
            executable_path=candidate,
            version=None,
            error=f"Failed to execute Zeek binary: {exc}",
        )

    if proc.returncode != 0:
        return ZeekAvailability(
            available=False,
            executable_path=candidate,
            version=None,
            error=f"Zeek version command exited with code {proc.returncode}.",
        )

    raw_output = proc.stdout.strip() or proc.stderr.strip()
    version_line = (
        raw_output.splitlines()[0].strip() if raw_output else "zeek (unknown)"
    )

    return ZeekAvailability(
        available=True,
        executable_path=candidate,
        version=version_line,
        error=None,
    )
