"""
SecureMailScope — Typed path helpers.

All paths are derived from the project root at call time.
Directories are NOT created automatically at import time.
Call ensure_runtime_directories() explicitly where needed.

Only runtime/ subdirectories are created by ensure_runtime_directories().
The project root and all other directories are assumed to exist from
repository checkout.
"""

from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    """Return the absolute path to the repository root.

    Determined as three levels up from this file:
    src/securemailscope/paths.py  →  project root
    """
    return Path(__file__).resolve().parent.parent.parent


def runtime_dir() -> Path:
    """Return the path to the runtime/ directory."""
    return project_root() / "runtime"


def uploads_dir() -> Path:
    """Return the path to the runtime/uploads/ directory."""
    return runtime_dir() / "uploads"


def jobs_dir() -> Path:
    """Return the path to the runtime/jobs/ directory."""
    return runtime_dir() / "jobs"


def zeek_logs_dir() -> Path:
    """Return the path to the runtime/zeek_logs/ directory."""
    return runtime_dir() / "zeek_logs"


def reports_dir() -> Path:
    """Return the path to the runtime/reports/ directory."""
    return runtime_dir() / "reports"


def ensure_runtime_directories(base: Path | None = None) -> None:
    """Create all expected runtime subdirectories if they do not exist.

    This function only creates directories inside runtime/.
    Pass a custom *base* path to redirect runtime creation (used in tests).

    Args:
        base: Optional override for the runtime/ base directory.
              Defaults to runtime_dir().
    """
    root = base if base is not None else runtime_dir()
    for subdir in ("uploads", "jobs", "zeek_logs", "reports"):
        (root / subdir).mkdir(parents=True, exist_ok=True)
