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


def runtime_root(base: Path | None = None) -> Path:
    """Return the resolved runtime root path, optionally overridden by *base*."""
    if base is not None:
        return Path(base).resolve()
    return runtime_dir().resolve()


def ensure_within_runtime(
    path: Path | str,
    runtime_base: Path | None = None,
) -> Path:
    """Ensure that *path* resolves to a location strictly within the runtime root.

    Args:
        path: Path to check.
        runtime_base: Optional base runtime directory override.

    Returns:
        The resolved Path if it is contained within the runtime root.

    Raises:
        UnsafePathError: If *path* is not within the runtime root.
    """
    root = runtime_root(runtime_base)
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        from securemailscope.exceptions import UnsafePathError

        raise UnsafePathError(
            f"Path '{resolved}' is outside the allowed runtime root '{root}'."
        ) from exc
    return resolved


def job_upload_dir(job_id: str, runtime_base: Path | None = None) -> Path:
    """Return the directory path for staging uploads for a specific job ID.

    Path format: runtime/uploads/<job_id>
    """
    root = runtime_root(runtime_base)
    target = (root / "uploads" / job_id).resolve()
    ensure_within_runtime(target, root)
    return target


def job_dir(job_id: str, runtime_base: Path | None = None) -> Path:
    """Return the directory path for job metadata and artifacts for a job ID.

    Path format: runtime/jobs/<job_id>
    """
    root = runtime_root(runtime_base)
    target = (root / "jobs" / job_id).resolve()
    ensure_within_runtime(target, root)
    return target


def ensure_within_directory(candidate: Path | str, parent: Path | str) -> Path:
    """Ensure that *candidate* resolves to a location strictly within *parent*.

    Args:
        candidate: Target path to test.
        parent: Boundary directory path.

    Returns:
        The resolved candidate Path.

    Raises:
        UnsafePathError: If candidate is not within parent.
    """
    resolved_candidate = Path(candidate).resolve()
    resolved_parent = Path(parent).resolve()
    try:
        resolved_candidate.relative_to(resolved_parent)
    except ValueError as exc:
        from securemailscope.exceptions import UnsafePathError

        raise UnsafePathError(
            f"Path '{resolved_candidate}' is outside '{resolved_parent}'."
        ) from exc
    return resolved_candidate


def zeek_logs_root(runtime_base: Path | None = None) -> Path:
    """Return the base directory path for Zeek output logs.

    Path format: runtime/zeek_logs
    """
    root = runtime_root(runtime_base)
    return (root / "zeek_logs").resolve()


def job_zeek_log_dir(job_id: str, runtime_base: Path | None = None) -> Path:
    """Return the isolated directory path for Zeek logs for a specific job ID.

    Path format: runtime/zeek_logs/<job_id>
    """
    root = runtime_root(runtime_base)
    base_logs = zeek_logs_root(root)
    target = (base_logs / job_id).resolve()
    ensure_within_directory(target, base_logs)
    ensure_within_runtime(target, root)
    return target


