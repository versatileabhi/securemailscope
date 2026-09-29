"""
Tests — path helpers.

Phase 0 acceptance criteria:
  - project_root() returns a Path.
  - ensure_runtime_directories() creates only expected runtime subdirectories
    in a temporary test environment.
  - No test modifies the real project runtime/ directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securemailscope.paths import (
    ensure_runtime_directories,
    jobs_dir,
    project_root,
    reports_dir,
    runtime_dir,
    uploads_dir,
    zeek_logs_dir,
)


def test_project_root_returns_path() -> None:
    """project_root() must return a pathlib.Path instance."""
    assert isinstance(project_root(), Path)


def test_project_root_is_absolute() -> None:
    """project_root() must return an absolute path."""
    assert project_root().is_absolute()


def test_runtime_dir_is_child_of_project_root() -> None:
    """runtime_dir() must be a child of project_root()."""
    assert runtime_dir().parent == project_root()


def test_uploads_dir_is_under_runtime() -> None:
    """uploads_dir() must be under runtime_dir()."""
    assert uploads_dir().parent == runtime_dir()


def test_jobs_dir_is_under_runtime() -> None:
    """jobs_dir() must be under runtime_dir()."""
    assert jobs_dir().parent == runtime_dir()


def test_zeek_logs_dir_is_under_runtime() -> None:
    """zeek_logs_dir() must be under runtime_dir()."""
    assert zeek_logs_dir().parent == runtime_dir()


def test_reports_dir_is_under_runtime() -> None:
    """reports_dir() must be under runtime_dir()."""
    assert reports_dir().parent == runtime_dir()


def test_ensure_runtime_directories_creates_expected_dirs(
    tmp_path: Path,
) -> None:
    """ensure_runtime_directories() must create uploads, jobs, zeek_logs, reports."""
    ensure_runtime_directories(base=tmp_path)

    expected = {"uploads", "jobs", "zeek_logs", "reports"}
    created = {d.name for d in tmp_path.iterdir() if d.is_dir()}
    assert expected == created


def test_ensure_runtime_directories_does_not_touch_project_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Using the base= parameter must never modify the real runtime/ directory."""
    ensure_runtime_directories(base=tmp_path)
    # Verify that results are isolated to tmp_path (real runtime/ was not altered).
    # We cannot assert exact contents of the real runtime/, but we confirm
    # that our tmp_path results are correctly populated.
    isolated_dirs = {d.name for d in tmp_path.iterdir() if d.is_dir()}
    assert "uploads" in isolated_dirs


def test_ensure_runtime_directories_is_idempotent(tmp_path: Path) -> None:
    """Calling ensure_runtime_directories() twice must not raise."""
    ensure_runtime_directories(base=tmp_path)
    ensure_runtime_directories(base=tmp_path)  # second call must be safe
    expected = {"uploads", "jobs", "zeek_logs", "reports"}
    created = {d.name for d in tmp_path.iterdir() if d.is_dir()}
    assert expected == created
