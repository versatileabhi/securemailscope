"""
Tests — package import and version.

Phase 0 acceptance criteria:
  - Package imports successfully.
  - __version__ equals '0.1.0'.
"""

from __future__ import annotations

import securemailscope


def test_package_imports_successfully() -> None:
    """The top-level package must be importable without errors."""
    import securemailscope as sms  # noqa: F401 — import is the test
    assert sms is not None


def test_version_is_correct() -> None:
    """__version__ must equal '0.1.0' exactly."""
    assert securemailscope.__version__ == "0.1.0"


def test_version_is_string() -> None:
    """__version__ must be a str."""
    assert isinstance(securemailscope.__version__, str)
