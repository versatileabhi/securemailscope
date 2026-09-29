"""
SecureMailScope — Pytest configuration and shared fixtures.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def project_root_path(tmp_path):
    """Return a temporary directory that mimics the project root structure.

    Used to test path helpers without touching the real project tree.
    Subdirectories matching the real project are created on demand by tests.
    """
    return tmp_path
