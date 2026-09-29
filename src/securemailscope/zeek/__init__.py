"""
SecureMailScope — Zeek sub-package.

Provides local Zeek availability checking, offline process invocation,
and execution status tracking.
"""

from securemailscope.zeek.discovery import ZeekAvailability, discover_zeek
from securemailscope.zeek.runner import (
    build_offline_zeek_command,
    run_zeek_offline,
)

__all__ = [
    "ZeekAvailability",
    "build_offline_zeek_command",
    "discover_zeek",
    "run_zeek_offline",
]
