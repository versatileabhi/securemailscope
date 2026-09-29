"""
SecureMailScope — Canonicalization sub-package.

Provides Zeek JSON-log reading and canonical session record correlation
implemented in Phase 3.
"""

from securemailscope.canonicalization.correlator import correlate_zeek_logs
from securemailscope.schemas.session import CorrelationResult

__all__ = [
    "correlate_zeek_logs",
    "CorrelationResult",
]
