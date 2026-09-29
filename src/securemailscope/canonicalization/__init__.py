"""
SecureMailScope — Canonicalization sub-package.

Provides Zeek JSON-log reading, canonical session record correlation
(Phase 3), and protocol observation extraction (Phase 4).
"""

from securemailscope.canonicalization.correlator import correlate_zeek_logs
from securemailscope.canonicalization.extractor import extract_observations
from securemailscope.schemas.observation import ObservationResult
from securemailscope.schemas.session import CorrelationResult

__all__ = [
    "CorrelationResult",
    "ObservationResult",
    "correlate_zeek_logs",
    "extract_observations",
]
