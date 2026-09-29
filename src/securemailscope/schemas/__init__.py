"""
SecureMailScope — Schemas sub-package.

Contains structured dataclass schemas for evidence metadata (Phase 1),
Zeek execution results (Phase 2), and canonical session records (Phase 3).
"""

from securemailscope.schemas.evidence import (
    PHASE_1_LIMITATION_TEXT,
    EvidenceMetadata,
)
from securemailscope.schemas.session import (
    PHASE_3_LIMITATIONS,
    CanonicalSession,
    CertificateRecord,
    CorrelationResult,
    ParseWarning,
    SmtpEnrichment,
    SslEnrichment,
)
from securemailscope.schemas.zeek import (
    PHASE_2_LIMITATIONS,
    ZeekRunResult,
)

__all__ = [
    # Phase 1
    "EvidenceMetadata",
    "PHASE_1_LIMITATION_TEXT",
    # Phase 2
    "PHASE_2_LIMITATIONS",
    "ZeekRunResult",
    # Phase 3
    "CanonicalSession",
    "CertificateRecord",
    "CorrelationResult",
    "PHASE_3_LIMITATIONS",
    "ParseWarning",
    "SmtpEnrichment",
    "SslEnrichment",
]
