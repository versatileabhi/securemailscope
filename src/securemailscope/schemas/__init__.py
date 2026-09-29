"""
SecureMailScope — Schemas sub-package.

Contains structured dataclass schemas for evidence metadata (Phase 1),
Zeek execution results (Phase 2), canonical session records (Phase 3),
and protocol observations (Phase 4).
"""

from securemailscope.schemas.evidence import (
    PHASE_1_LIMITATION_TEXT,
    EvidenceMetadata,
)
from securemailscope.schemas.observation import (
    PHASE_4_LIMITATIONS,
    CertificateObservation,
    ImapObservation,
    ObservationResult,
    Pop3Observation,
    SessionObservation,
    SmtpObservation,
    StarttlsObservation,
    TlsObservation,
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
    # Phase 4
    "CertificateObservation",
    "ImapObservation",
    "ObservationResult",
    "PHASE_4_LIMITATIONS",
    "Pop3Observation",
    "SessionObservation",
    "SmtpObservation",
    "StarttlsObservation",
    "TlsObservation",
]
