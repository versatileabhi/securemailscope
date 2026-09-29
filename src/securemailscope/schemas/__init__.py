"""
SecureMailScope — Schemas sub-package.

Contains structured dataclass schemas for evidence metadata and (in Phase 3+)
canonical session records.
"""

from securemailscope.schemas.evidence import (
    PHASE_1_LIMITATION_TEXT,
    EvidenceMetadata,
)

__all__ = [
    "EvidenceMetadata",
    "PHASE_1_LIMITATION_TEXT",
]
