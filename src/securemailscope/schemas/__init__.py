"""
SecureMailScope — Schemas sub-package.

Contains structured dataclass schemas for evidence metadata (Phase 1)
and Zeek execution results (Phase 2).
"""

from securemailscope.schemas.evidence import (
    PHASE_1_LIMITATION_TEXT,
    EvidenceMetadata,
)
from securemailscope.schemas.zeek import (
    PHASE_2_LIMITATIONS,
    ZeekRunResult,
)

__all__ = [
    "EvidenceMetadata",
    "PHASE_1_LIMITATION_TEXT",
    "PHASE_2_LIMITATIONS",
    "ZeekRunResult",
]
