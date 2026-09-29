"""
SecureMailScope — Evidence metadata schema.

Defines the structured metadata record generated upon successful
Phase 1 capture file ingestion and staging.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

PHASE_1_LIMITATION_TEXT: str = (
    "Phase 1 validates file-level evidence only; protocol, TCP, TLS, certificate, "
    "cryptographic policy, posture scoring, ML, reporting, and dashboard analysis "
    "are not yet implemented."
)


@dataclass
class EvidenceMetadata:
    """Machine-readable evidence metadata record for an ingested capture file.

    Note on privacy and chain-of-custody:
        The absolute source path is intentionally excluded to prevent accidental
        disclosure of sensitive local environment paths. Only the basename is stored.
    """

    job_id: str
    original_file_name: str
    staged_file_name: str
    extension: str
    file_size_bytes: int
    sha256: str
    ingestion_timestamp_utc: str
    analysis_mode: str = "offline"
    status: str = "accepted"
    source_path_disclosed: bool = False
    coverage: str = "insufficient"
    attribution: str = "not_proven"
    limitations: list[str] = field(
        default_factory=lambda: [PHASE_1_LIMITATION_TEXT]
    )
    metadata_schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert the metadata record to a dictionary."""
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the metadata record to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceMetadata:
        """Construct an EvidenceMetadata instance from a dictionary."""
        return cls(**data)
