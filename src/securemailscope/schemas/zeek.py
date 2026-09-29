"""
SecureMailScope — Zeek run result schema.

Defines the structured metadata model returned after offline Zeek execution.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

PHASE_2_LIMITATIONS: list[str] = [
    "Phase 2 executes Zeek in offline mode only and does not parse or interpret "
    "generated logs.",
    "Protocol, TLS, certificate, cryptographic policy, posture scoring, ML, "
    "reporting, and dashboard analysis are not implemented in Phase 2.",
]


@dataclass
class ZeekRunResult:
    """Structured execution result of an offline Zeek execution job.

    Statuses:
        - 'completed': Process exited with code 0.
        - 'zeek_unavailable': Zeek binary could not be found or executed.
        - 'invalid_evidence_reference': Staged capture file missing or invalid.
        - 'timed_out': Process exceeded configured execution timeout.
        - 'failed': Process exited with non-zero status code.
    """

    job_id: str
    status: str
    zeek_available: bool
    zeek_version: str | None
    command: tuple[str, ...]
    log_directory_name: str | None
    started_at_utc: str
    completed_at_utc: str | None = None
    duration_seconds: float | None = None
    exit_code: int | None = None
    timed_out: bool = False
    ignore_invalid_ip_checksums: bool = False
    stdout_summary: str | None = None
    stderr_summary: str | None = None
    limitations: list[str] = field(
        default_factory=lambda: list(PHASE_2_LIMITATIONS)
    )
    metadata_schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a dictionary."""
        d = asdict(self)
        d["command"] = list(self.command)
        return d

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize result to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ZeekRunResult:
        """Construct ZeekRunResult from dictionary representation."""
        data_copy = dict(data)
        if "command" in data_copy and isinstance(data_copy["command"], list):
            data_copy["command"] = tuple(data_copy["command"])
        return cls(**data_copy)
