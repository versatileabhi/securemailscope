"""
SecureMailScope — Canonical session schema.

Defines the structured dataclass models produced by Phase 3 Zeek JSON-log
reading and correlation. These models are the primary output of the
canonicalization pipeline and the input to Phase 4 observation extraction.

Privacy note:
    Absolute filesystem paths are excluded from all exported models.
    Only the log directory name (basename) and job_id are retained for
    provenance, consistent with the project privacy conventions established
    in Phase 1 and Phase 2.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

PHASE_3_LIMITATIONS: list[str] = [
    "Phase 3 reads and correlates Zeek JSON logs only; no detection rules, "
    "risk scoring, ML ranking, reporting, or dashboard are implemented.",
    "X.509 certificate records are associated via ssl.cert_chain_fuids → x509.fuid; "
    "direct conn.uid → x509 association is not available in standard Zeek output.",
    "smtp.log and ssl.log enrichment is optional; absent logs produce None enrichment "
    "Phase 3 does not parse PCAP files or invoke Zeek; "
    "it reads existing log output only.",
]


# ---------------------------------------------------------------------------
# Non-fatal observable parse event
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParseWarning:
    """Non-fatal observable event encountered during Zeek JSON-log reading.

    Attributes:
        log_type: Identifies the source log file (e.g. "conn", "smtp", "ssl", "x509").
        line_number: 1-indexed source line. Use 0 for file-level warnings.
        issue: Concise human-readable description of the problem.
        raw_line: Up to max_raw_line_length chars of the offending line, or None.
    """

    log_type: str
    line_number: int
    issue: str
    raw_line: str | None


# ---------------------------------------------------------------------------
# Enrichment sub-models
# ---------------------------------------------------------------------------


@dataclass
class SmtpEnrichment:
    """SMTP session enrichment sourced from Zeek smtp.log.

    The Zeek field ``from`` is stored as ``from_`` to avoid a Python keyword
    conflict. ``to_dict()`` re-maps it back to ``"from"`` for JSON output.

    Unknown Zeek fields are silently dropped during construction; they are
    not stored and do not trigger a ParseWarning.
    """

    uid: str

    ts: float | None = None
    trans_depth: int | None = None
    helo: str | None = None
    mailfrom: str | None = None
    rcptto: list[str] = field(default_factory=list)
    date: str | None = None
    from_: str | None = None  # Zeek field "from"
    to: list[str] = field(default_factory=list)
    reply_to: str | None = None
    msg_id: str | None = None
    subject: str | None = None
    x_originating_ip: str | None = None
    first_received: str | None = None
    second_received: str | None = None
    last_reply: str | None = None
    path: list[str] = field(default_factory=list)
    user_agent: str | None = None
    tls: bool | None = None
    fuids: list[str] = field(default_factory=list)
    is_webmail: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, remapping ``from_`` → ``"from"``."""
        d = asdict(self)
        if "from_" in d:
            d["from"] = d.pop("from_")
        return d

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SmtpEnrichment:
        """Construct from a dictionary, remapping ``"from"`` → ``from_``."""
        d = dict(data)
        if "from" in d:
            d["from_"] = d.pop("from")
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


@dataclass
class SslEnrichment:
    """TLS session enrichment sourced from Zeek ssl.log.

    ``cert_chain_fuids`` is the critical join key to x509.log records.
    """

    uid: str

    ts: float | None = None
    version: str | None = None
    cipher: str | None = None
    curve: str | None = None
    server_name: str | None = None  # SNI
    resumed: bool | None = None
    established: bool | None = None
    cert_chain_fuids: list[str] = field(default_factory=list)
    client_cert_chain_fuids: list[str] = field(default_factory=list)
    subject: str | None = None
    issuer: str | None = None
    validation_status: str | None = None
    next_protocol: str | None = None  # ALPN

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SslEnrichment:
        """Construct from a dictionary, ignoring unknown fields."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class CertificateRecord:
    """X.509 certificate record sourced from Zeek x509.log.

    ``fuid`` (file UID) is the primary key used to join with
    ``SslEnrichment.cert_chain_fuids``. x509.log records do NOT share
    a ``uid`` with conn.log; the join chain is:

        conn.uid → ssl.uid → ssl.cert_chain_fuids → x509.fuid

    This is the only reliable association in standard Zeek output.
    """

    fuid: str  # file UID — join key from ssl.log cert_chain_fuids

    ts: float | None = None
    id: str | None = None  # Zeek x509 id field
    certificate_version: int | None = None
    certificate_serial: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_not_valid_before: float | None = None
    certificate_not_valid_after: float | None = None
    certificate_key_alg: str | None = None
    certificate_sig_alg: str | None = None
    certificate_key_type: str | None = None
    certificate_key_length: int | None = None
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    basic_constraints_ca: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CertificateRecord:
        """Construct from a dictionary, ignoring unknown fields."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


# ---------------------------------------------------------------------------
# Primary canonical session output
# ---------------------------------------------------------------------------


@dataclass
class CanonicalSession:
    """Canonical session record produced by Phase 3 Zeek log correlation.

    One record represents one Zeek connection anchored by ``uid``, optionally
    enriched with smtp.log, ssl.log, and x509.log data where available.

    Fields left as ``None`` indicate the field was absent in the source log or
    the corresponding optional log was not present — never a fabricated value.
    ``certificates`` is always a list (empty when no ssl enrichment or no
    matching certificate fuids were found).
    """

    # Identity (required)
    uid: str
    job_id: str | None
    log_directory_name: str | None

    # conn.log fields — all optional (absent Zeek fields stay None)
    ts: float | None = None
    id_orig_h: str | None = None
    id_orig_p: int | None = None
    id_resp_h: str | None = None
    id_resp_p: int | None = None
    proto: str | None = None
    service: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    conn_state: str | None = None
    missed_bytes: int | None = None

    # Optional enrichment — None means log absent or uid unmatched
    smtp: SmtpEnrichment | None = None
    ssl: SslEnrichment | None = None

    # Certificate chain — empty list if no ssl enrichment or no matched fuids
    certificates: list[CertificateRecord] = field(default_factory=list)

    # Schema provenance
    limitations: list[str] = field(
        default_factory=lambda: list(PHASE_3_LIMITATIONS)
    )
    metadata_schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary.

        Nested enrichment models are recursively converted.
        ``SmtpEnrichment.from_`` is emitted as ``"from"`` in the output.
        """
        d = asdict(self)
        # asdict recurses into nested dataclasses automatically, but
        # SmtpEnrichment.from_ → "from" rename must be applied manually.
        if d.get("smtp") is not None and "from_" in d["smtp"]:
            d["smtp"]["from"] = d["smtp"].pop("from_")
        return d

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CanonicalSession:
        """Reconstruct a CanonicalSession from a dictionary.

        Nested dicts for smtp, ssl, and certificates are reconstructed
        into their respective dataclass types.
        """
        d = dict(data)

        if d.get("smtp") is not None:
            d["smtp"] = SmtpEnrichment.from_dict(d["smtp"])

        if d.get("ssl") is not None:
            d["ssl"] = SslEnrichment.from_dict(d["ssl"])

        certs_raw = d.get("certificates")
        if certs_raw is not None:
            d["certificates"] = [CertificateRecord.from_dict(c) for c in certs_raw]

        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


# ---------------------------------------------------------------------------
# Correlation result container
# ---------------------------------------------------------------------------


@dataclass
class CorrelationResult:
    """Container for the complete output of a Phase 3 Zeek log correlation run.

    Sessions are sorted by (ts or 0.0, uid) ascending for deterministic output.
    All non-fatal parse events are collected in ``warnings``.
    Unmatched records are preserved explicitly rather than silently discarded.
    """

    job_id: str | None
    log_directory_name: str | None
    sessions: list[CanonicalSession]
    unmatched_smtp_uids: list[str]
    unmatched_ssl_uids: list[str]
    unmatched_cert_fuids: list[str]
    warnings: list[ParseWarning]
    conn_records_read: int
    smtp_records_read: int
    ssl_records_read: int
    x509_records_read: int
    metadata_schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        d = asdict(self)
        # Apply from_ → "from" rename inside any smtp sub-dicts
        for session_dict in d.get("sessions", []):
            if session_dict.get("smtp") is not None and "from_" in session_dict["smtp"]:
                session_dict["smtp"]["from"] = session_dict["smtp"].pop("from_")
        return d

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
