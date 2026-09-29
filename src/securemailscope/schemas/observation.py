"""
SecureMailScope — Canonical observation schema (Phase 4).

Defines structured, neutral, explainable dataclass models for extracted
mail protocol (SMTP), transport context (STARTTLS / implicit TLS),
cryptographic parameters (TLS), and certificate metadata (X.509).

Non-evaluative design principle:
    Observations record what was seen or what is unavailable.
    They never claim maliciousness, legitimacy, compliance, security,
    insecurity, risk scores, or threat verdicts.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

PHASE_4_LIMITATIONS: list[str] = [
    "Phase 4 extracts neutral, explainable observations from Phase 3 canonical "
    "sessions; no detection rules, risk scoring, ML ranking, reporting, or "
    "dashboard are implemented.",
    "The smtp.tls indicator reflects a normalized Zeek flag only; it does not "
    "confirm an observed STARTTLS command transcript exchange.",
    "Server certificate chain order is established strictly from "
    "ssl.cert_chain_fuids when present; fallback ordering does not confirm "
    "TLS handshake order.",
    "Client certificate chain evidence (client_cert_chain_fuids) is not part "
    "of the server certificate chain.",
    "IMAP and POP3 observations report unsupported_by_current_input because "
    "Phase 3 does not ingest imap.log or pop3.log.",
    "Phase 4 does not perform security evaluation, cipher grading, certificate "
    "trust validation, expiration checking, or attack classification.",
]


# ---------------------------------------------------------------------------
# Protocol and Transport Observations
# ---------------------------------------------------------------------------


@dataclass
class SmtpObservation:
    """Normalized SMTP observations extracted from canonical session enrichment.

    Attributes:
        state: "observed" when SMTP data is present, "unavailable" when in a
            mail transport context but absent, or "not_applicable" for non-mail.
        helo: HELO/EHLO greeting banner domain/hostname.
        mailfrom: Reverse-path mailbox address from MAIL FROM.
        rcptto: Forward-path mailbox addresses from RCPT TO.
        from_: Display/header sender from the email header "From:".
        to: Recipient addresses from the email header "To:".
        reply_to: Address from the email header "Reply-To:".
        msg_id: Value from the email header "Message-ID:".
        subject: Subject line header.
        user_agent: User agent string if observed.
        is_webmail: Whether webmail origin was flagged in normalization.
        fuids: File UIDs associated with message attachments/payloads.
        trans_depth: Transaction depth within the connection.
        missing_fields: List of expected SMTP fields that were absent.
        raw_values: Preserved raw normalized values from canonical input.
    """

    state: str = "not_applicable"  # "observed" | "unavailable" | "not_applicable"
    helo: str | None = None
    mailfrom: str | None = None
    rcptto: list[str] = field(default_factory=list)
    from_: str | None = None
    to: list[str] = field(default_factory=list)
    reply_to: str | None = None
    msg_id: str | None = None
    subject: str | None = None
    user_agent: str | None = None
    is_webmail: bool | None = None
    fuids: list[str] = field(default_factory=list)
    trans_depth: int | None = None
    missing_fields: list[str] = field(default_factory=list)
    raw_values: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, remapping ``from_`` → ``"from"``."""
        d = asdict(self)
        if "from_" in d:
            d["from"] = d.pop("from_")
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SmtpObservation:
        """Construct from a dictionary, remapping ``"from"`` → ``from_``."""
        d = dict(data)
        if "from" in d:
            d["from_"] = d.pop("from")
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


@dataclass
class StarttlsObservation:
    """Observation of transport security indicators and mail transport context.

    Records the independent evidence flags without concluding whether a
    STARTTLS upgrade exchange occurred or whether the session is secure.

    Allowed ``mail_transport_context`` values:
        - "smtp_tls_flagged": smtp.tls is True in canonical enrichment.
        - "correlated_tls": session.ssl is present on a mail-context session.
        - "implicit_tls_context": session.ssl is present and responder port is 465.
        - "cleartext_smtp_observed": SMTP present, smtp.tls is False, session.ssl
          is absent, and session is in a mail context.
        - "tls_status_unavailable": mail-context session lacks sufficient evidence.
        - "not_applicable": non-mail session.
    """

    state: str = "not_applicable"  # "observed" | "unavailable" | "not_applicable"
    smtp_tls_flag: bool | None = None
    correlated_tls_present: bool = False
    mail_transport_context: str = "not_applicable"
    responder_port: int | None = None
    service: str | None = None
    evidence_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StarttlsObservation:
        """Construct from a dictionary."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class TlsObservation:
    """TLS handshake parameters normalized from ssl.log.

    Attributes:
        state: "observed", "unavailable", or "not_applicable".
        version: Negotiated TLS/SSL protocol version (e.g. "TLSv12", "TLSv13").
        cipher: Negotiated cipher suite string.
        curve: Elliptic curve if ECDHE used.
        server_name: Server Name Indication (SNI) string.
        resumed: Whether TLS session resumption was flagged.
        established: Whether the TLS handshake completed successfully.
        validation_status: OpenSSL/Zeek validation result string.
        next_protocol: ALPN negotiated protocol identifier.
        cert_chain_fuids: Server certificate chain FUID list from ssl.log.
        client_cert_chain_fuids: Client certificate chain FUID list from ssl.log.
        cert_chain_fuid_count: Length of cert_chain_fuids.
        has_certificates: True if at least one certificate record was linked.
        server_chain_confirmed: True if cert order is confirmed by cert_chain_fuids.
        missing_fields: List of expected TLS fields that were absent.
        raw_values: Preserved raw values from canonical input.
    """

    state: str = "not_applicable"  # "observed" | "unavailable" | "not_applicable"
    version: str | None = None
    cipher: str | None = None
    curve: str | None = None
    server_name: str | None = None
    resumed: bool | None = None
    established: bool | None = None
    validation_status: str | None = None
    next_protocol: str | None = None
    cert_chain_fuids: list[str] = field(default_factory=list)
    client_cert_chain_fuids: list[str] = field(default_factory=list)
    cert_chain_fuid_count: int = 0
    has_certificates: bool = False
    server_chain_confirmed: bool = False
    missing_fields: list[str] = field(default_factory=list)
    raw_values: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TlsObservation:
        """Construct from a dictionary."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class CertificateObservation:
    """X.509 certificate attributes extracted from canonical session evidence.

    Attributes:
        fuid: File UID identifying the certificate artifact.
        chain_index: 0-indexed position in the server certificate chain.
        in_server_chain: True if referenced in ssl.cert_chain_fuids.
        record_available: True if full CertificateRecord details were found.
        subject: Certificate subject distinguished name (DN).
        issuer: Certificate issuer distinguished name (DN).
        serial: Serial number string.
        not_valid_before: Validity start epoch timestamp.
        not_valid_after: Validity end epoch timestamp.
        key_alg: Public key algorithm.
        sig_alg: Signature algorithm.
        key_type: Key type identifier.
        key_length: Key length in bits.
        san_dns: Subject Alternative Name DNS entries.
        san_ip: Subject Alternative Name IP entries.
        basic_constraints_ca: CA basic constraint boolean.
        missing_fields: List of expected certificate fields that were absent.
    """

    fuid: str
    chain_index: int = 0
    in_server_chain: bool = True
    record_available: bool = True
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    not_valid_before: float | None = None
    not_valid_after: float | None = None
    key_alg: str | None = None
    sig_alg: str | None = None
    key_type: str | None = None
    key_length: int | None = None
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    basic_constraints_ca: bool | None = None
    missing_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CertificateObservation:
        """Construct from a dictionary."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class ImapObservation:
    """IMAP protocol observation placeholder documenting unsupported status."""

    state: str = "unsupported_by_current_input"
    reason: str = (
        "IMAP log ingestion (imap.log) is not implemented in the Phase 3 "
        "canonicalization pipeline."
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ImapObservation:
        """Construct from a dictionary."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class Pop3Observation:
    """POP3 protocol observation placeholder documenting unsupported status."""

    state: str = "unsupported_by_current_input"
    reason: str = (
        "POP3 log ingestion (pop3.log) is not implemented in the Phase 3 "
        "canonicalization pipeline."
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Pop3Observation:
        """Construct from a dictionary."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


# ---------------------------------------------------------------------------
# Aggregated Session and Run Observations
# ---------------------------------------------------------------------------


@dataclass
class SessionObservation:
    """Complete structured observation bundle for a single canonical session."""

    uid: str
    job_id: str | None
    log_directory_name: str | None
    ts: float | None
    orig_h: str | None
    orig_p: int | None
    resp_h: str | None
    resp_p: int | None
    proto: str | None
    service: str | None

    smtp: SmtpObservation
    starttls: StarttlsObservation
    tls: TlsObservation
    server_certificates: list[CertificateObservation] = field(default_factory=list)
    unlinked_certificates: list[CertificateObservation] = field(default_factory=list)
    imap: ImapObservation = field(default_factory=ImapObservation)
    pop3: Pop3Observation = field(default_factory=Pop3Observation)

    coverage_state: str = "insufficient"  # "full" | "partial" | "insufficient"
    limitations: list[str] = field(
        default_factory=lambda: list(PHASE_4_LIMITATIONS)
    )
    metadata_schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, recursively converting nested observations."""
        d = asdict(self)
        if d.get("smtp") is not None and "from_" in d["smtp"]:
            d["smtp"]["from"] = d["smtp"].pop("from_")
        return d

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionObservation:
        """Construct from dictionary, reconstructing nested observation dataclasses."""
        d = dict(data)

        if d.get("smtp") is not None:
            d["smtp"] = SmtpObservation.from_dict(d["smtp"])

        if d.get("starttls") is not None:
            d["starttls"] = StarttlsObservation.from_dict(d["starttls"])

        if d.get("tls") is not None:
            d["tls"] = TlsObservation.from_dict(d["tls"])

        if d.get("server_certificates") is not None:
            d["server_certificates"] = [
                CertificateObservation.from_dict(c) for c in d["server_certificates"]
            ]

        if d.get("unlinked_certificates") is not None:
            d["unlinked_certificates"] = [
                CertificateObservation.from_dict(c) for c in d["unlinked_certificates"]
            ]

        if d.get("imap") is not None:
            d["imap"] = ImapObservation.from_dict(d["imap"])

        if d.get("pop3") is not None:
            d["pop3"] = Pop3Observation.from_dict(d["pop3"])

        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


@dataclass
class ObservationResult:
    """Container for the output of a Phase 4 observation extraction run."""

    job_id: str | None
    log_directory_name: str | None
    total_sessions: int
    sessions_with_smtp: int
    sessions_with_tls: int
    sessions_with_certificates: int
    observations: list[SessionObservation]
    warnings: list[str]
    metadata_schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        for s in d.get("observations", []):
            if s.get("smtp") is not None and "from_" in s["smtp"]:
                s["smtp"]["from"] = s["smtp"].pop("from_")
        return d

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
