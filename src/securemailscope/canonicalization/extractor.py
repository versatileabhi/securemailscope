"""
SecureMailScope — Observation extractor (Phase 4).

Performs pure in-memory transformation from Phase 3 CanonicalSession
records to Phase 4 SessionObservation and ObservationResult models.

Guarantees:
    - Pure function: no filesystem writes, no network calls, no subprocesses.
    - Non-mutating: input CanonicalSession objects are never modified.
    - Deterministic: output observations sorted by (ts or 0.0, uid) ascending.
    - Non-evaluative: neutral summaries only, no security or risk judgments.
"""

from __future__ import annotations

from collections.abc import Sequence

from securemailscope.schemas.observation import (
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
    CanonicalSession,
    CertificateRecord,
    CorrelationResult,
    SmtpEnrichment,
    SslEnrichment,
)

# Standard mail ports for transport context evaluation
MAIL_PORTS: frozenset[int] = frozenset({25, 465, 587, 110, 143, 993, 995})


def _is_mail_context(session: CanonicalSession) -> bool:
    """Return True if session exhibits mail service, port, or protocol markers."""
    if session.service in ("smtp", "mail", "smtps", "submission"):
        return True
    if session.id_resp_p in MAIL_PORTS:
        return True
    if session.smtp is not None:
        return True
    return False


def _extract_smtp_observation(
    smtp: SmtpEnrichment | None,
    is_mail: bool,
) -> SmtpObservation:
    """Extract SmtpObservation from canonical SmtpEnrichment."""
    if smtp is None:
        if is_mail:
            return SmtpObservation(
                state="unavailable",
                missing_fields=["smtp_enrichment"],
            )
        return SmtpObservation(state="not_applicable")

    missing: list[str] = []
    if not smtp.helo:
        missing.append("helo")
    if not smtp.mailfrom:
        missing.append("mailfrom")
    if not smtp.rcptto:
        missing.append("rcptto")
    if not smtp.from_:
        missing.append("from")
    if not smtp.to:
        missing.append("to")
    if not smtp.subject:
        missing.append("subject")
    if not smtp.msg_id:
        missing.append("msg_id")

    return SmtpObservation(
        state="observed",
        helo=smtp.helo,
        mailfrom=smtp.mailfrom,
        rcptto=list(smtp.rcptto),
        from_=smtp.from_,
        to=list(smtp.to),
        reply_to=smtp.reply_to,
        msg_id=smtp.msg_id,
        subject=smtp.subject,
        user_agent=smtp.user_agent,
        is_webmail=smtp.is_webmail,
        fuids=list(smtp.fuids),
        trans_depth=smtp.trans_depth,
        missing_fields=missing,
        raw_values=smtp.to_dict(),
    )


def _extract_starttls_observation(
    session: CanonicalSession,
    is_mail: bool,
) -> StarttlsObservation:
    """Extract transport security observation and mail transport context."""
    smtp_flag = session.smtp.tls if session.smtp is not None else None
    has_tls = session.ssl is not None
    resp_p = session.id_resp_p
    service = session.service
    notes: list[str] = []

    if not is_mail:
        return StarttlsObservation(
            state="not_applicable",
            smtp_tls_flag=smtp_flag,
            correlated_tls_present=has_tls,
            mail_transport_context="not_applicable",
            responder_port=resp_p,
            service=service,
            evidence_notes=["Session is not in a mail transport context."],
        )

    # Mail transport context classification
    if session.smtp is not None and session.smtp.tls is True:
        notes.append(
            "Normalized SMTP TLS flag (smtp.tls) is True; "
            "does not confirm STARTTLS command transcript."
        )
        if has_tls:
            notes.append(
                "Correlated TLS session (ssl.log) is present on connection UID."
            )
        return StarttlsObservation(
            state="observed",
            smtp_tls_flag=True,
            correlated_tls_present=has_tls,
            mail_transport_context="smtp_tls_flagged",
            responder_port=resp_p,
            service=service,
            evidence_notes=notes,
        )

    if resp_p == 465 and has_tls:
        notes.append(
            "Correlated TLS observed on standard implicit TLS port 465; "
            "this is transport context, not STARTTLS."
        )
        return StarttlsObservation(
            state="observed",
            smtp_tls_flag=smtp_flag,
            correlated_tls_present=True,
            mail_transport_context="implicit_tls_context",
            responder_port=resp_p,
            service=service,
            evidence_notes=notes,
        )

    if has_tls:
        notes.append(
            "Correlated TLS session observed without an explicit SMTP TLS flag."
        )
        return StarttlsObservation(
            state="observed",
            smtp_tls_flag=smtp_flag,
            correlated_tls_present=True,
            mail_transport_context="correlated_tls",
            responder_port=resp_p,
            service=service,
            evidence_notes=notes,
        )

    if session.smtp is not None and session.smtp.tls is False and not has_tls:
        notes.append(
            "SMTP observed with explicit smtp.tls=False and no correlated TLS session."
        )
        return StarttlsObservation(
            state="observed",
            smtp_tls_flag=False,
            correlated_tls_present=False,
            mail_transport_context="cleartext_smtp_observed",
            responder_port=resp_p,
            service=service,
            evidence_notes=notes,
        )

    notes.append(
        "Mail-context session lacks sufficient SMTP or TLS evidence to determine "
        "transport security."
    )
    return StarttlsObservation(
        state="unavailable",
        smtp_tls_flag=smtp_flag,
        correlated_tls_present=has_tls,
        mail_transport_context="tls_status_unavailable",
        responder_port=resp_p,
        service=service,
        evidence_notes=notes,
    )


def _extract_tls_observation(
    ssl: SslEnrichment | None,
    is_mail: bool,
    resp_p: int | None,
) -> TlsObservation:
    """Extract TlsObservation from canonical SslEnrichment."""
    if ssl is None:
        if is_mail and resp_p == 465:
            return TlsObservation(
                state="unavailable",
                missing_fields=["ssl_enrichment"],
            )
        return TlsObservation(state="not_applicable")

    missing: list[str] = []
    if not ssl.version:
        missing.append("version")
    if not ssl.cipher:
        missing.append("cipher")
    if not ssl.server_name:
        missing.append("server_name")
    if ssl.established is None:
        missing.append("established")

    has_certs = bool(ssl.cert_chain_fuids)
    chain_confirmed = bool(ssl.cert_chain_fuids)

    return TlsObservation(
        state="observed",
        version=ssl.version,
        cipher=ssl.cipher,
        curve=ssl.curve,
        server_name=ssl.server_name,
        resumed=ssl.resumed,
        established=ssl.established,
        validation_status=ssl.validation_status,
        next_protocol=ssl.next_protocol,
        cert_chain_fuids=list(ssl.cert_chain_fuids),
        client_cert_chain_fuids=list(ssl.client_cert_chain_fuids),
        cert_chain_fuid_count=len(ssl.cert_chain_fuids),
        has_certificates=has_certs,
        server_chain_confirmed=chain_confirmed,
        missing_fields=missing,
        raw_values=ssl.to_dict(),
    )


def _extract_certificate_record(
    rec: CertificateRecord,
    chain_index: int,
    in_server_chain: bool,
) -> CertificateObservation:
    """Convert a single CertificateRecord to a CertificateObservation."""
    missing: list[str] = []
    if not rec.certificate_subject:
        missing.append("certificate_subject")
    if not rec.certificate_issuer:
        missing.append("certificate_issuer")
    if rec.certificate_not_valid_before is None:
        missing.append("certificate_not_valid_before")
    if rec.certificate_not_valid_after is None:
        missing.append("certificate_not_valid_after")

    return CertificateObservation(
        fuid=rec.fuid,
        chain_index=chain_index,
        in_server_chain=in_server_chain,
        record_available=True,
        subject=rec.certificate_subject,
        issuer=rec.certificate_issuer,
        serial=rec.certificate_serial,
        not_valid_before=rec.certificate_not_valid_before,
        not_valid_after=rec.certificate_not_valid_after,
        key_alg=rec.certificate_key_alg,
        sig_alg=rec.certificate_sig_alg,
        key_type=rec.certificate_key_type,
        key_length=rec.certificate_key_length,
        san_dns=list(rec.san_dns),
        san_ip=list(rec.san_ip),
        basic_constraints_ca=rec.basic_constraints_ca,
        missing_fields=missing,
    )


def _extract_certificates(
    session: CanonicalSession,
    warnings: list[str],
) -> tuple[list[CertificateObservation], list[CertificateObservation]]:
    """Extract server and unlinked certificate observations respecting chain order."""
    server_certs: list[CertificateObservation] = []
    unlinked_certs: list[CertificateObservation] = []

    ssl = session.ssl
    cert_map = {c.fuid: c for c in session.certificates if c.fuid}

    if ssl is not None and ssl.cert_chain_fuids:
        # ssl.cert_chain_fuids provides authoritative server-chain ordering
        seen_fuids: set[str] = set()
        for idx, fuid in enumerate(ssl.cert_chain_fuids):
            seen_fuids.add(fuid)
            if fuid in cert_map:
                server_certs.append(
                    _extract_certificate_record(
                        cert_map[fuid],
                        chain_index=idx,
                        in_server_chain=True,
                    )
                )
            else:
                warnings.append(
                    f"Server chain FUID '{fuid}' (index {idx}) in session "
                    f"'{session.uid}' has no matching CertificateRecord."
                )
                server_certs.append(
                    CertificateObservation(
                        fuid=fuid,
                        chain_index=idx,
                        in_server_chain=True,
                        record_available=False,
                        missing_fields=["certificate_record"],
                    )
                )

        # Retain any certificates present on the session not referenced
        # in the server chain
        for rec in session.certificates:
            if rec.fuid not in seen_fuids:
                warnings.append(
                    f"Certificate FUID '{rec.fuid}' in session '{session.uid}' "
                    "is not referenced in ssl.cert_chain_fuids; retained as unlinked."
                )
                unlinked_certs.append(
                    _extract_certificate_record(
                        rec,
                        chain_index=-1,
                        in_server_chain=False,
                    )
                )
    else:
        # Fallback ordering when ssl is absent or cert_chain_fuids is empty
        if session.certificates:
            warnings.append(
                f"Session '{session.uid}' has certificates without "
                "ssl.cert_chain_fuids; using deterministic fallback ordering "
                "(not confirmed TLS handshake order)."
            )
            sorted_fallback = sorted(session.certificates, key=lambda c: c.fuid or "")
            for idx, rec in enumerate(sorted_fallback):
                server_certs.append(
                    _extract_certificate_record(
                        rec,
                        chain_index=idx,
                        in_server_chain=False,
                    )
                )

    return server_certs, unlinked_certs


def _compute_coverage_state(
    smtp_obs: SmtpObservation,
    tls_obs: TlsObservation,
    server_certs: list[CertificateObservation],
) -> str:
    """Compute evidence coverage state: 'full', 'partial', or 'insufficient'."""
    has_smtp = smtp_obs.state == "observed"
    has_tls = tls_obs.state == "observed"
    has_certs = len(server_certs) > 0

    if has_smtp and has_tls and has_certs:
        return "full"

    # Explicit cleartext SMTP is considered full coverage of the cleartext transaction
    if has_smtp and not has_tls and smtp_obs.trans_depth is not None:
        return "full"

    if has_smtp or has_tls or has_certs:
        return "partial"

    return "insufficient"


def extract_observations(
    source: Sequence[CanonicalSession] | CorrelationResult,
) -> ObservationResult:
    """Extract structured protocol and cryptographic observations.

    Accepts either a sequence of CanonicalSession objects or a CorrelationResult.
    Performs pure in-memory extraction without modifying the input objects.

    Args:
        source: Canonical sessions or correlation result produced in Phase 3.

    Returns:
        ObservationResult with deterministic session observations and warnings.

    Guarantees:
        - No filesystem writes or reads.
        - No subprocess invocations.
        - No network operations.
        - Input objects are never mutated.
        - Output is deterministically ordered by (ts or 0.0, uid).
    """
    if isinstance(source, CorrelationResult):
        sessions = list(source.sessions)
        job_id = source.job_id
        log_dir_name = source.log_directory_name
    else:
        sessions = list(source)
        job_id = sessions[0].job_id if sessions else None
        log_dir_name = sessions[0].log_directory_name if sessions else None

    all_warnings: list[str] = []
    observations: list[SessionObservation] = []

    smtp_count = 0
    tls_count = 0
    cert_count = 0

    for session in sessions:
        is_mail = _is_mail_context(session)

        # 1. SMTP Observation
        smtp_obs = _extract_smtp_observation(session.smtp, is_mail)
        if smtp_obs.state == "observed":
            smtp_count += 1

        # 2. STARTTLS / Transport Context Observation
        starttls_obs = _extract_starttls_observation(session, is_mail)

        # 3. TLS Observation
        tls_obs = _extract_tls_observation(session.ssl, is_mail, session.id_resp_p)
        if tls_obs.state == "observed":
            tls_count += 1

        # 4. Certificates
        server_certs, unlinked_certs = _extract_certificates(session, all_warnings)
        if server_certs or unlinked_certs:
            cert_count += 1

        # 5. Coverage State
        coverage = _compute_coverage_state(smtp_obs, tls_obs, server_certs)

        obs = SessionObservation(
            uid=session.uid,
            job_id=session.job_id,
            log_directory_name=session.log_directory_name,
            ts=session.ts,
            orig_h=session.id_orig_h,
            orig_p=session.id_orig_p,
            resp_h=session.id_resp_h,
            resp_p=session.id_resp_p,
            proto=session.proto,
            service=session.service,
            smtp=smtp_obs,
            starttls=starttls_obs,
            tls=tls_obs,
            server_certificates=server_certs,
            unlinked_certificates=unlinked_certs,
            imap=ImapObservation(),
            pop3=Pop3Observation(),
            coverage_state=coverage,
        )
        observations.append(obs)

    # Sort deterministically: (ts or 0.0, uid) ascending
    observations.sort(key=lambda o: (o.ts or 0.0, o.uid))

    return ObservationResult(
        job_id=job_id,
        log_directory_name=log_dir_name,
        total_sessions=len(observations),
        sessions_with_smtp=smtp_count,
        sessions_with_tls=tls_count,
        sessions_with_certificates=cert_count,
        observations=observations,
        warnings=all_warnings,
    )
