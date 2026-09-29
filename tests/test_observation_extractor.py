"""
Tests for Phase 4 observation extractor (extract_observations).
"""

from pathlib import Path

from securemailscope.canonicalization.extractor import extract_observations
from securemailscope.schemas.session import (
    CanonicalSession,
    CertificateRecord,
    CorrelationResult,
    SmtpEnrichment,
    SslEnrichment,
)


def test_extract_empty_list() -> None:
    result = extract_observations([])
    assert result.total_sessions == 0
    assert result.observations == []
    assert result.warnings == []


def test_extract_empty_correlation_result() -> None:
    corr = CorrelationResult(
        job_id="job_empty",
        log_directory_name="logs_empty",
        sessions=[],
        unmatched_smtp_uids=[],
        unmatched_ssl_uids=[],
        unmatched_cert_fuids=[],
        warnings=[],
        conn_records_read=0,
        smtp_records_read=0,
        ssl_records_read=0,
        x509_records_read=0,
    )
    result = extract_observations(corr)
    assert result.job_id == "job_empty"
    assert result.log_directory_name == "logs_empty"
    assert result.total_sessions == 0
    assert result.observations == []


def test_extract_from_correlation_result() -> None:
    session = CanonicalSession(
        uid="C1",
        job_id="job_1",
        log_directory_name="logs_1",
        ts=100.0,
        id_resp_p=25,
        service="smtp",
    )
    corr = CorrelationResult(
        job_id="job_1",
        log_directory_name="logs_1",
        sessions=[session],
        unmatched_smtp_uids=[],
        unmatched_ssl_uids=[],
        unmatched_cert_fuids=[],
        warnings=[],
        conn_records_read=1,
        smtp_records_read=0,
        ssl_records_read=0,
        x509_records_read=0,
    )
    result = extract_observations(corr)
    assert result.job_id == "job_1"
    assert result.total_sessions == 1
    assert result.observations[0].uid == "C1"


def test_extract_smtp_full_data() -> None:
    smtp = SmtpEnrichment(
        uid="C_smtp",
        helo="mail.corp.com",
        mailfrom="alice@corp.com",
        rcptto=["bob@target.org"],
        from_="Alice <alice@corp.com>",
        to=["bob@target.org"],
        subject="Important notice",
        msg_id="<msg01@corp.com>",
        user_agent="Thunderbird",
        fuids=["Fattach1"],
        trans_depth=1,
    )
    session = CanonicalSession(
        uid="C_smtp",
        job_id=None,
        log_directory_name=None,
        id_resp_p=25,
        service="smtp",
        smtp=smtp,
    )

    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.smtp.state == "observed"
    assert obs.smtp.helo == "mail.corp.com"
    assert obs.smtp.mailfrom == "alice@corp.com"
    assert obs.smtp.from_ == "Alice <alice@corp.com>"
    assert obs.smtp.rcptto == ["bob@target.org"]
    assert obs.smtp.subject == "Important notice"
    assert obs.smtp.msg_id == "<msg01@corp.com>"
    assert obs.smtp.user_agent == "Thunderbird"
    assert obs.smtp.fuids == ["Fattach1"]
    assert obs.smtp.trans_depth == 1
    assert "from" in obs.smtp.raw_values


def test_extract_smtp_absent_in_mail_context() -> None:
    session = CanonicalSession(
        uid="C_no_smtp",
        job_id=None,
        log_directory_name=None,
        id_resp_p=587,
        service="smtp",
        smtp=None,
    )
    result = extract_observations([session])
    obs = result.observations[0]
    assert obs.smtp.state == "unavailable"
    assert "smtp_enrichment" in obs.smtp.missing_fields


def test_extract_smtp_non_mail_session() -> None:
    session = CanonicalSession(
        uid="C_web",
        job_id=None,
        log_directory_name=None,
        id_resp_p=80,
        service="http",
        smtp=None,
    )
    result = extract_observations([session])
    obs = result.observations[0]
    assert obs.smtp.state == "not_applicable"
    assert obs.starttls.state == "not_applicable"
    assert obs.starttls.mail_transport_context == "not_applicable"


def test_extract_starttls_smtp_tls_flagged() -> None:
    # Correction 1: smtp.tls is True -> context is "smtp_tls_flagged",
    # not "explicit_starttls"
    session = CanonicalSession(
        uid="C_tls_flag",
        job_id=None,
        log_directory_name=None,
        id_resp_p=587,
        service="smtp",
        smtp=SmtpEnrichment(uid="C_tls_flag", tls=True),
        ssl=SslEnrichment(uid="C_tls_flag", version="TLSv13"),
    )
    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.starttls.state == "observed"
    assert obs.starttls.smtp_tls_flag is True
    assert obs.starttls.correlated_tls_present is True
    assert obs.starttls.mail_transport_context == "smtp_tls_flagged"
    assert any("does not confirm STARTTLS" in n for n in obs.starttls.evidence_notes)


def test_extract_starttls_correlated_tls() -> None:
    # Correlated TLS on mail port without smtp.tls flag
    session = CanonicalSession(
        uid="C_corr_tls",
        job_id=None,
        log_directory_name=None,
        id_resp_p=25,
        service="smtp",
        smtp=SmtpEnrichment(uid="C_corr_tls", tls=None),
        ssl=SslEnrichment(uid="C_corr_tls", version="TLSv12"),
    )
    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.starttls.correlated_tls_present is True
    assert obs.starttls.mail_transport_context == "correlated_tls"


def test_extract_starttls_implicit_port_465() -> None:
    # Port 465 with TLS -> implicit_tls_context
    session = CanonicalSession(
        uid="C_smtps",
        job_id=None,
        log_directory_name=None,
        id_resp_p=465,
        service="ssl",
        ssl=SslEnrichment(uid="C_smtps", version="TLSv12"),
    )
    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.starttls.mail_transport_context == "implicit_tls_context"
    assert any("implicit TLS port 465" in n for n in obs.starttls.evidence_notes)


def test_extract_starttls_cleartext_smtp_observed() -> None:
    # Explicit smtp.tls=False and no SSL on mail port
    session = CanonicalSession(
        uid="C_clear",
        job_id=None,
        log_directory_name=None,
        id_resp_p=25,
        service="smtp",
        smtp=SmtpEnrichment(uid="C_clear", tls=False, trans_depth=1),
        ssl=None,
    )
    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.starttls.mail_transport_context == "cleartext_smtp_observed"
    assert obs.starttls.smtp_tls_flag is False
    assert obs.starttls.correlated_tls_present is False
    assert obs.coverage_state == "full"


def test_extract_tls_fields() -> None:
    ssl = SslEnrichment(
        uid="C_ssl",
        version="TLSv13",
        cipher="TLS_AES_256_GCM_SHA384",
        curve="x25519",
        server_name="mx.domain.com",
        resumed=False,
        established=True,
        validation_status="ok",
        next_protocol="smtp",
        cert_chain_fuids=["F1"],
    )
    session = CanonicalSession(
        uid="C_ssl",
        job_id=None,
        log_directory_name=None,
        id_resp_p=587,
        ssl=ssl,
    )
    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.tls.state == "observed"
    assert obs.tls.version == "TLSv13"
    assert obs.tls.cipher == "TLS_AES_256_GCM_SHA384"
    assert obs.tls.curve == "x25519"
    assert obs.tls.server_name == "mx.domain.com"
    assert obs.tls.established is True
    assert obs.tls.validation_status == "ok"
    assert obs.tls.next_protocol == "smtp"
    assert obs.tls.cert_chain_fuid_count == 1
    assert obs.tls.has_certificates is True
    assert obs.tls.server_chain_confirmed is True


def test_extract_tls_13_zero_certificates() -> None:
    # TLS 1.3 session with empty certificate list: has_certificates=False, no error
    ssl = SslEnrichment(
        uid="C_tls13",
        version="TLSv13",
        cipher="TLS_AES_128_GCM_SHA256",
        established=True,
        cert_chain_fuids=[],
    )
    session = CanonicalSession(
        uid="C_tls13",
        job_id=None,
        log_directory_name=None,
        id_resp_p=587,
        ssl=ssl,
        certificates=[],
    )
    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.tls.state == "observed"
    assert obs.tls.has_certificates is False
    assert obs.server_certificates == []
    assert obs.unlinked_certificates == []


def test_server_certificate_chain_ordering() -> None:
    # Correction 2: cert_chain_fuids order differs from session.certificates list order
    cert1 = CertificateRecord(fuid="F_leaf", certificate_subject="CN=leaf")
    cert2 = CertificateRecord(fuid="F_inter", certificate_subject="CN=intermediate")
    cert3 = CertificateRecord(fuid="F_root", certificate_subject="CN=root")

    # In session.certificates, order is root, leaf, inter
    session_certs = [cert3, cert1, cert2]

    # In ssl.cert_chain_fuids, order is leaf, intermediate, root
    ssl = SslEnrichment(
        uid="C_chain",
        cert_chain_fuids=["F_leaf", "F_inter", "F_root"],
    )

    session = CanonicalSession(
        uid="C_chain",
        job_id=None,
        log_directory_name=None,
        ssl=ssl,
        certificates=session_certs,
    )

    result = extract_observations([session])
    obs = result.observations[0]

    # Verify exact server chain order matches cert_chain_fuids
    assert len(obs.server_certificates) == 3
    assert [c.fuid for c in obs.server_certificates] == ["F_leaf", "F_inter", "F_root"]
    assert [c.chain_index for c in obs.server_certificates] == [0, 1, 2]
    assert all(c.in_server_chain for c in obs.server_certificates)
    assert obs.unlinked_certificates == []


def test_chain_fuid_missing_certificate_record() -> None:
    # Chain references F_missing, but only F_leaf is in session.certificates
    cert1 = CertificateRecord(fuid="F_leaf", certificate_subject="CN=leaf")
    ssl = SslEnrichment(
        uid="C_missing_rec",
        cert_chain_fuids=["F_leaf", "F_missing"],
    )
    session = CanonicalSession(
        uid="C_missing_rec",
        job_id=None,
        log_directory_name=None,
        ssl=ssl,
        certificates=[cert1],
    )

    result = extract_observations([session])
    obs = result.observations[0]

    assert len(obs.server_certificates) == 2
    c0, c1 = obs.server_certificates

    assert c0.fuid == "F_leaf"
    assert c0.record_available is True

    assert c1.fuid == "F_missing"
    assert c1.chain_index == 1
    assert c1.record_available is False
    assert "certificate_record" in c1.missing_fields

    # Non-fatal warning recorded
    assert any("has no matching CertificateRecord" in w for w in result.warnings)


def test_unlinked_certificate_retained() -> None:
    # session.certificates contains a cert not in ssl.cert_chain_fuids
    cert_chain = CertificateRecord(fuid="F_used", certificate_subject="CN=used")
    cert_orphan = CertificateRecord(fuid="F_orphan", certificate_subject="CN=orphan")

    ssl = SslEnrichment(
        uid="C_orphan",
        cert_chain_fuids=["F_used"],
    )
    session = CanonicalSession(
        uid="C_orphan",
        job_id=None,
        log_directory_name=None,
        ssl=ssl,
        certificates=[cert_chain, cert_orphan],
    )

    result = extract_observations([session])
    obs = result.observations[0]

    assert len(obs.server_certificates) == 1
    assert obs.server_certificates[0].fuid == "F_used"

    assert len(obs.unlinked_certificates) == 1
    assert obs.unlinked_certificates[0].fuid == "F_orphan"
    assert obs.unlinked_certificates[0].in_server_chain is False

    assert any("retained as unlinked" in w for w in result.warnings)


def test_client_cert_chain_fuids_not_in_server_chain() -> None:
    # Client cert chain is kept on TlsObservation and not mixed into server_certificates
    ssl = SslEnrichment(
        uid="C_client_cert",
        cert_chain_fuids=["F_server"],
        client_cert_chain_fuids=["F_client"],
    )
    cert_server = CertificateRecord(fuid="F_server", certificate_subject="CN=server")
    cert_client = CertificateRecord(fuid="F_client", certificate_subject="CN=client")

    session = CanonicalSession(
        uid="C_client_cert",
        job_id=None,
        log_directory_name=None,
        ssl=ssl,
        certificates=[cert_server, cert_client],
    )

    result = extract_observations([session])
    obs = result.observations[0]

    # Server chain contains only F_server
    assert [c.fuid for c in obs.server_certificates] == ["F_server"]
    # Client cert is retained in unlinked_certificates, not claimed as server chain
    assert [c.fuid for c in obs.unlinked_certificates] == ["F_client"]
    # Client chain FUID is preserved on TlsObservation
    assert obs.tls.client_cert_chain_fuids == ["F_client"]


def test_deterministic_fallback_cert_ordering() -> None:
    # No ssl.cert_chain_fuids -> fallback deterministic ordering by FUID
    c_b = CertificateRecord(fuid="F_beta", certificate_subject="CN=beta")
    c_a = CertificateRecord(fuid="F_alpha", certificate_subject="CN=alpha")

    session = CanonicalSession(
        uid="C_fallback",
        job_id=None,
        log_directory_name=None,
        ssl=None,
        certificates=[c_b, c_a],
    )

    result = extract_observations([session])
    obs = result.observations[0]

    assert [c.fuid for c in obs.server_certificates] == ["F_alpha", "F_beta"]
    assert all(not c.in_server_chain for c in obs.server_certificates)
    assert any("deterministic fallback ordering" in w for w in result.warnings)


def test_imap_and_pop3_reported_unsupported() -> None:
    session = CanonicalSession(
        uid="C_mail",
        job_id=None,
        log_directory_name=None,
        id_resp_p=993,
        service="imap",
    )
    result = extract_observations([session])
    obs = result.observations[0]

    assert obs.imap.state == "unsupported_by_current_input"
    assert "not implemented" in obs.imap.reason
    assert obs.pop3.state == "unsupported_by_current_input"
    assert "not implemented" in obs.pop3.reason


def test_coverage_state_insufficient() -> None:
    # Bare connection without SMTP or SSL enrichment
    session = CanonicalSession(
        uid="C_bare",
        job_id=None,
        log_directory_name=None,
        id_resp_p=80,
    )
    result = extract_observations([session])
    assert result.observations[0].coverage_state == "insufficient"


def test_input_immutability() -> None:
    # Verify input CanonicalSession is not modified by extract_observations
    smtp = SmtpEnrichment(uid="C_mut", helo="helo.org")
    session = CanonicalSession(
        uid="C_mut",
        job_id=None,
        log_directory_name=None,
        smtp=smtp,
    )
    dict_before = session.to_dict()

    _ = extract_observations([session])

    dict_after = session.to_dict()
    assert dict_before == dict_after


def test_no_filesystem_writes(tmp_path: Path) -> None:
    # Asserts extraction creates zero files
    session = CanonicalSession(uid="C_nowrite", job_id=None, log_directory_name=None)
    items_before = set(tmp_path.iterdir())

    _ = extract_observations([session])

    items_after = set(tmp_path.iterdir())
    assert items_before == items_after


def test_deterministic_output_order() -> None:
    # Sessions out of chronological order must be returned sorted by (ts or 0.0, uid)
    s3 = CanonicalSession(uid="C_3", job_id=None, log_directory_name=None, ts=300.0)
    s1 = CanonicalSession(uid="C_1", job_id=None, log_directory_name=None, ts=100.0)
    s2 = CanonicalSession(uid="C_2", job_id=None, log_directory_name=None, ts=200.0)
    s0 = CanonicalSession(uid="C_0", job_id=None, log_directory_name=None, ts=None)

    result = extract_observations([s3, s1, s2, s0])
    uids = [o.uid for o in result.observations]
    assert uids == ["C_0", "C_1", "C_2", "C_3"]
