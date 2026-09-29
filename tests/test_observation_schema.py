"""
Tests for Phase 4 observation schema models.
"""

import json

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


def test_session_observation_round_trip() -> None:
    session_obs = SessionObservation(
        uid="C_test_001",
        job_id="job_001",
        log_directory_name="zeek_job_001",
        ts=1727520000.0,
        orig_h="192.168.1.10",
        orig_p=54321,
        resp_h="203.0.113.25",
        resp_p=587,
        proto="tcp",
        service="smtp",
        smtp=SmtpObservation(
            state="observed",
            helo="mail.example.com",
            mailfrom="sender@example.com",
            rcptto=["rcpt@target.org"],
            from_="Sender <sender@example.com>",
            to=["rcpt@target.org"],
            subject="Status update",
            fuids=["Fattach1"],
        ),
        starttls=StarttlsObservation(
            state="observed",
            smtp_tls_flag=True,
            correlated_tls_present=True,
            mail_transport_context="smtp_tls_flagged",
            responder_port=587,
            service="smtp",
            evidence_notes=["TLS flag observed."],
        ),
        tls=TlsObservation(
            state="observed",
            version="TLSv13",
            cipher="TLS_AES_256_GCM_SHA384",
            server_name="mail.target.org",
            cert_chain_fuids=["Fcert1"],
            cert_chain_fuid_count=1,
            has_certificates=True,
            server_chain_confirmed=True,
        ),
        server_certificates=[
            CertificateObservation(
                fuid="Fcert1",
                chain_index=0,
                in_server_chain=True,
                record_available=True,
                subject="CN=mail.target.org",
                issuer="CN=Test CA",
                key_length=2048,
                san_dns=["mail.target.org"],
            )
        ],
        unlinked_certificates=[],
        imap=ImapObservation(),
        pop3=Pop3Observation(),
        coverage_state="full",
    )

    d = session_obs.to_dict()
    assert d["uid"] == "C_test_001"
    assert d["smtp"]["from"] == "Sender <sender@example.com>"
    assert "from_" not in d["smtp"]
    assert len(d["server_certificates"]) == 1
    assert d["server_certificates"][0]["fuid"] == "Fcert1"

    # JSON round trip
    json_str = session_obs.to_json()
    parsed_json = json.loads(json_str)
    assert parsed_json["uid"] == "C_test_001"

    # Dataclass reconstruction
    restored = SessionObservation.from_dict(d)
    assert restored.uid == session_obs.uid
    assert restored.smtp.from_ == session_obs.smtp.from_
    assert restored.starttls.mail_transport_context == "smtp_tls_flagged"
    assert restored.server_certificates[0].fuid == "Fcert1"
    assert restored.coverage_state == "full"


def test_observation_result_to_dict_and_json() -> None:
    session_obs = SessionObservation(
        uid="C_test_002",
        job_id=None,
        log_directory_name=None,
        ts=None,
        orig_h=None,
        orig_p=None,
        resp_h=None,
        resp_p=None,
        proto=None,
        service=None,
        smtp=SmtpObservation(state="not_applicable"),
        starttls=StarttlsObservation(state="not_applicable"),
        tls=TlsObservation(state="not_applicable"),
    )
    result = ObservationResult(
        job_id="job_test",
        log_directory_name="logs",
        total_sessions=1,
        sessions_with_smtp=0,
        sessions_with_tls=0,
        sessions_with_certificates=0,
        observations=[session_obs],
        warnings=["Non-fatal test warning"],
    )

    d = result.to_dict()
    assert d["job_id"] == "job_test"
    assert len(d["observations"]) == 1
    assert len(d["warnings"]) == 1

    json_str = result.to_json()
    loaded = json.loads(json_str)
    assert loaded["total_sessions"] == 1
    assert loaded["warnings"] == ["Non-fatal test warning"]


def test_smtp_from_field_serialization() -> None:
    smtp = SmtpObservation(
        state="observed",
        from_="user@domain.com",
    )
    d = smtp.to_dict()
    assert "from" in d
    assert "from_" not in d
    assert d["from"] == "user@domain.com"

    restored = SmtpObservation.from_dict(d)
    assert restored.from_ == "user@domain.com"


def test_smtp_observation_defaults() -> None:
    smtp = SmtpObservation()
    assert smtp.state == "not_applicable"
    assert smtp.rcptto == []
    assert smtp.to == []
    assert smtp.fuids == []
    assert smtp.missing_fields == []
    assert smtp.raw_values == {}


def test_tls_observation_defaults() -> None:
    tls = TlsObservation()
    assert tls.state == "not_applicable"
    assert tls.cert_chain_fuids == []
    assert tls.client_cert_chain_fuids == []
    assert tls.cert_chain_fuid_count == 0
    assert tls.has_certificates is False
    assert tls.server_chain_confirmed is False


def test_certificate_observation_defaults() -> None:
    cert = CertificateObservation(fuid="F123")
    assert cert.fuid == "F123"
    assert cert.chain_index == 0
    assert cert.in_server_chain is True
    assert cert.record_available is True
    assert cert.san_dns == []
    assert cert.san_ip == []


def test_imap_pop3_default_unsupported() -> None:
    imap = ImapObservation()
    assert imap.state == "unsupported_by_current_input"
    assert "not implemented" in imap.reason

    pop3 = Pop3Observation()
    assert pop3.state == "unsupported_by_current_input"
    assert "not implemented" in pop3.reason


def test_phase_4_limitations_embedded() -> None:
    session_obs = SessionObservation(
        uid="C_test_003",
        job_id=None,
        log_directory_name=None,
        ts=None,
        orig_h=None,
        orig_p=None,
        resp_h=None,
        resp_p=None,
        proto=None,
        service=None,
        smtp=SmtpObservation(),
        starttls=StarttlsObservation(),
        tls=TlsObservation(),
    )
    assert len(session_obs.limitations) == len(PHASE_4_LIMITATIONS)
    assert session_obs.limitations == PHASE_4_LIMITATIONS
    assert "STARTTLS command transcript" in session_obs.limitations[1]
