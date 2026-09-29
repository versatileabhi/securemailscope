"""
Tests for CanonicalSession and Phase 3 schema models.
"""

import json

from securemailscope.schemas.session import (
    PHASE_3_LIMITATIONS,
    CanonicalSession,
    CertificateRecord,
    CorrelationResult,
    ParseWarning,
    SmtpEnrichment,
    SslEnrichment,
)


def test_canonical_session_to_dict_round_trip() -> None:
    session = CanonicalSession(
        uid="CiA7yB3xkFaQvInJl",
        job_id="job-12345",
        log_directory_name="zeek-job-12345",
        ts=1727520000.0,
        id_orig_h="192.168.1.10",
        id_orig_p=54321,
        id_resp_h="203.0.113.25",
        id_resp_p=587,
        proto="tcp",
        service="smtp",
        duration=1.234,
        orig_bytes=512,
        resp_bytes=1024,
        conn_state="SF",
        missed_bytes=0,
        smtp=SmtpEnrichment(
            uid="CiA7yB3xkFaQvInJl",
            ts=1727520001.0,
            helo="mail.example.com",
            mailfrom="alice@example.com",
            rcptto=["bob@target.org"],
            from_="Alice <alice@example.com>",
            to=["bob@target.org"],
            subject="Invoice",
            tls=True,
            fuids=["Fattach001"],
        ),
        ssl=SslEnrichment(
            uid="CiA7yB3xkFaQvInJl",
            ts=1727520000.5,
            version="TLSv12",
            server_name="mail.target.org",
            cert_chain_fuids=["Fcert001"],
        ),
        certificates=[
            CertificateRecord(
                fuid="Fcert001",
                certificate_subject="CN=mail.target.org",
                certificate_key_length=2048,
                san_dns=["mail.target.org"],
            )
        ],
    )

    data = session.to_dict()
    reconstructed = CanonicalSession.from_dict(data)

    assert reconstructed == session


def test_canonical_session_to_json_valid() -> None:
    session = CanonicalSession(
        uid="Ctest001",
        job_id="job-abc",
        log_directory_name="zeek-log-abc",
        ts=1727520000.0,
        id_orig_h="10.0.0.1",
        id_orig_p=12345,
        id_resp_h="10.0.0.2",
        id_resp_p=25,
    )

    json_str = session.to_json()
    parsed = json.loads(json_str)

    assert parsed["uid"] == "Ctest001"
    assert parsed["job_id"] == "job-abc"
    assert parsed["id_orig_h"] == "10.0.0.1"
    assert parsed["certificates"] == []
    assert parsed["smtp"] is None
    assert parsed["ssl"] is None


def test_smtp_from_field_serialized_correctly() -> None:
    smtp = SmtpEnrichment(
        uid="Ctest002",
        from_="sender@example.com",
    )
    session = CanonicalSession(
        uid="Ctest002",
        job_id=None,
        log_directory_name=None,
        smtp=smtp,
    )

    d = session.to_dict()
    assert "smtp" in d
    assert "from" in d["smtp"]
    assert "from_" not in d["smtp"]
    assert d["smtp"]["from"] == "sender@example.com"

    # Also test SmtpEnrichment alone
    smtp_dict = smtp.to_dict()
    assert "from" in smtp_dict
    assert "from_" not in smtp_dict
    assert smtp_dict["from"] == "sender@example.com"

    # Round trip from dict
    restored = SmtpEnrichment.from_dict(smtp_dict)
    assert restored.from_ == "sender@example.com"


def test_certificates_empty_list_by_default() -> None:
    session = CanonicalSession(
        uid="Ctest003",
        job_id=None,
        log_directory_name=None,
    )
    assert session.certificates == []
    assert session.smtp is None
    assert session.ssl is None


def test_limitations_populated() -> None:
    session = CanonicalSession(
        uid="Ctest004",
        job_id=None,
        log_directory_name=None,
    )
    assert len(session.limitations) == len(PHASE_3_LIMITATIONS)
    assert session.limitations == PHASE_3_LIMITATIONS
    assert PHASE_3_LIMITATIONS[0] in session.limitations


def test_metadata_schema_version() -> None:
    session = CanonicalSession(
        uid="Ctest005",
        job_id=None,
        log_directory_name=None,
    )
    assert session.metadata_schema_version == "1.0"


def test_correlation_result_round_trip() -> None:
    session = CanonicalSession(
        uid="Ctest006",
        job_id="job-999",
        log_directory_name="zeek-999",
        smtp=SmtpEnrichment(uid="Ctest006", from_="test@example.com"),
    )
    warning = ParseWarning(
        log_type="smtp",
        line_number=5,
        issue="Test warning",
        raw_line="bad line",
    )
    result = CorrelationResult(
        job_id="job-999",
        log_directory_name="zeek-999",
        sessions=[session],
        unmatched_smtp_uids=["U_smtp_1"],
        unmatched_ssl_uids=["U_ssl_1"],
        unmatched_cert_fuids=["U_fuid_1"],
        warnings=[warning],
        conn_records_read=1,
        smtp_records_read=2,
        ssl_records_read=1,
        x509_records_read=1,
    )

    d = result.to_dict()
    assert d["job_id"] == "job-999"
    assert d["sessions"][0]["smtp"]["from"] == "test@example.com"
    assert "from_" not in d["sessions"][0]["smtp"]
    assert len(d["warnings"]) == 1
    assert d["warnings"][0]["line_number"] == 5

    json_str = result.to_json()
    loaded = json.loads(json_str)
    assert loaded["job_id"] == "job-999"
    assert loaded["sessions"][0]["uid"] == "Ctest006"
