"""
Tests for SecureMailScope Zeek log correlator (Phase 3).
"""

import shutil
from pathlib import Path

import pytest

from securemailscope.canonicalization.correlator import correlate_zeek_logs
from securemailscope.exceptions import UnsafePathError

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "zeek_logs"


@pytest.fixture
def setup_log_dir(tmp_path: Path) -> Path:
    """Sets up a runtime log directory within tmp_path containing basic logs."""
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_test" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    shutil.copy(FIXTURES_DIR / "conn_basic.jsonl", runtime_dir / "conn.log")
    shutil.copy(FIXTURES_DIR / "smtp_basic.jsonl", runtime_dir / "smtp.log")
    shutil.copy(FIXTURES_DIR / "ssl_basic.jsonl", runtime_dir / "ssl.log")
    shutil.copy(FIXTURES_DIR / "x509_basic.jsonl", runtime_dir / "x509.log")

    return runtime_dir


def test_conn_only_produces_sessions(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_conn_only" / "zeek_logs"
    runtime_dir.mkdir(parents=True)
    shutil.copy(FIXTURES_DIR / "conn_basic.jsonl", runtime_dir / "conn.log")

    result = correlate_zeek_logs(
        runtime_dir,
        job_id="job_conn_only",
        runtime_root_path=tmp_path / "runtime",
    )

    assert result.job_id == "job_conn_only"
    assert result.log_directory_name == "zeek_logs"
    assert len(result.sessions) == 2
    assert result.conn_records_read == 2
    assert result.smtp_records_read == 0
    assert result.ssl_records_read == 0
    assert result.x509_records_read == 0

    s1, s2 = result.sessions
    assert s1.uid == "CiA7yB3xkFaQvInJl"
    assert s1.smtp is None
    assert s1.ssl is None
    assert s1.certificates == []

    assert s2.uid == "Dj8Bz4yLgGbRwJoKm"
    assert s2.smtp is None
    assert s2.ssl is None
    assert s2.certificates == []


def test_conn_smtp_correlation(setup_log_dir: Path, tmp_path: Path) -> None:
    result = correlate_zeek_logs(
        setup_log_dir,
        job_id="job_test",
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 2
    # In conn_basic.jsonl:
    # CiA7yB3xkFaQvInJl has ts=1727520000.0 (service=smtp)
    # Dj8Bz4yLgGbRwJoKm has ts=1727520005.0 (service=ssl)
    s_smtp = result.sessions[0]
    s_ssl = result.sessions[1]

    assert s_smtp.uid == "CiA7yB3xkFaQvInJl"
    assert s_smtp.smtp is not None
    assert s_smtp.smtp.helo == "mail.example.com"
    assert s_smtp.smtp.mailfrom == "alice@example.com"
    assert s_smtp.smtp.from_ == "Alice Smith <alice@example.com>"

    assert s_ssl.uid == "Dj8Bz4yLgGbRwJoKm"
    assert s_ssl.smtp is None


def test_conn_ssl_correlation(setup_log_dir: Path, tmp_path: Path) -> None:
    result = correlate_zeek_logs(
        setup_log_dir,
        job_id="job_test",
        runtime_root_path=tmp_path / "runtime",
    )

    s_smtp = result.sessions[0]
    s_ssl = result.sessions[1]

    assert s_smtp.ssl is None

    assert s_ssl.uid == "Dj8Bz4yLgGbRwJoKm"
    assert s_ssl.ssl is not None
    assert s_ssl.ssl.version == "TLSv12"
    assert s_ssl.ssl.server_name == "mail.target.org"
    assert s_ssl.ssl.cert_chain_fuids == ["FcertChain001"]


def test_ssl_x509_cert_chain_association(setup_log_dir: Path, tmp_path: Path) -> None:
    result = correlate_zeek_logs(
        setup_log_dir,
        job_id="job_test",
        runtime_root_path=tmp_path / "runtime",
    )

    s_ssl = result.sessions[1]
    assert len(s_ssl.certificates) == 1
    cert = s_ssl.certificates[0]
    assert cert.fuid == "FcertChain001"
    assert cert.certificate_subject == "CN=mail.target.org, O=Target Org, C=US"
    assert cert.certificate_key_length == 2048


def test_x509_direct_uid_join_not_performed(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_direct_x509" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    # conn has uid "ConnUid123"
    (runtime_dir / "conn.log").write_text(
        '{"uid": "ConnUid123", "ts": 100.0, "proto": "tcp"}\n',
        encoding="utf-8",
    )
    # x509 has fuid "ConnUid123" — even if fuid matches conn uid,
    # without ssl it shouldn't attach
    (runtime_dir / "x509.log").write_text(
        '{"fuid": "ConnUid123", "certificate_subject": "CN=direct"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        job_id="job_direct_x509",
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    # Must NOT have attached certificate directly to conn session without
    # ssl cert_chain_fuids
    assert result.sessions[0].certificates == []
    # And "ConnUid123" must be in unmatched_cert_fuids because no ssl referenced it
    assert "ConnUid123" in result.unmatched_cert_fuids


def test_unmatched_smtp_recorded(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_unmatched_smtp" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"uid": "Conn1", "ts": 100.0}\n',
        encoding="utf-8",
    )
    (runtime_dir / "smtp.log").write_text(
        '{"uid": "OrphanSmtpUid", "helo": "orphan.com"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    assert result.sessions[0].smtp is None
    assert result.unmatched_smtp_uids == ["OrphanSmtpUid"]


def test_unmatched_ssl_recorded(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_unmatched_ssl" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"uid": "Conn1", "ts": 100.0}\n',
        encoding="utf-8",
    )
    (runtime_dir / "ssl.log").write_text(
        '{"uid": "OrphanSslUid", "server_name": "orphan.com"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    assert result.sessions[0].ssl is None
    assert result.unmatched_ssl_uids == ["OrphanSslUid"]


def test_unmatched_cert_fuid_recorded(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_unmatched_cert" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"uid": "Conn1", "ts": 100.0}\n',
        encoding="utf-8",
    )
    (runtime_dir / "ssl.log").write_text(
        '{"uid": "Conn1", "cert_chain_fuids": ["Fcert1"]}\n',
        encoding="utf-8",
    )
    (runtime_dir / "x509.log").write_text(
        '{"fuid": "Fcert1", "certificate_subject": "CN=used"}\n'
        '{"fuid": "Fcert2_orphan", "certificate_subject": "CN=orphan"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    assert len(result.sessions[0].certificates) == 1
    assert result.sessions[0].certificates[0].fuid == "Fcert1"
    assert result.unmatched_cert_fuids == ["Fcert2_orphan"]


def test_missing_optional_log_non_fatal(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_missing_opt" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"uid": "Conn1", "ts": 100.0}\n',
        encoding="utf-8",
    )
    # smtp.log, ssl.log, x509.log are NOT created

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    assert result.sessions[0].uid == "Conn1"
    # Warnings for missing optional logs are recorded
    missing_warnings = [w for w in result.warnings if "not found" in w.issue.lower()]
    assert len(missing_warnings) == 3


def test_empty_optional_log_non_fatal(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_empty_opt" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"uid": "Conn1", "ts": 100.0}\n',
        encoding="utf-8",
    )
    (runtime_dir / "smtp.log").write_text("", encoding="utf-8")
    (runtime_dir / "ssl.log").write_text("", encoding="utf-8")
    (runtime_dir / "x509.log").write_text("", encoding="utf-8")

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    # Empty files produce 0 records and no warnings
    assert result.smtp_records_read == 0
    assert result.ssl_records_read == 0
    assert result.x509_records_read == 0
    assert len(result.warnings) == 0


def test_missing_uid_in_conn_skipped(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_missing_conn_uid" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"ts": 100.0, "proto": "tcp"}\n'
        '{"uid": "ValidUid", "ts": 101.0, "proto": "tcp"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    assert result.sessions[0].uid == "ValidUid"
    warnings = [w for w in result.warnings if "conn.log record missing" in w.issue]
    assert len(warnings) == 1


def test_missing_uid_in_smtp_skipped(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_missing_smtp_uid" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"uid": "Conn1", "ts": 100.0}\n',
        encoding="utf-8",
    )
    (runtime_dir / "smtp.log").write_text(
        '{"helo": "no_uid.com"}\n'
        '{"uid": "Conn1", "helo": "valid_uid.com"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    assert result.sessions[0].smtp is not None
    assert result.sessions[0].smtp.helo == "valid_uid.com"
    warnings = [w for w in result.warnings if "smtp.log record missing" in w.issue]
    assert len(warnings) == 1


def test_duplicate_uid_in_smtp_warns_last_wins(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_dup_smtp" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "conn.log").write_text(
        '{"uid": "Conn1", "ts": 100.0}\n',
        encoding="utf-8",
    )
    (runtime_dir / "smtp.log").write_text(
        '{"uid": "Conn1", "helo": "first.com"}\n'
        '{"uid": "Conn1", "helo": "second.com"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert len(result.sessions) == 1
    assert result.sessions[0].smtp is not None
    assert result.sessions[0].smtp.helo == "second.com"
    warnings = [w for w in result.warnings if "Duplicate uid 'Conn1'" in w.issue]
    assert len(warnings) == 1


def test_sessions_ordered_by_ts_then_uid(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_order" / "zeek_logs"
    runtime_dir.mkdir(parents=True)

    # Out of order records
    (runtime_dir / "conn.log").write_text(
        '{"uid": "Z_conn", "ts": 200.0}\n'
        '{"uid": "B_conn", "ts": 100.0}\n'
        '{"uid": "A_conn", "ts": 100.0}\n'
        '{"uid": "No_ts_2"}\n'
        '{"uid": "No_ts_1"}\n',
        encoding="utf-8",
    )

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    uids = [s.uid for s in result.sessions]
    # No ts records have (0.0, uid) -> "No_ts_1", "No_ts_2"
    # ts 100.0 -> "A_conn", "B_conn"
    # ts 200.0 -> "Z_conn"
    assert uids == ["No_ts_1", "No_ts_2", "A_conn", "B_conn", "Z_conn"]


def test_no_writes_during_correlation(setup_log_dir: Path, tmp_path: Path) -> None:
    files_before = {p: p.stat().st_mtime_ns for p in setup_log_dir.iterdir()}

    _ = correlate_zeek_logs(
        setup_log_dir,
        job_id="job_test",
        runtime_root_path=tmp_path / "runtime",
    )

    files_after = {p: p.stat().st_mtime_ns for p in setup_log_dir.iterdir()}

    assert set(files_before.keys()) == set(files_after.keys())
    assert files_before == files_after


def test_conn_records_read_count(setup_log_dir: Path, tmp_path: Path) -> None:
    result = correlate_zeek_logs(
        setup_log_dir,
        job_id="job_test",
        runtime_root_path=tmp_path / "runtime",
    )

    assert result.conn_records_read == 2
    assert result.smtp_records_read == 1
    assert result.ssl_records_read == 1
    assert result.x509_records_read == 1


def test_empty_conn_log_returns_empty_sessions(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime" / "jobs" / "job_empty_conn" / "zeek_logs"
    runtime_dir.mkdir(parents=True)
    (runtime_dir / "conn.log").write_text("", encoding="utf-8")

    result = correlate_zeek_logs(
        runtime_dir,
        runtime_root_path=tmp_path / "runtime",
    )

    assert result.sessions == []
    assert result.conn_records_read == 0


def test_path_outside_runtime_raises(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    outside_dir = tmp_path / "outside_runtime" / "zeek_logs"
    outside_dir.mkdir(parents=True)
    (outside_dir / "conn.log").write_text('{"uid": "c1"}\n', encoding="utf-8")

    with pytest.raises(UnsafePathError):
        correlate_zeek_logs(
            outside_dir,
            runtime_root_path=runtime_dir,
        )
