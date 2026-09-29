"""
SecureMailScope — Zeek log correlator.

Reads conn.log, smtp.log, ssl.log, and x509.log from a per-job Zeek log
directory and correlates them into a list of CanonicalSession records.

Correlation join paths:
    conn.log  → smtp.log : conn.uid == smtp.uid
    conn.log  → ssl.log  : conn.uid == ssl.uid
    ssl.log   → x509.log : ssl.cert_chain_fuids[] == x509.fuid

There is no direct conn.uid → x509.fuid mapping in standard Zeek output.
Phase 3 does not attempt such a join.

This module never writes files, makes network connections, or invokes
subprocesses.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from securemailscope.paths import ensure_within_runtime, runtime_root
from securemailscope.schemas.session import (
    CanonicalSession,
    CertificateRecord,
    CorrelationResult,
    ParseWarning,
    SmtpEnrichment,
    SslEnrichment,
)
from securemailscope.zeek.log_reader import read_jsonl_log

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_CONN_FIELDS: frozenset[str] = frozenset({
    "uid", "ts",
    "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration",
    "orig_bytes", "resp_bytes", "conn_state", "missed_bytes",
})


def _build_smtp_map(
    records: list[dict[str, Any]],
    warnings: list[ParseWarning],
) -> dict[str, SmtpEnrichment]:
    """Build uid → SmtpEnrichment map; emit warnings for bad records."""
    result: dict[str, SmtpEnrichment] = {}
    for rec in records:
        uid = rec.get("uid", "")
        if not uid or not isinstance(uid, str) or not uid.strip():
            warnings.append(
                ParseWarning(
                    log_type="smtp",
                    line_number=0,
                    issue="smtp.log record missing or blank uid; record skipped.",
                    raw_line=None,
                )
            )
            continue
        if uid in result:
            warnings.append(
                ParseWarning(
                    log_type="smtp",
                    line_number=0,
                    issue=f"Duplicate uid '{uid}' in smtp.log; last record wins.",
                    raw_line=None,
                )
            )
        # Map "from" → "from_" before construction
        mapped = dict(rec)
        if "from" in mapped:
            mapped["from_"] = mapped.pop("from")
        result[uid] = SmtpEnrichment.from_dict(mapped)
    return result


def _build_ssl_map(
    records: list[dict[str, Any]],
    warnings: list[ParseWarning],
) -> dict[str, SslEnrichment]:
    """Build uid → SslEnrichment map; emit warnings for bad records."""
    result: dict[str, SslEnrichment] = {}
    for rec in records:
        uid = rec.get("uid", "")
        if not uid or not isinstance(uid, str) or not uid.strip():
            warnings.append(
                ParseWarning(
                    log_type="ssl",
                    line_number=0,
                    issue="ssl.log record missing or blank uid; record skipped.",
                    raw_line=None,
                )
            )
            continue
        if uid in result:
            warnings.append(
                ParseWarning(
                    log_type="ssl",
                    line_number=0,
                    issue=f"Duplicate uid '{uid}' in ssl.log; last record wins.",
                    raw_line=None,
                )
            )
        result[uid] = SslEnrichment.from_dict(rec)
    return result


def _build_cert_map(
    records: list[dict[str, Any]],
    warnings: list[ParseWarning],
) -> dict[str, CertificateRecord]:
    """Build fuid → CertificateRecord map; emit warnings for bad records."""
    result: dict[str, CertificateRecord] = {}
    for rec in records:
        fuid = rec.get("fuid", "")
        if not fuid or not isinstance(fuid, str) or not fuid.strip():
            warnings.append(
                ParseWarning(
                    log_type="x509",
                    line_number=0,
                    issue="x509.log record missing or blank fuid; record skipped.",
                    raw_line=None,
                )
            )
            continue
        if fuid in result:
            warnings.append(
                ParseWarning(
                    log_type="x509",
                    line_number=0,
                    issue=f"Duplicate fuid '{fuid}' in x509.log; last record wins.",
                    raw_line=None,
                )
            )
        result[fuid] = CertificateRecord.from_dict(rec)
    return result


def _session_from_conn_record(
    rec: dict[str, Any],
    *,
    job_id: str | None,
    log_directory_name: str | None,
) -> CanonicalSession:
    """Construct a CanonicalSession from a raw conn.log dict."""
    # Zeek uses dotted keys like "id.orig_h" — handle both forms.
    return CanonicalSession(
        uid=rec["uid"],
        job_id=job_id,
        log_directory_name=log_directory_name,
        ts=rec.get("ts"),
        id_orig_h=rec.get("id.orig_h") or rec.get("id", {}).get("orig_h"),
        id_orig_p=rec.get("id.orig_p") or rec.get("id", {}).get("orig_p"),
        id_resp_h=rec.get("id.resp_h") or rec.get("id", {}).get("resp_h"),
        id_resp_p=rec.get("id.resp_p") or rec.get("id", {}).get("resp_p"),
        proto=rec.get("proto"),
        service=rec.get("service"),
        duration=rec.get("duration"),
        orig_bytes=rec.get("orig_bytes"),
        resp_bytes=rec.get("resp_bytes"),
        conn_state=rec.get("conn_state"),
        missed_bytes=rec.get("missed_bytes"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate_zeek_logs(
    log_directory: Path,
    *,
    job_id: str | None = None,
    runtime_root_path: Path | None = None,
) -> CorrelationResult:
    """Read and correlate Zeek JSON logs into canonical session records.

    Reads conn.log, smtp.log, ssl.log, and x509.log from ``log_directory``.
    smtp.log, ssl.log, and x509.log are optional; their absence is recorded
    as a ParseWarning and does not prevent session construction.

    Args:
        log_directory: Path to the per-job Zeek log output directory.
        job_id: Optional job ID for provenance metadata in session records.
        runtime_root_path: Optional override for runtime root containment checks.

    Returns:
        CorrelationResult containing sorted sessions, unmatched records,
        warnings, and record counts.

    Raises:
        UnsafePathError: If ``log_directory`` is not within the runtime root.

    Guarantees:
        - No filesystem writes.
        - No network access or subprocess calls.
        - Sessions sorted by (ts or 0.0, uid) ascending.
        - All non-fatal issues collected in CorrelationResult.warnings.
    """
    root = runtime_root(runtime_root_path)
    resolved_log_dir = Path(log_directory).resolve()
    ensure_within_runtime(resolved_log_dir, root)

    log_dir_name = resolved_log_dir.name
    all_warnings: list[ParseWarning] = []

    # -----------------------------------------------------------------------
    # 1. Read all four log files
    # -----------------------------------------------------------------------
    conn_records, conn_warnings = read_jsonl_log(
        resolved_log_dir / "conn.log", log_type="conn"
    )
    all_warnings.extend(conn_warnings)

    smtp_records, smtp_warnings = read_jsonl_log(
        resolved_log_dir / "smtp.log", log_type="smtp"
    )
    all_warnings.extend(smtp_warnings)

    ssl_records, ssl_warnings = read_jsonl_log(
        resolved_log_dir / "ssl.log", log_type="ssl"
    )
    all_warnings.extend(ssl_warnings)

    x509_records, x509_warnings = read_jsonl_log(
        resolved_log_dir / "x509.log", log_type="x509"
    )
    all_warnings.extend(x509_warnings)

    # -----------------------------------------------------------------------
    # 2. Build enrichment maps
    # -----------------------------------------------------------------------
    smtp_map = _build_smtp_map(smtp_records, all_warnings)
    ssl_map = _build_ssl_map(ssl_records, all_warnings)
    cert_map = _build_cert_map(x509_records, all_warnings)

    # -----------------------------------------------------------------------
    # 3. Build sessions from conn.log
    # -----------------------------------------------------------------------
    sessions: list[CanonicalSession] = []
    seen_conn_uids: set[str] = set()

    for rec in conn_records:
        uid = rec.get("uid", "")
        if not uid or not isinstance(uid, str) or not uid.strip():
            all_warnings.append(
                ParseWarning(
                    log_type="conn",
                    line_number=0,
                    issue="conn.log record missing or blank uid; record skipped.",
                    raw_line=None,
                )
            )
            continue

        session = _session_from_conn_record(
            rec,
            job_id=job_id,
            log_directory_name=log_dir_name,
        )

        # Enrich with smtp
        session.smtp = smtp_map.get(uid)

        # Enrich with ssl
        session.ssl = ssl_map.get(uid)

        # Enrich with certificates via ssl.cert_chain_fuids → x509.fuid
        if session.ssl is not None:
            for fuid in session.ssl.cert_chain_fuids:
                cert = cert_map.get(fuid)
                if cert is not None:
                    session.certificates.append(cert)

        sessions.append(session)
        seen_conn_uids.add(uid)

    # -----------------------------------------------------------------------
    # 4. Identify unmatched enrichment records
    # -----------------------------------------------------------------------
    unmatched_smtp_uids = [u for u in smtp_map if u not in seen_conn_uids]
    unmatched_ssl_uids = [u for u in ssl_map if u not in seen_conn_uids]

    # Unmatched cert fuids: in x509 fuid map but not referenced by any ssl record
    all_referenced_fuids: set[str] = set()
    for ssl_rec in ssl_map.values():
        all_referenced_fuids.update(ssl_rec.cert_chain_fuids)
    unmatched_cert_fuids = [f for f in cert_map if f not in all_referenced_fuids]

    # -----------------------------------------------------------------------
    # 5. Sort sessions deterministically: (ts or 0.0, uid) ascending
    # -----------------------------------------------------------------------
    sessions.sort(key=lambda s: (s.ts or 0.0, s.uid))

    return CorrelationResult(
        job_id=job_id,
        log_directory_name=log_dir_name,
        sessions=sessions,
        unmatched_smtp_uids=unmatched_smtp_uids,
        unmatched_ssl_uids=unmatched_ssl_uids,
        unmatched_cert_fuids=unmatched_cert_fuids,
        warnings=all_warnings,
        conn_records_read=len(conn_records),
        smtp_records_read=len(smtp_records),
        ssl_records_read=len(ssl_records),
        x509_records_read=len(x509_records),
    )
