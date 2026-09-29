# SecureMailScope — Persistent Build Progress

## Project Identity

- **Project:** SecureMailScope
- **Purpose:** Offline, passive, evidence-linked cryptographic posture assessment for SMTP, IMAP, and POP3 PCAP/PCAPNG traffic.
- **Primary telemetry engine:** Zeek (planned, Phase 2+).
- **Primary language:** Python 3.11+.
- **Deployment model:** Local/offline only.
- **Current phase:** Phase 3.
- **Current status:** Complete.

## Non-Negotiable Architecture Rules

- Offline-first and passive analysis only.
- No cloud upload or external runtime API dependency.
- Zeek is the planned primary telemetry engine.
- Rule engine and ML model are separate modules.
- Deterministic rules establish observed cryptographic findings.
- ML only ranks unusual sessions for analyst review.
- No unsupported claims of attack confirmation, compliance, or attribution.
- Unknown evidence must be represented explicitly (partial/insufficient/not-observable).

## Completed Work

- [x] Phase 0 complete: Foundation & Continuity System
  - [x] Repository scaffold created
  - [x] Package/CLI foundation working
  - [x] Phase 0 test suite passing (22 tests)
  - [x] Documentation & configuration templates created
  - [x] Git hygiene configured
- [x] Phase 1 complete: Local Input Validation & SHA-256 Evidence Hashing
  - [x] File candidate validation (`.pcap`, `.pcapng`, case-insensitive, size limits, empty check)
  - [x] Chunked SHA-256 hashing without whole-file memory loading
  - [x] Safe local staging under `runtime/uploads/<job_id>/` with hash integrity verification
  - [x] Evidence metadata JSON record generation (`runtime/jobs/<job_id>/metadata.json`) with atomic write
  - [x] Path containment verification (`ensure_within_runtime`) and traversal prevention
  - [x] Full Phase 1 test suite passing (48 total tests across project)
- [x] Phase 2 complete: Zeek Availability Check & Offline Runner
  - [x] Local Zeek binary discovery via `shutil.which` and optional configured path
  - [x] Safe `zeek --version` validation with timeout and OSError handling (`ZeekAvailability`)
  - [x] Offline-only command construction (`zeek -r <pcap> Log::default_logdir=<dir>`) — no `-i` live capture flag
  - [x] Per-job isolated Zeek log directory (`runtime/zeek_logs/<job_id>/`) created only after Zeek confirmed available
  - [x] `subprocess.run` invoked with `shell=False` and explicit argument list — no shell string interpolation
  - [x] Five discrete execution statuses: `completed`, `failed`, `timed_out`, `zeek_unavailable`, `invalid_evidence_reference`
  - [x] `ZeekRunResult` schema with `to_dict`, `to_json`, `from_dict`, and embedded `PHASE_2_LIMITATIONS`
  - [x] Full Phase 2 test suite passing (65 total tests across project) — all mocked, no real Zeek binary required
  - [x] Phase 2 boundary strictly enforced: no log parsing, no protocol extraction, no report generation
- [x] Phase 3 complete: Zeek JSON-Log Readers and Canonical Session Schema
  - [x] Pure read-only JSONL log reader (`read_jsonl_log`) with non-fatal `ParseWarning` collection
  - [x] Canonical session schema (`CanonicalSession`, `SmtpEnrichment`, `SslEnrichment`, `CertificateRecord`, `CorrelationResult`)
  - [x] Multi-log correlator (`correlate_zeek_logs`) joining `conn.log`, `smtp.log`, `ssl.log`, and `x509.log`
  - [x] Standard Zeek join semantics: `conn.uid → smtp.uid`, `conn.uid → ssl.uid`, `ssl.cert_chain_fuids → x509.fuid`
  - [x] Unmatched records preserved in `unmatched_smtp_uids`, `unmatched_ssl_uids`, `unmatched_cert_fuids`
  - [x] Missing optional logs handled gracefully with non-fatal warnings
  - [x] Path confinement via `ensure_within_runtime` with `UnsafePathError`
  - [x] Lossless JSON serialization/deserialization (`to_dict`, `to_json`, `from_dict`)
  - [x] Full Phase 3 test suite passing (99 total tests across project) — 34 new Phase 3 tests

## Current Work

- **Active task:** None. Phase 3 implementation and verification are complete.
- **Phase 3 status:** All acceptance criteria met. Unit tests pass with 100% clean linter.
- **Remaining future work:** Phase 4 protocol observation extraction (SMTP, IMAP, POP3, TLS, and certificates).
- **Blockers:** None.
- **Decisions made:**
  - Standard library `dataclass` used for all Phase 3 models.
  - Non-raising log reader returns `(records, warnings)` tuple.
  - SmtpEnrichment maps Zeek `"from"` field to Python `from_`, emitted back as `"from"` in JSON.
  - Certificate join requires `ssl.cert_chain_fuids → x509.fuid`; direct `conn.uid → x509` is never performed.
  - Sessions deterministically sorted by `(ts or 0.0, uid)` ascending.
  - Absolute filesystem paths excluded from all exported session records.

## Next Allowed Task

Await explicit approval before starting **Phase 4** — SMTP/IMAP/POP3, STARTTLS, TLS, and Certificate Observation Extraction.

## Commands to Verify Current State

```bash
python --version
# Output: Python 3.11.9

python -m securemailscope --version
# Output: SecureMailScope 0.1.0 (Exit code: 0)

python -m securemailscope status
# Output: offline mode, all components not implemented (Exit code: 0)

python -m pytest
# Output: 99 passed in 3.14s (Exit code: 0)

python -m ruff check .
# Output: All checks passed! (Exit code: 0)
```

## Known Limitations

- Phase 1 validates file-level eligibility only; it does not verify PCAP/PCAPNG internal frame structure or parse packet contents.
- Phase 2 discovers and invokes Zeek only; no real Zeek installation or real-PCAP integration test has been executed against this codebase.
- Phase 3 reads and correlates Zeek JSON logs only; no detection rules, risk scoring, ML ranking, reporting, or dashboard are implemented.
- X.509 certificate records are associated via `ssl.cert_chain_fuids → x509.fuid`; direct `conn.uid → x509` association is not available in standard Zeek output.
- `smtp.log` and `ssl.log` enrichment is optional; absent logs produce `None` enrichment fields, not errors.
- Phase 3 does not parse PCAP files or invoke Zeek; it reads existing log output only.
- No empirical performance claims or benchmark numbers.

## Handoff Instructions

1. Read this file first.
2. Run the verification commands listed above.
3. Do not start a later phase until the current phase is marked Complete.
4. Update this file with files changed, commands run, test results, and blockers.
5. Commit only after tests pass.

## Change Log

| Date | Phase | Change | Verification | Status |
|---|---|---|---|---|
| 2026-09-29 | 0 | Project initialized — scaffold, package, CLI, tests, docs | Pending | In Progress |
| 2026-09-29 | 0 | Resumed Batch 2 after quota interruption; added config templates and completed Phase 0 verification | CLI version/status ok; pytest (22 passed); ruff check (passed) | Complete |
| 2026-09-29 | 1 | Local capture validation, chunked SHA-256, safe staging, and evidence metadata generation | pytest (48 passed); ruff check (passed); CLI ok | Complete |
| 2026-09-29 | 2 | Finalized Phase 2 Zeek availability check and offline runner after interrupted WIP checkpoint | pytest (65 passed); ruff check (passed) | Complete |
| 2026-09-29 | 3 | Zeek JSON-log readers, canonical session schema, and correlator pipeline | pytest (99 passed); ruff check (passed); CLI ok | Complete |
