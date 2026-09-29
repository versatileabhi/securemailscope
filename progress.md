# SecureMailScope — Persistent Build Progress

## Project Identity

- **Project:** SecureMailScope
- **Purpose:** Offline, passive, evidence-linked cryptographic posture assessment for SMTP, IMAP, and POP3 PCAP/PCAPNG traffic.
- **Primary telemetry engine:** Zeek (planned, Phase 2+).
- **Primary language:** Python 3.11+.
- **Deployment model:** Local/offline only.
- **Current phase:** Phase 1.
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

## Current Work

- **Active task:** Phase 1 complete; awaiting explicit approval for Phase 2.
- **Blockers:** None.
- **Decisions made:**
  - Standard library `dataclass` used for `EvidenceMetadata` (`v1.0`).
  - Standard library `hashlib.sha256` with 1 MiB chunked reads (`HASH_CHUNK_SIZE_BYTES = 1024 * 1024`).
  - Absolute source paths strictly excluded from metadata records (`source_path_disclosed = False`).
  - Atomic rename (`Path.replace`) used for metadata persistence.

## Next Allowed Task

Await explicit approval before starting **Phase 2** — Zeek availability check and offline runner.

## Commands to Verify Current State

```bash
python --version
# Output: Python 3.11.9

python -m securemailscope --version
# Output: SecureMailScope 0.1.0 (Exit code: 0)

python -m securemailscope status
# Output: offline mode, all components not implemented (Exit code: 0)

python -m pytest
# Output: 48 passed in 2.05s (Exit code: 0)

python -m ruff check .
# Output: All checks passed! (Exit code: 0)
```

## Known Limitations

- Phase 1 validates file-level eligibility only; it does not verify PCAP/PCAPNG internal frame structure or parse packet contents.
- No Zeek installation or runner yet (Phase 2).
- No protocol parsing or observation extraction yet (Phase 3–4).
- No deterministic rule engine, scoring, ML, reports, or dashboard yet.
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
