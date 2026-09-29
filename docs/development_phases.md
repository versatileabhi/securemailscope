# SecureMailScope — Development Phases

> **Rule:** Do not start a later phase until the prior phase is marked **Complete** in `progress.md` and all acceptance criteria are met.

---

## Phase 0: Foundation and Continuity System

**Objective:** Create a clean, reproducible Python project foundation with developer documentation, repository structure, test scaffold, and continuity files.

**Inputs:** None.

**Outputs:**
- Repository scaffold and folder structure.
- Installable Python package with minimal CLI.
- Passing pytest suite.
- Core documentation.
- `progress.md` continuity file.

**Acceptance Criteria:**
- `python -m securemailscope --version` prints `0.1.0`.
- `python -m securemailscope status` prints offline mode and not-implemented states.
- All pytest tests pass.
- Ruff check passes (or unavailability documented).
- All required documentation files exist.
- No fake implementation, benchmark, or cloud dependency.

---

## Phase 1: Local Input Validation and SHA-256 Evidence Hashing

**Objective:** Accept a local PCAP/PCAPNG file path, validate the file, and compute a SHA-256 evidence hash.

**Prerequisite:** Phase 0 complete.

**Inputs:** Local file path to a PCAP or PCAPNG file.

**Outputs:**
- Validated file metadata (path, size, extension).
- SHA-256 hex digest of the file.
- Structured evidence record (JSON-serialisable).

**Acceptance Criteria:**
- Known synthetic PCAP produces the correct SHA-256 hash.
- Missing or unreadable files are rejected with a clear error.
- Non-PCAP files are rejected with a clear error.
- No network calls are made during ingestion.
- Pytest tests cover all acceptance criteria.

**Status:** Complete (Verified: 48 tests pass, ruff clean, chunked SHA-256 and atomic metadata staging implemented).

---

## Phase 2: Zeek Availability Check and Offline Runner

**Objective:** Detect whether Zeek is installed locally, and run Zeek offline against a provided PCAP.

**Prerequisite:** Phase 1 complete.

**Inputs:** Validated PCAP evidence record from Phase 1.

**Outputs:**
- Zeek availability status (installed version or not-found).
- Zeek output directory containing raw log files.

**Acceptance Criteria:**
- Zeek version is detected correctly or a clear not-found error is raised.
- Zeek is run in offline/read mode only (no live capture).
- Output logs are placed in `runtime/zeek_logs/<job-id>/`.
- Pytest tests cover availability check and (mocked) runner invocation.

---

## Phase 3: Zeek JSON-Log Readers and Canonical Session Schema

**Objective:** Parse Zeek JSON logs into canonical session records.

**Prerequisite:** Phase 2 complete.

**Inputs:** Zeek log directory from Phase 2.

**Outputs:**
- Typed canonical session records (dataclass or Pydantic model).
- One record per session, combining conn/ssl/x509/smtp/imap/pop3 fields.

**Acceptance Criteria:**
- Synthetic Zeek log fixtures produce correct canonical records.
- Missing or absent log files result in partial/not-observable coverage fields, not errors.
- Schema is defined in `src/securemailscope/schemas/`.
- Pytest tests cover parsing and field mapping.

---

## Phase 4: SMTP/IMAP/POP3, STARTTLS, TLS, and Certificate Observation Extraction

**Objective:** Extract mail-protocol-specific observations from canonical session records.

**Prerequisite:** Phase 3 complete.

**Inputs:** Canonical session records from Phase 3.

**Outputs:**
- Mail protocol observations: STARTTLS presence, TLS version, cipher suite, certificate fields.
- Coverage state for each observation.

**Acceptance Criteria:**
- Observations correctly reflect Zeek log data.
- Absent fields produce `not-observable` coverage state.
- Pytest tests cover extraction from synthetic session records.

---

## Phase 5: Deterministic RFC/Policy Rule Engine

**Objective:** Apply deterministic rules to observations and produce structured findings.

**Prerequisite:** Phase 4 complete.

**Inputs:** Mail protocol observations from Phase 4.

**Outputs:**
- Structured findings: rule-id, description, severity, coverage-state.
- No finding claims attack occurrence or attribution.

**Acceptance Criteria:**
- Known deprecated-TLS observation produces the correct finding and severity.
- Clean session produces no false findings.
- Rules are stored in `rules/` and loaded from there.
- Pytest tests cover rule evaluation and coverage state output.

---

## Phase 6: Coverage-Aware Posture Scoring and Prioritization

**Objective:** Calculate a posture score that reflects evidence coverage.

**Prerequisite:** Phase 5 complete.

**Inputs:** Structured findings from Phase 5.

**Outputs:**
- Posture score (numeric, bounded range).
- Coverage disclosure (full/partial/insufficient).
- Prioritised finding list.

**Acceptance Criteria:**
- Insufficient evidence coverage is explicitly disclosed in the score output.
- Score is reproducible for the same input.
- Pytest tests cover scoring logic and coverage disclosure.

---

## Phase 7: Separate Local IsolationForest ML Anomaly-Ranking Module

**Objective:** Train and apply a local IsolationForest model to rank sessions by anomaly score.

**Prerequisite:** Phase 6 complete.

**Inputs:** Zeek-derived session feature vectors (from canonical records).

**Outputs:**
- Anomaly score per session.
- Rank/priority ordering.
- `review_recommended` flag.

**Acceptance Criteria:**
- Model runs entirely offline.
- Model is trained on local synthetic baseline data.
- Injected outlier records rank higher than baseline records.
- ML output does not override rule-engine findings.
- Pytest tests cover training, scoring, and rank ordering.

---

## Phase 8: JSON, HTML, and PDF Forensic Reporting

**Objective:** Generate evidence-linked reports in three formats.

**Prerequisite:** Phase 7 complete.

**Inputs:** Posture score, findings, ML ranks, evidence hashes.

**Outputs:**
- `runtime/reports/<job-id>/report.json`
- `runtime/reports/<job-id>/report.html`
- `runtime/reports/<job-id>/report.pdf`

**Acceptance Criteria:**
- JSON report is valid and machine-parseable.
- HTML report contains evidence hash, findings, coverage states, and ML rank.
- PDF report is generated without external cloud dependencies.
- Pytest tests cover report generation from synthetic analysis results.

---

## Phase 9: Local Flask Dashboard and PCAP Upload Workflow

**Objective:** Provide a local web dashboard for PCAP upload, job management, and report viewing.

**Prerequisite:** Phase 8 complete.

**Inputs:** Local PCAP file (uploaded via dashboard).

**Outputs:**
- Running Flask server on `localhost` only.
- Job status tracking.
- Report viewing interface.

**Acceptance Criteria:**
- Dashboard binds to `127.0.0.1` only.
- No PCAP content is sent to any remote endpoint.
- Job results are stored in `runtime/`.
- Pytest tests cover route availability and job workflow.

---

## Phase 10: Integration Tests, Sample-Data Validation, Hardening, and Demo Package

**Objective:** End-to-end integration tests, hardening, and a distributable demo package.

**Prerequisite:** Phase 9 complete.

**Inputs:** Synthetic PCAP samples, known expected findings.

**Outputs:**
- Full integration test suite.
- Hardened configuration and error handling.
- Demo package with synthetic sample data.

**Acceptance Criteria:**
- End-to-end test from PCAP ingestion to report generation passes.
- All known synthetic anomaly cases produce expected findings and ML ranks.
- No real PCAP, credential, or PII is included in the demo package.
- Documentation is updated and internally consistent.
