# SecureMailScope — Phase 4: SMTP/IMAP/POP3, STARTTLS, TLS, and Certificate Observation Extraction

## 1. Overview & Scope

Phase 4 introduces the observation extraction layer of SecureMailScope. It translates the normalized, correlated sessions produced by Phase 3 into structured, neutral, and explainable observation records.

Key capabilities introduced in Phase 4:
1. Pure in-memory extraction function (`extract_observations`) accepting `list[CanonicalSession]` or `CorrelationResult`.
2. Structured observation dataclass models (`SessionObservation`, `ObservationResult`, `SmtpObservation`, `StarttlsObservation`, `TlsObservation`, `CertificateObservation`, `ImapObservation`, `Pop3Observation`).
3. Evidence-linked transport security classification separating explicit normalized indicators, correlated TLS, and implicit port context.
4. Authoritative server certificate chain ordering driven by `ssl.cert_chain_fuids` with explicit tracking of unlinked certificates and missing records.
5. Explicit, truthful representation of unsupported protocol sources (IMAP, POP3) without inventing fake telemetry.

---

## 2. Input Data Contract (Phase 3 Dependency)

Phase 4 consumes only the canonical dataclasses produced in Phase 3 ([src/securemailscope/schemas/session.py](file:///c:/Users/Sarvadnya/Downloads/SIH'26/securemailscope/src/securemailscope/schemas/session.py)):
- `CanonicalSession` (anchored by `uid`, with optional `smtp`, `ssl`, and `certificates` lists).
- `CorrelationResult` (container with sorted sessions, provenance, and warnings).

Phase 4 does not read raw Zeek JSON files, PCAP files, or filesystem paths directly.

---

## 3. Observation Models and States

All observation models are defined in [src/securemailscope/schemas/observation.py](file:///c:/Users/Sarvadnya/Downloads/SIH'26/securemailscope/src/securemailscope/schemas/observation.py):

### Observation State Classifications
- `"observed"`: Evidence was explicitly present and captured in the canonical input.
- `"unavailable"`: The field or protocol was expected/applicable for the session context, but absent or null.
- `"not_applicable"`: The observation category does not apply to this session type (e.g. SMTP on HTTP port 80).
- `"unsupported_by_current_input"`: Sourced protocol is not implemented in the current pipeline (IMAP and POP3).

### Observation Bundle (`SessionObservation`)
Each session yields a `SessionObservation` containing:
- Connection coordinates: `uid`, `job_id`, `log_directory_name`, `ts`, `orig_h`, `orig_p`, `resp_h`, `resp_p`, `proto`, `service`.
- Protocol observations:
  - `smtp`: `SmtpObservation`
  - `starttls`: `StarttlsObservation`
  - `tls`: `TlsObservation`
  - `server_certificates`: `list[CertificateObservation]`
  - `unlinked_certificates`: `list[CertificateObservation]`
  - `imap`: `ImapObservation` (`state="unsupported_by_current_input"`)
  - `pop3`: `Pop3Observation` (`state="unsupported_by_current_input"`)
- Synthesis:
  - `coverage_state`: `"full"`, `"partial"`, or `"insufficient"` (indicating evidence depth only).
  - `limitations`: Embedded list of `PHASE_4_LIMITATIONS`.
  - `metadata_schema_version`: `"1.0"`.

---

## 4. Transport Security Evidence (STARTTLS / Implicit TLS)

### Design Correction: Non-Equivalence of `smtp.tls` and STARTTLS Upgrade
Zeek's `smtp.log` provides a single boolean flag `tls: bool | None`. While this flag indicates that Zeek recognized TLS traffic inside the SMTP conversation, standard Zeek does not log the raw command transcript (such as the client `STARTTLS` verb or the server `220 2.0.0 Ready to start TLS` response).

Phase 4 therefore **does not claim `explicit_starttls`** solely because `smtp.tls` is True. Instead, it captures independent, neutral evidence:
- `smtp_tls_flag: bool | None`
- `correlated_tls_present: bool`
- `responder_port: int | None`
- `mail_transport_context: str`

### Allowed Mail Transport Contexts
- `"smtp_tls_flagged"`: `smtp.tls` is True. Indicates normalized SMTP TLS flag was observed without asserting a command transcript.
- `"correlated_tls"`: `session.ssl` is present on a mail-context session without an explicit SMTP TLS flag.
- `"implicit_tls_context"`: `session.ssl` is present and the responder port is 465 (SMTPS).
- `"cleartext_smtp_observed"`: SMTP enrichment present, `smtp.tls` is explicitly False, and `session.ssl` is absent.
- `"tls_status_unavailable"`: Mail-context session lacks sufficient SMTP or TLS evidence.
- `"not_applicable"`: Non-mail session.

At no point does Phase 4 conclude whether a session is "secure", "insecure", "downgraded", or "vulnerable".

---

## 5. Certificate Chain Ordering

### Authoritative Server Chain via `ssl.cert_chain_fuids`
Standard Zeek stores the server certificate chain sequence in `ssl.log` as `cert_chain_fuids: list[str]`. The order of records in `session.certificates` is not guaranteed to match this sequence.

Phase 4 implements the following ordering rules:
1. When `ssl.cert_chain_fuids` is present, it is treated as the **authoritative server certificate chain order**.
2. `server_certificates` observations are constructed in the exact sequence of `ssl.cert_chain_fuids`, with `chain_index` starting at 0.
3. If a chain FUID has no matching `CertificateRecord`, an explicit observation is produced with `record_available=False` and a non-fatal warning is logged.
4. Any `CertificateRecord` present on the session but not listed in `ssl.cert_chain_fuids` is retained in `unlinked_certificates` with `in_server_chain=False` and `chain_index=-1`.
5. `ssl.client_cert_chain_fuids` is preserved separately on `TlsObservation.client_cert_chain_fuids` and is never mixed into the server certificate chain.
6. When `ssl.cert_chain_fuids` is empty or absent, a deterministic fallback order (by FUID) is used and explicitly marked as not confirmed TLS handshake order.

---

## 6. IMAP and POP3 Status

Phase 3 does not ingest `imap.log` or `pop3.log`. Phase 4 does not invent fake telemetry or fabricate readers. Both protocols are represented truthfully:
- `imap.state = "unsupported_by_current_input"`
- `pop3.state = "unsupported_by_current_input"`
- Explicit explanatory reasons are embedded in the observation models.

---

## 7. Explicit Non-Goals

Phase 4 strictly prohibits:
- Detection rules, IOCs, heuristics, or anomaly logic.
- Risk scores, severity levels, confidence scores, or verdicts.
- ML/AI models, embeddings, or classifications.
- Cipher strength evaluation, protocol deprecation labeling, or trust assessment.
- Certificate expiration checks, root CA validation, or hostname verification.
- Reports, PDF/HTML generation, UI/dashboard, APIs, or database persistence.
- Live traffic capture, PCAP replay, or real Zeek binary invocation.
