# SecureMailScope — Validation Plan

> **Note:** No numerical accuracy metrics are included here because empirical validation has not yet been performed. Metrics will be added after each phase is completed with real or representative data.

## Validation Areas

| # | Validation Area | Test Method / Input | Acceptance Criteria |
|---|-----------------|--------------------|-----------------------|
| 1 | PCAP ingestion and SHA-256 integrity | Provide a known synthetic PCAP file; compute hash and compare to a pre-computed reference value. | Hash output matches reference value exactly; invalid or missing files are rejected with a clear error. |
| 2 | Zeek protocol and TLS analysis | Run Zeek offline against a synthetic PCAP containing known TLS versions and protocol sequences. | Zeek produces conn.log, ssl.log, x509.log, smtp.log as expected; fields mapped correctly to canonical schema. |
| 3 | Deterministic rule engine | Apply rules to synthetic canonical session records with known conditions (e.g., TLS 1.0, missing STARTTLS). | Each rule produces the expected finding, severity, and coverage state; no false findings on clean sessions. |
| 4 | Local ML anomaly prioritization | Provide a baseline of synthetic session feature records plus injected outlier records. | Injected outliers are ranked higher than baseline sessions; model runs offline without external dependencies. |
| 5 | JSON/HTML/PDF/dashboard outputs | Generate reports from known synthetic analysis results. | Output files are valid, contain evidence hashes, findings, coverage states, and ML ranks; dashboard binds to localhost only. |
