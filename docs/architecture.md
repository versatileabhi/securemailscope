# SecureMailScope — Planned Architecture

> **Status: Planned. No component beyond the CLI is implemented in Phase 0.**

## Data Flow Overview

```
PCAP/PCAPNG (authorised capture)
        │
        v
[ SHA-256 Evidence Hash ]
    (Phase 1 — planned)
        │
        v
[ Zeek Offline Analysis ]
    conn.log, ssl.log, x509.log,
    smtp.log, imap.log, pop3.log
    (Phase 2–4 — planned)
        │
        v
[ Canonical Session Records ]
    Zeek-derived, structured,
    protocol- and TLS-annotated
    (Phase 3–4 — planned)
        │
        v
[ Deterministic Rule Engine ]
    RFC/policy rules applied to
    observed cryptographic conditions
    Findings: observed/not-observed/partial
    (Phase 5 — planned)
        │
        v
[ Coverage-Aware Posture Score ]
    Score reflects what evidence exists
    Partial/insufficient coverage disclosed
    (Phase 6 — planned)
        │
        v
[ Separate ML Anomaly Ranking ]
    Local IsolationForest on session features
    Output: anomaly score + review recommendation
    Does NOT override rule findings
    (Phase 7 — planned)
        │
        v
[ Forensic Reports ]
    JSON (machine-readable)
    HTML (human-readable)
    PDF (printable evidence)
    (Phase 8 — planned)
        │
        v
[ Local Dashboard ]
    Flask, localhost only
    PCAP upload + job management
    (Phase 9 — planned)
        │
        v
[ Human Analyst Review ]
    Final operational decisions
    Attribution, remediation, escalation
```

## Module Boundaries

| Module | Responsibility | Phase |
|--------|---------------|-------|
| `ingest/` | PCAP validation, SHA-256 hashing | 1–2 |
| `zeek/` | Zeek runner, log parsing | 2–3 |
| `canonicalization/` | Canonical session records | 3–4 |
| `rules_engine/` | Deterministic findings | 5 |
| `scoring/` | Coverage-aware posture score | 6 |
| `ml/` | Anomaly ranking (IsolationForest) | 7 |
| `reporting/` | JSON/HTML/PDF generation | 8 |
| `dashboard/` | Local Flask UI | 9 |

## Key Invariants

1. The rule engine and ML model are always separate modules.
2. ML output never overrides or replaces rule-engine findings.
3. Absent or unobservable evidence is always disclosed (never assumed present).
4. No external network calls are required for core operation.
5. All output is stored locally in `runtime/`.
