# SecureMailScope — Assumptions

This file records conservative assumptions made during development. When a requirement is ambiguous, the most conservative offline-first approach is chosen and recorded here.

## Phase 0 Assumptions

| # | Assumption | Rationale |
|---|------------|-----------|
| A01 | Offline PCAP/PCAPNG analysis only. Live capture is out of scope. | Privacy, authorisation, and passive-analysis requirements. |
| A02 | Zeek is the intended primary telemetry engine. Alternatives (e.g., Suricata, tshark) are not in scope unless explicitly added. | Zeek produces the richest SSL/TLS and mail-protocol logs in accessible JSON format. |
| A03 | The dashboard will be local-only and bound to localhost. Public deployment is out of scope. | Privacy model and offline-first requirement. |
| A04 | Real production traffic and cloud deployment are out of scope. | Security, privacy, and legal authorisation requirements. |
| A05 | The rule engine and ML model are distinct modules. Their outputs must not be merged or co-mingled. | Separation of deterministic findings from probabilistic ranking is an explicit architecture requirement. |
| A06 | Unknown, absent, or unobservable evidence must be expressed as partial/insufficient/not-observable. False certainty is prohibited. | Forensic accuracy and analyst trust. |
| A07 | No LLM is required for core operation. LLM integration is explicitly out of default scope. | Offline-first, reproducibility, and no external API dependency. |
| A08 | Apache-2.0 license is chosen for open development compatibility. | Standard open-source permissive licence compatible with planned dependencies. |
| A09 | Python 3.11 is the minimum supported version. | Type hint features (e.g., `tuple[str, ...]` without `from __future__`) and `tomllib` standard library availability. |
