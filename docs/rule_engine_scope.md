# SecureMailScope — Rule Engine Scope

> **Status: Planned. Phase 5.**

## What the Rule Engine Does

The deterministic rule engine maps **observed technical conditions** extracted from Zeek logs to structured findings according to relevant RFCs and configurable local policy.

### What It Can Establish

- An observed TLS version (e.g., TLS 1.0 observed on a session).
- A deprecated cipher suite observed in a session.
- A missing STARTTLS negotiation in an SMTP session.
- A self-signed or expired certificate observed in captured data.
- An observed protocol behaviour inconsistent with current RFCs.

### What It Cannot Establish

- Whether an exploit or attack actually occurred.
- Attribution to any threat actor.
- Organisation-wide compliance posture (only analysed sessions are in scope).
- Conditions not directly observable in the provided PCAP evidence.

## Example Planned Rule (Illustrative)

```
Rule ID:  TLS-001
Name:     Deprecated TLS Version Observed
Condition: ssl.log field `version` equals "TLSv10" or "SSLv3"
Finding:  Deprecated TLS version observed in session.
Severity: HIGH (per local policy)
Coverage: full (if ssl.log contains version field)
Coverage: partial (if ssl.log present but version field absent)
Note:     Does not confirm that the session was successfully attacked.
```

## Rule Files (Placeholder)

Future rule definitions will be stored in the `rules/` directory.
The schema for rule files will be defined in Phase 5.

## Key Constraints

- Rules must be deterministic and reproducible.
- Rule output must distinguish `observed`, `not-observed`, and `not-observable`.
- Rules must never produce findings that assert attribution or attack confirmation.
- Coverage state must always accompany a finding.
