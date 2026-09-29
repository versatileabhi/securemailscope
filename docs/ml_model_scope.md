# SecureMailScope — ML Model Scope

> **Status: Planned. Phase 7.**

## Model Type

A local **IsolationForest** model, trained and run entirely offline.

## Input

Zeek-derived session feature vectors (e.g., session duration, byte counts, port, protocol version, handshake timing). The model **does not consume raw PCAP payloads**, email content, or decrypted TLS data.

## Output

- Anomaly score per session.
- Rank/priority ordering for analyst review.
- A recommendation flag: `review_recommended: true/false`.

## What the ML Model DOES NOT Do

| Claim | Status |
|-------|--------|
| Override deterministic rule-engine findings | ❌ Prohibited |
| Confirm that an attack occurred | ❌ Prohibited |
| Establish attribution | ❌ Prohibited |
| Access raw PCAP bytes | ❌ Out of scope |
| Use any external API or cloud service | ❌ Out of scope |
| Replace analyst judgment | ❌ Out of scope |

## Validation Approach (Planned, Phase 7)

- Initial validation will use a local baseline of synthesised or sanitised Zeek session features.
- Controlled anomaly feature records will be injected to confirm that outliers are ranked appropriately.
- No external benchmark datasets will be used without explicit documentation of their provenance, licensing, and privacy status.
- No numerical accuracy claims will be published until empirical validation on representative data is complete.

## Relationship to Rule Engine

```
Rule Engine  -->  confirmed findings (deterministic)
ML Model     -->  anomaly rank / review priority (probabilistic)
Analyst      -->  operational decision
```

The ML model output is always presented alongside, never in place of, rule-engine findings.
