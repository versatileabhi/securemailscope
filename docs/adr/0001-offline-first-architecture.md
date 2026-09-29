# ADR 0001: Offline-First Architecture

**Status:** Accepted

## Context

SecureMailScope is designed to analyse authorised PCAP/PCAPNG evidence for cryptographic security posture issues in email protocols (SMTP, IMAP, POP3). The tool must be usable in environments where:

- Internet access may be restricted or prohibited.
- PCAP content contains sensitive or legally protected network traffic.
- Privacy regulations prohibit uploading captured traffic to external services.
- Chain-of-custody requirements mandate local, auditable, reproducible processing.

Alternative architectures (cloud analysis, SaaS platform, or hosted API) were considered.

## Decision

All core analysis is performed locally and offline:

1. PCAP files are read from the local filesystem only.
2. Zeek is run offline in read-pcap mode (no live capture).
3. All derived logs, canonical records, findings, scores, and reports are written to `runtime/` on the local filesystem.
4. The planned dashboard binds to `127.0.0.1` (localhost) only.
5. No external API, cloud service, telemetry endpoint, or LLM is required for core operation.

## Consequences

**Positive:**
- Suitable for air-gapped, restricted, or privacy-sensitive environments.
- No network exposure of analysed PCAP content.
- Reproducible: given the same PCAP and rule set, the same findings are always produced.
- No external runtime dependency cost or availability risk.

**Negative:**
- Certificate revocation status (OCSP/CRL) cannot be checked without an internet connection. This limitation is explicitly disclosed in findings.
- Threat intelligence enrichment (e.g., known-bad IP lookup) is not available by default.
- Users must install Zeek locally (documented prerequisite for Phase 2+).

## Alternatives Considered

| Alternative | Reason Rejected |
|-------------|----------------|
| Cloud-hosted analysis API | Privacy and authorisation requirements prohibit uploading captured traffic. |
| Hosted SaaS dashboard | Incompatible with offline-first and air-gapped use cases. |
| Direct libpcap/dpkt Python parsing | Zeek provides richer, more reliable SSL/TLS and mail-protocol telemetry with proven RFC coverage. |
| Real-time live-capture mode | Passive-only requirement; live capture changes the tool's legal and operational scope. |
