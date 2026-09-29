# Security Policy

## Scope

SecureMailScope is an **offline, passive forensic analysis tool**. It does not connect to mail servers, does not expose public endpoints, and does not process live traffic.

## Authorisation Requirement

This tool is designed for use **only on PCAP/PCAPNG files that you are legally authorised to analyse**. Unauthorised capture or analysis of network traffic may violate local laws. The authors and contributors accept no liability for unauthorised use.

## Sensitive Data Handling

- Do not commit real PCAP files, email payloads, private keys, certificates, or credentials.
- Keep all captured traffic in the local `runtime/` directory, which is excluded from Git.
- See [docs/data_handling.md](docs/data_handling.md) and [docs/offline_privacy_model.md](docs/offline_privacy_model.md).

## Reporting Vulnerabilities

If you discover a security vulnerability in the SecureMailScope codebase itself (not in the traffic being analysed), please report it by opening a GitHub Issue marked **[SECURITY]** or by contacting the maintainers privately.

Do not include real network captures, credentials, or sensitive organisational data in bug reports.

## Supported Versions

| Version | Phase | Status     |
|---------|-------|------------|
| 0.1.0   | 0     | Foundation |
