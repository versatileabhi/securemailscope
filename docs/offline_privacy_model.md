# SecureMailScope — Offline Privacy Model

## Core Principle

SecureMailScope is designed for **offline, local-only operation**. It is not a cloud service.

## What This Tool Does NOT Do

| Behaviour | Status |
|-----------|--------|
| Upload PCAPs to a cloud service | ❌ Never |
| Connect to public mail servers | ❌ Never |
| Send telemetry or analytics | ❌ Never |
| Require an internet connection for core analysis | ❌ Never |
| Query public CRL/OCSP endpoints (by default) | ❌ Out of scope |
| Use a hosted LLM API | ❌ Out of scope |
| Contact threat-intelligence cloud feeds | ❌ Out of scope |
| Store raw PCAP content in a browser | ❌ Out of scope |

## What This Tool Does

- Reads local PCAP/PCAPNG files from the local filesystem.
- Runs Zeek locally (planned, Phase 2) to generate log files.
- Applies deterministic rules locally.
- Runs a local ML model locally (planned, Phase 7).
- Generates reports to the local `runtime/reports/` directory.
- Serves a dashboard on `localhost` only (planned, Phase 9).

## Optional Future Integrations (Explicitly Out of Default Scope)

The following are deliberately excluded from the default scope and must be explicitly documented, opt-in, and tested offline-safe if ever added:

- Live OCSP/CRL certificate revocation queries.
- Threat-intelligence API lookups.
- Cloud LLM-assisted analysis.
- Remote log forwarding.

## Dashboard Privacy (Planned Phase 9)

The planned local dashboard will:
- Bind to `localhost` (127.0.0.1) only.
- Require no authentication by default for local single-user operation.
- Not transmit PCAP data, session records, or findings to any remote endpoint.
- Not store raw PCAP content in browser local storage or cookies.
