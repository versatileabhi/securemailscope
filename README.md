# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

> **Current State: Phase 1 — Local Input Validation & SHA-256 Evidence Hashing.**

## What This Is

SecureMailScope is an offline, passive, evidence-linked cryptographic security posture assessment tool for SMTP, IMAP, and POP3 traffic captured in PCAP/PCAPNG files.

### What Is Implemented (Phase 1)

- Local candidate file validation (`.pcap`, `.pcapng` case-insensitive, non-empty, path safety, and file size limits).
- Chunked SHA-256 evidence hashing without whole-file memory loading.
- Collision-resistant unique job ID generation (`job_YYYYMMDDTHHMMSSZ_<uuid>`).
- Safe local staging copy into `runtime/uploads/<job_id>/` with source-to-staged hash integrity verification.
- Evidence metadata record generation and atomic JSON write into `runtime/jobs/<job_id>/metadata.json`.

## What Is NOT Implemented Yet

The following features are planned for future phases and are **not present** in the current codebase:

- Internal PCAP/PCAPNG frame parsing or packet inspection
- Zeek integration or offline runner (Phase 2)
- Protocol extraction (SMTP, IMAP, POP3, STARTTLS, TLS, x509) (Phase 3–4)
- Deterministic RFC/policy rule engine (Phase 5)
- Cryptographic posture scoring (Phase 6)
- ML anomaly ranking (Phase 7)
- JSON, HTML, or PDF report generation (Phase 8)
- Local dashboard (Flask) (Phase 9)
- Any form of active probing, network connection, or mail-server interaction

## Design Principles

- **Offline-first and passive analysis only.** The tool never actively probes, connects to, or modifies mail servers.
- **Local execution.** No cloud upload, external API, or telemetry is used for core operation.
- **Evidence-linked findings.** All findings are traceable to observed PCAP evidence.
- **Analyst-in-the-loop.** ML output ranks sessions for analyst review; it never claims attack confirmation or attribution.
- **Authorised captures only.** Never analyse PCAPs without proper authorisation.

## Prerequisites

- Python 3.11 or later
- Git
- (Future phases) Zeek network security monitor, installed locally

## Installation

```bash
# 1. Clone the repository
git clone <repository-url> securemailscope
cd securemailscope

# 2. Create and activate the virtual environment
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

# 3. Install the package in editable mode with dev dependencies
pip install -e .[dev]
```

## Commands

### Version and help
```bash
python -m securemailscope --version
python -m securemailscope --help
```

### Status
```bash
python -m securemailscope status
```

### Run tests
```bash
pytest
# or with coverage:
pytest --cov=securemailscope --cov-report=term-missing
```

### Lint and format
```bash
ruff check .
ruff format --check .
```

### Make commands (if make is available)
```bash
make setup        # create venv and install dev dependencies
make test         # run pytest
make lint         # run ruff check
make format       # run ruff format
make run-status   # run securemailscope status
```

**If `make` is unavailable (e.g., Windows without Git Bash or WSL)**, use the equivalent direct commands above.

## Repository Structure (Abbreviated)

```
securemailscope/
├── src/securemailscope/     # installable package
│   ├── cli.py               # minimal CLI (Phase 0)
│   ├── constants.py         # project constants
│   ├── paths.py             # typed path helpers
│   ├── exceptions.py        # custom exceptions
│   ├── logging_config.py    # logging setup
│   ├── ingest/              # Phase 1–2 (planned)
│   ├── zeek/                # Phase 2–3 (planned)
│   ├── rules_engine/        # Phase 5 (planned)
│   ├── ml/                  # Phase 7 (planned)
│   └── reporting/           # Phase 8 (planned)
├── tests/                   # pytest suite
├── docs/                    # project documentation
├── config/                  # example configuration files
├── runtime/                 # local runtime data (git-ignored)
├── rules/                   # future rule files
├── models/                  # future local ML models
└── pyproject.toml           # packaging and tool config
```

## Roadmap

See [docs/development_phases.md](docs/development_phases.md) for the full ten-phase plan.

## Safety and Privacy

> **⚠️ WARNING:** Never analyse PCAP or PCAPNG files without proper legal authorisation.
> Do not commit real captures, email payloads, private keys, credentials, or sensitive
> institutional data to this repository. See [docs/data_handling.md](docs/data_handling.md)
> and [docs/offline_privacy_model.md](docs/offline_privacy_model.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
