# Contributing to SecureMailScope

## Current State

This project is in **Phase 0 — Foundation Only**. Contributions should respect the phase boundaries documented in [docs/development_phases.md](docs/development_phases.md).

## Ground Rules

1. **Do not start a later phase until the current phase is marked Complete** in `progress.md`.
2. **Do not introduce cloud dependencies, external APIs, telemetry, or analytics.**
3. **Do not commit real PCAPs, credentials, private keys, email payloads, or sensitive data.**
4. **Do not use "AI detects attacks" language.** Use "ML anomaly ranking for analyst review."
5. **Do not claim unimplemented features are complete.**
6. All code must pass `pytest` and `ruff check .` before being merged.
7. Use type hints for all new public functions.
8. Update `progress.md` after each phase is complete.

## Development Setup

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
# or: source .venv/bin/activate  # macOS/Linux
pip install -e .[dev]
```

## Running Tests

```bash
pytest
pytest --cov=securemailscope --cov-report=term-missing
```

## Linting and Formatting

```bash
ruff check .
ruff format .
```

## Submitting Changes

- Work only within the current phase scope.
- Ensure all tests pass and ruff check is clean.
- Update `progress.md` with the date, change, and verification status.
- Open a pull request with a description of what was changed and why.
