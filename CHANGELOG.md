# Changelog

All notable changes to SecureMailScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Phase 1: Local capture file validation (`.pcap`, `.pcapng`), chunked SHA-256 evidence hashing, safe staging into `runtime/uploads/<job_id>/`, and atomic metadata JSON generation into `runtime/jobs/<job_id>/metadata.json`.
- Typed exception hierarchy for ingestion validation, integrity, containment, and staging errors.
- Structured dataclass schema for `EvidenceMetadata` records (`v1.0`).
- Documentation: `docs/phase_1_evidence_ingestion.md`.

## [0.1.0] — 2026-09-29

### Added
- Phase 0: Repository scaffold, package foundation, CLI (version/status), typed path helpers, custom exceptions, logging configuration.
- Full test suite for package import, CLI, and path helpers.
- Core documentation: README, architecture, offline privacy model, rule engine scope, ML model scope, validation plan, data handling, development phases, project handoff, assumptions, ADR 0001.
- Git hygiene: `.gitignore`, `.python-version`.
- `pyproject.toml` with setuptools backend, pytest/ruff/mypy configuration.
- `Makefile` with setup/test/lint/format/run-status targets.
- Added offline-safe example configuration templates under `config/`.
- `progress.md` continuity file.
