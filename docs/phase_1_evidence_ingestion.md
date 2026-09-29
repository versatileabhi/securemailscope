# SecureMailScope — Phase 1: Local Input Validation & SHA-256 Evidence Hashing

## Overview & Scope

Phase 1 provides local file-level validation, chunked SHA-256 evidence hashing, safe staging, and atomic metadata persistence for candidate PCAP/PCAPNG network captures.

It implements the initial entry point for passive cryptographic evaluation without parsing packet frames, inspecting protocol payloads, or invoking any network operations.

## Security & Privacy Properties

- **Offline-Only & No-Network:** Operates purely on local filesystem paths. No sockets, external APIs, cloud uploads, or telemetry calls are made.
- **Privacy-Preserving Metadata:** Absolute source paths on the host system are explicitly omitted (`source_path_disclosed = false`) to avoid leaking sensitive user directory structures or host usernames in evidence records.
- **Path Containment:** All generated files (staged captures and metadata) are strictly validated to reside within the designated `runtime/` root directory using resolved path canonicalization. Directory traversal filenames (`../`, `\`, `/`) are rejected.
- **Integrity Verification:** A SHA-256 hash is computed from the original source file and verified against the staged copy immediately following staging. Any discrepancy raises an `EvidenceIntegrityError` and cleans up partial artifacts.
- **Non-Destructive:** The source capture file is strictly treated as read-only and is never modified or deleted.

## Metadata Schema Fields

Each accepted capture produces a machine-readable `runtime/jobs/<job_id>/metadata.json` adhering to `metadata_schema_version = "1.0"`:

| Field | Type | Description / Value |
|---|---|---|
| `job_id` | `str` | Collision-resistant identifier (`job_YYYYMMDDTHHMMSSZ_<uuid>`) |
| `analysis_mode` | `str` | `"offline"` (mandatory literal) |
| `status` | `str` | `"accepted"` (mandatory literal) |
| `original_file_name` | `str` | Base filename of candidate file |
| `staged_file_name` | `str` | Clean filename under `runtime/uploads/<job_id>/` |
| `extension` | `str` | Lowercase extension (`.pcap` or `.pcapng`) |
| `file_size_bytes` | `int` | Exact size in bytes |
| `sha256` | `str` | 64-character lowercase hexadecimal SHA-256 digest |
| `ingestion_timestamp_utc` | `str` | ISO 8601 UTC timestamp |
| `source_path_disclosed` | `bool` | `false` |
| `coverage` | `str` | `"insufficient"` (indicates protocol parsing not yet performed) |
| `attribution` | `str` | `"not_proven"` (mandatory non-attribution policy) |
| `limitations` | `list[str]` | Explicit phase scope limitations |
| `metadata_schema_version`| `str` | `"1.0"` |

## Explicit Limitations

> **Limitation Notice:** Phase 1 validates file-level evidence only; protocol, TCP, TLS, certificate, cryptographic policy, posture scoring, ML, reporting, and dashboard analysis are not yet implemented.

Extension validation confirms only file naming and file-level readability; it does not prove internal PCAP format validity or packet integrity.

## Local Artifact Paths

All generated files are strictly organized under the `runtime/` workspace:

- Staged capture: `runtime/uploads/<job_id>/<staged_file_name>`
- Evidence metadata: `runtime/jobs/<job_id>/metadata.json`

## Test Strategy

Phase 1 functionality is validated using synthetic in-memory binary fixtures and temporary directory trees:

- Extension validation (case-insensitivity, rejection of unsupported formats).
- Boundary conditions (empty files, oversized captures, unreadable paths, directories).
- Chunked hashing accuracy against known SHA-256 test vectors.
- Atomic write failure simulation and automatic artifact cleanup.
- Absence of source path disclosure and strict containment enforcement.
