# SecureMailScope — Phase 2: Zeek Availability Check & Offline Runner

## Overview & Scope

Phase 2 introduces the offline Zeek execution boundary for SecureMailScope. It provides:
1. Safe discovery of the local Zeek executable and retrieval of its version string via `zeek --version`.
2. Safe offline command construction for previously ingested, validated, and staged Phase 1 PCAP/PCAPNG evidence.
3. Isolated execution of Zeek strictly in offline trace-reading mode (`-r`) with output written to a dedicated per-job log directory (`runtime/zeek_logs/<job_id>/`).
4. Structured execution outcome tracking via `ZeekRunResult`.

## Offline-Only Security Boundary

- **No Live Capture:** Zeek is strictly invoked with the `-r` flag targeting a staged capture file in `runtime/uploads/<job_id>/`. The live interface capture flag (`-i`) is never permitted.
- **No Network Activity:** The runner makes no outbound network connections, binds no listening sockets, and requires no external API or cloud services.
- **Safe Command Construction:** Commands are executed strictly as argument lists/tuples (`shell=False`) using `subprocess.run`. No shell string interpolation is performed.
- **Analyst-Controlled Checksum Flag:** The `-C` flag (ignore invalid IP checksums) is omitted by default and can only be enabled by explicit analyst opt-in.

## Zeek Command Format

Offline commands are constructed in the following format:

```text
zeek [-C] -r <staged_capture_path> Log::default_logdir=<isolated_log_directory>
```

- Executable path: either configured explicitly or resolved via `shutil.which`.
- Staged capture path: verified to reside under `runtime/uploads/<job_id>/`.
- Log directory: verified to reside under `runtime/zeek_logs/<job_id>/`.

## Output Directory Policy

All Zeek log files are confined to:
```text
runtime/zeek_logs/<job_id>/
```
- The directory is created only after Zeek availability has been verified.
- The directory is isolated per job ID.
- Generated logs (e.g., `conn.log`, `ssl.log`, `smtp.log`) are preserved intact for consumption by Phase 3 JSON readers.

## Result Statuses

The `ZeekRunResult` dataclass reports one of five discrete statuses:

| Status | Condition |
|---|---|
| `completed` | Zeek process exited with return code 0. |
| `zeek_unavailable` | Zeek binary not found on PATH or configured location. |
| `invalid_evidence_reference` | Staged capture file missing, outside runtime, or evidence not accepted. |
| `timed_out` | Zeek process exceeded configured execution timeout. |
| `failed` | Zeek process exited with a non-zero return code. |

## Timeout and Process Control

- Execution is governed by an explicit timeout (default: 120 seconds).
- In the event of a timeout (`subprocess.TimeoutExpired`), the process state is captured with `status="timed_out"` and `timed_out=True`.
- Standard output and standard error streams are capped at 2,000 characters to prevent excessive memory consumption.

## Explicit Non-Goals

- **No Log Parsing:** Phase 2 does not parse, deserialize, or inspect any log files produced by Zeek. Log reading is reserved for Phase 3.
- **No Protocol Extraction:** No SMTP, IMAP, POP3, TLS, or X.509 field extraction is performed in Phase 2.
- **No Report Generation:** No assessment reports (JSON, HTML, PDF) or dashboard updates are generated.

## Setup & Testing Note

Unit tests for Phase 2 do not require a local Zeek installation; all process invocations and filesystem checks are fully validated using deterministic mocks and monkeypatched fixtures. Live end-to-end integration requires a locally installed Zeek binary in a subsequent controlled validation step.
