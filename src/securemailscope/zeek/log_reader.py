"""
SecureMailScope — Zeek newline-delimited JSON log reader.

Reads Zeek JSON log files safely, line by line, collecting non-fatal
parse events as ParseWarning objects. This module never writes files,
makes network connections, or invokes subprocesses.

Supported log format: one JSON object per line (Zeek JSON output mode).
Lines beginning with ``#`` and blank lines are silently skipped (Zeek
may produce TSV-style headers even in JSON-output directories).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from securemailscope.schemas.session import ParseWarning

# Maximum characters retained from an offending line in a ParseWarning.
MAX_RAW_LINE_LENGTH: int = 200


def read_jsonl_log(
    path: Path,
    *,
    log_type: str,
    max_raw_line_length: int = MAX_RAW_LINE_LENGTH,
) -> tuple[list[dict[str, Any]], list[ParseWarning]]:
    """Read a Zeek newline-delimited JSON log file.

    Reads ``path`` line by line and returns all successfully parsed
    JSON-object records together with a list of non-fatal ParseWarning
    objects describing every issue encountered.

    Args:
        path: Absolute path to the Zeek JSON log file.
        log_type: Source log identifier used in warnings (e.g. "conn", "smtp").
        max_raw_line_length: Maximum characters from an offending line stored
            in ParseWarning.raw_line. Defaults to 200.

    Returns:
        A tuple ``(records, warnings)`` where:
        - ``records`` is a list of successfully parsed dict objects.
          Unknown fields are preserved as-is.
        - ``warnings`` is a list of ParseWarning for every non-fatal issue.

    Raises:
        Nothing. All errors are captured as ParseWarning objects.
        (UnsafePathError from path containment is raised by the caller
        before this function is invoked.)

    Guarantees:
        - No filesystem writes.
        - No network access or subprocess calls.
        - Unknown Zeek fields are preserved in returned records.
        - Empty files return ([], []).
        - FileNotFoundError returns ([], [one warning]).
    """
    records: list[dict[str, Any]] = []
    warnings: list[ParseWarning] = []

    try:
        file_obj = path.open(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        warnings.append(
            ParseWarning(
                log_type=log_type,
                line_number=0,
                issue="Optional log not found.",
                raw_line=None,
            )
        )
        return records, warnings
    except OSError as exc:
        warnings.append(
            ParseWarning(
                log_type=log_type,
                line_number=0,
                issue=f"Could not open log file: {exc}",
                raw_line=None,
            )
        )
        return records, warnings

    with file_obj:
        for line_number, raw_line in enumerate(file_obj, start=1):
            stripped = raw_line.rstrip("\n\r")

            # Silently skip blank lines and TSV-style comment/header lines.
            if not stripped or stripped.startswith("#"):
                continue

            # Attempt JSON parse.
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                warnings.append(
                    ParseWarning(
                        log_type=log_type,
                        line_number=line_number,
                        issue="Malformed JSON: could not parse line.",
                        raw_line=stripped[:max_raw_line_length],
                    )
                )
                continue

            # Require root to be a JSON object (dict).
            if not isinstance(obj, dict):
                warnings.append(
                    ParseWarning(
                        log_type=log_type,
                        line_number=line_number,
                        issue=(
                            f"JSON root is not an object (got {type(obj).__name__})."
                        ),
                        raw_line=stripped[:max_raw_line_length],
                    )
                )
                continue

            records.append(obj)

    return records, warnings
