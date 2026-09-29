"""
SecureMailScope — Capture ingestion service (Phase 1).

Orchestrates candidate validation, safe staging, SHA-256 evidence hashing,
and atomic evidence metadata creation.
"""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from securemailscope.exceptions import (
    EvidenceIntegrityError,
    EvidenceStagingError,
    SecureMailScopeError,
    UnsafePathError,
)
from securemailscope.ingest.hashing import calculate_sha256
from securemailscope.ingest.validator import (
    DEFAULT_MAX_FILE_SIZE_BYTES,
    validate_capture_file,
)
from securemailscope.paths import (
    ensure_within_runtime,
    job_dir,
    job_upload_dir,
    runtime_root,
)
from securemailscope.schemas.evidence import (
    PHASE_1_LIMITATION_TEXT,
    EvidenceMetadata,
)


def ingest_capture(
    input_path: str | Path,
    *,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    runtime_root_path: Path | None = None,
    now_utc: datetime | None = None,
) -> EvidenceMetadata:
    """Ingest, validate, stage, and generate evidence metadata for a capture file.

    Workflow:
        1. Validate candidate file eligibility (extension, size, non-empty).
        2. Compute SHA-256 hash of original source file.
        3. Generate a collision-resistant unique job ID.
        4. Validate that all staging target paths lie within the runtime root.
        5. Stage the capture file into runtime/uploads/<job_id>/.
        6. Compute SHA-256 of staged copy and verify integrity against source.
        7. Atomically write metadata JSON into runtime/jobs/<job_id>/metadata.json.
        8. Return the structured EvidenceMetadata record.

    Args:
        input_path: Path to candidate PCAP/PCAPNG file.
        max_file_size_bytes: Maximum allowed file size in bytes.
        runtime_root_path: Optional override for runtime root directory.
        now_utc: Optional override for current UTC datetime (for testing).

    Returns:
        EvidenceMetadata record containing validated file attributes and SHA-256.

    Raises:
        InputValidationError: If the candidate file fails validation.
        UnsupportedCaptureTypeError: If the extension is not .pcap or .pcapng.
        EmptyCaptureError: If the file is 0 bytes.
        CaptureTooLargeError: If the file exceeds max_file_size_bytes.
        UnsafePathError: If path containment or safe naming checks fail.
        EvidenceIntegrityError: If source and staged SHA-256 digests differ.
        EvidenceStagingError: If staging or metadata serialization fails.
    """
    validated = validate_capture_file(
        input_path, max_file_size_bytes=max_file_size_bytes
    )

    # 1. Compute source digest before copying
    source_sha256 = calculate_sha256(validated.original_path)

    # 2. Determine UTC timestamp & generate job ID
    if now_utc is None:
        effective_utc = datetime.now(UTC)
    elif now_utc.tzinfo is None:
        effective_utc = now_utc.replace(tzinfo=UTC)
    else:
        effective_utc = now_utc.astimezone(UTC)

    timestamp_str = effective_utc.strftime("%Y%m%dT%H%M%SZ")
    short_uuid = uuid.uuid4().hex[:8]
    job_id = f"job_{timestamp_str}_{short_uuid}"

    root = runtime_root(runtime_root_path)
    target_upload_dir = job_upload_dir(job_id, root)
    target_job_dir = job_dir(job_id, root)

    # 3. Sanitize staged filename and ensure containment
    original_name = validated.original_file_name
    staged_name = Path(original_name).name
    is_unsafe_name = (
        not staged_name
        or staged_name in (".", "..")
        or "/" in staged_name
        or "\\" in staged_name
    )
    if is_unsafe_name:
        raise UnsafePathError(f"Unsafe filename detected: {original_name}")

    staged_path = target_upload_dir / staged_name
    ensure_within_runtime(staged_path, root)

    metadata_path = target_job_dir / "metadata.json"
    ensure_within_runtime(metadata_path, root)

    upload_created = False
    job_created = False

    def _cleanup() -> None:
        """Clean up partial staging artifacts without touching the source file."""
        if upload_created and target_upload_dir.exists():
            shutil.rmtree(target_upload_dir, ignore_errors=True)
        if job_created and target_job_dir.exists():
            shutil.rmtree(target_job_dir, ignore_errors=True)

    try:
        target_upload_dir.mkdir(parents=True, exist_ok=True)
        upload_created = True

        # 4. Copy file to staging area
        shutil.copy2(validated.original_path, staged_path)

        # 5. Verify staged file integrity
        staged_sha256 = calculate_sha256(staged_path)
        if staged_sha256 != source_sha256:
            raise EvidenceIntegrityError(
                f"Integrity check failed: source hash ({source_sha256}) "
                f"does not match staged hash ({staged_sha256})."
            )

        # 6. Create job metadata directory and build metadata model
        target_job_dir.mkdir(parents=True, exist_ok=True)
        job_created = True

        evidence = EvidenceMetadata(
            job_id=job_id,
            original_file_name=original_name,
            staged_file_name=staged_name,
            extension=validated.extension,
            file_size_bytes=validated.file_size_bytes,
            sha256=staged_sha256,
            ingestion_timestamp_utc=effective_utc.isoformat(),
            analysis_mode="offline",
            status="accepted",
            source_path_disclosed=False,
            coverage="insufficient",
            attribution="not_proven",
            limitations=[PHASE_1_LIMITATION_TEXT],
            metadata_schema_version="1.0",
        )

        # 7. Atomic metadata JSON write
        tmp_meta_file = target_job_dir / f".metadata_{uuid.uuid4().hex}.tmp"
        try:
            with tmp_meta_file.open("w", encoding="utf-8") as f:
                f.write(evidence.to_json())
                f.flush()
            tmp_meta_file.replace(metadata_path)
        except Exception as exc:
            if tmp_meta_file.exists():
                tmp_meta_file.unlink(missing_ok=True)
            raise EvidenceStagingError(
                f"Failed to atomically write metadata JSON: {exc}"
            ) from exc

        return evidence

    except SecureMailScopeError:
        _cleanup()
        raise
    except Exception as exc:
        _cleanup()
        raise EvidenceStagingError(
            f"Staging failed during capture ingestion: {exc}"
        ) from exc
