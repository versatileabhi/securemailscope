"""
SecureMailScope — Custom exception hierarchy.
"""


class SecureMailScopeError(Exception):
    """Base exception for all SecureMailScope errors."""


class ConfigurationError(SecureMailScopeError):
    """Raised when configuration is missing, invalid, or unsupported."""


class UnsupportedPhaseError(SecureMailScopeError):
    """Raised when functionality belonging to a future phase is invoked."""


# Phase 1 Ingestion & Evidence Exceptions


class InputValidationError(SecureMailScopeError):
    """Raised when input candidate file fails basic validation."""


class UnsupportedCaptureTypeError(InputValidationError):
    """Raised when candidate file extension is not a supported capture format."""


class CaptureTooLargeError(InputValidationError):
    """Raised when candidate file exceeds the maximum permitted file size."""


class EmptyCaptureError(InputValidationError):
    """Raised when candidate capture file is zero bytes."""


class UnsafePathError(SecureMailScopeError):
    """Raised when a path violates security boundaries (e.g. traversal/containment)."""


class EvidenceIntegrityError(SecureMailScopeError):
    """Raised when evidence integrity verification fails (e.g. hash mismatch)."""


class EvidenceStagingError(SecureMailScopeError):
    """Raised when staging or metadata persistence fails during ingestion."""


# Phase 2 Zeek Runner Exceptions


class InvalidEvidenceReferenceError(SecureMailScopeError):
    """Raised when an invalid or non-existent evidence record is passed to a runner."""


class ZeekError(SecureMailScopeError):
    """Base exception for Zeek discovery, configuration, and execution errors."""


class ZeekNotAvailableError(ZeekError):
    """Raised when Zeek is required but not found on the local system."""


class ZeekExecutionError(ZeekError):
    """Raised when offline Zeek execution fails."""


class ZeekExecutionTimeoutError(ZeekExecutionError):
    """Raised when offline Zeek execution exceeds the configured timeout."""


# Phase 3 Log Parsing Exceptions


class ZeekLogParseError(SecureMailScopeError):
    """Raised when a Zeek JSON log file cannot be opened or is fatally unreadable.

    Note: Malformed individual lines are represented as ParseWarning objects
    and never raise this exception. This exception is reserved for
    unrecoverable file-level failures such as permission errors.
    """

