"""
SecureMailScope — Custom exception hierarchy.
"""


class SecureMailScopeError(Exception):
    """Base exception for all SecureMailScope errors."""


class ConfigurationError(SecureMailScopeError):
    """Raised when configuration is missing, invalid, or unsupported."""


class UnsupportedPhaseError(SecureMailScopeError):
    """Raised when functionality belonging to a future phase is invoked."""
