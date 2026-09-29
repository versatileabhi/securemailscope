"""
SecureMailScope — Project-wide constants.

Only safe, non-sensitive constants are defined here.
Do not add security rules, credentials, IP addresses, or runtime paths here.
"""

# Project identity
PROJECT_NAME: str = "SecureMailScope"
PROJECT_VERSION: str = "0.1.0"

# Analysis mode — always offline for core operation
DEFAULT_ANALYSIS_MODE: str = "offline"

# Attribution state — the tool never establishes attribution
DEFAULT_ATTRIBUTION_STATE: str = "not_proven"

# Coverage states used when evidence is absent or incomplete
VALID_COVERAGE_STATES: tuple[str, ...] = ("full", "partial", "insufficient")

# Current development phase
CURRENT_PHASE: int = 4
