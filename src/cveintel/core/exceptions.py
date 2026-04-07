"""CVEIntel exception hierarchy."""


class CVEIntelError(Exception):
    """Base exception for all CVEIntel errors."""


class InputError(CVEIntelError):
    """Raised for invalid CVE input or unreadable files."""


class FetchError(CVEIntelError):
    """Raised when fetching advisory data fails."""


class AnalysisError(CVEIntelError):
    """Raised when LLM analysis fails."""


class OutputError(CVEIntelError):
    """Raised when writing output fails."""


class ConfigError(CVEIntelError):
    """Raised for missing or invalid configuration."""
