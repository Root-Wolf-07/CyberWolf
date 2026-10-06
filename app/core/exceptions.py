"""CYBERWOLF Core Exceptions Hierarchy (V2).

Provides consistent, user-understandable application exceptions with
rich diagnostic context and remediation hints.
"""

from typing import Optional


class CyberWolfError(Exception):
    """Base exception for all CYBERWOLF operations."""
    def __init__(self, message: str, details: Optional[str] = None, remediation: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.details = details
        self.remediation = remediation

    def __str__(self) -> str:
        base = self.message
        if self.details:
            base += f" ({self.details})"
        if self.remediation:
            base += f"\nAction: {self.remediation}"
        return base


# Backward compatibility alias
CyberwolfError = CyberWolfError


class ConfigurationError(CyberWolfError):
    """Raised when configuration files are missing, malformed, or invalid."""
    pass


class AuthorizationError(CyberWolfError):
    """Raised when an operation lacks explicit target authorization."""
    pass


class ScopeError(CyberWolfError):
    """Raised when a target is outside the authorized scope."""
    pass


class TargetValidationError(CyberWolfError):
    """Raised when target inputs fail RFC, IP, CIDR, or URL validation."""
    pass


# Backward compatibility alias
ValidationError = TargetValidationError


class PolicyViolationError(CyberWolfError):
    """Raised when an action violates active safety policy or execution mode."""
    pass


# Backward compatibility alias
SafetyPolicyViolation = PolicyViolationError


class ToolNotFoundError(CyberWolfError):
    """Raised when a required external security binary is not found in PATH."""
    pass


class ToolExecutionError(CyberWolfError):
    """Raised when an external or native security tool fails execution."""
    pass


class ParserError(CyberWolfError):
    """Raised when raw scanner output cannot be parsed into structured data."""
    pass


class DatabaseError(CyberWolfError):
    """Raised on SQLite database queries, integrity checks, or migration errors."""
    pass


class ReportGenerationError(CyberWolfError):
    """Raised when report rendering (HTML, PDF, JSON, CSV) encounters a failure."""
    pass


class AIError(CyberWolfError):
    """Raised when AI inference or connection to Ollama fails."""
    pass
