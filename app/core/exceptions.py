"""CYBERWOLF Core Exceptions Hierarchy."""

class CyberwolfError(Exception):
    """Base exception for all CYBERWOLF operations."""
    def __init__(self, message: str, details: str = None):
        super().__init__(message)
        self.message = message
        self.details = details

class AuthorizationError(CyberwolfError):
    """Raised when an operation lacks valid authorization."""
    pass

class ScopeError(CyberwolfError):
    """Raised when a target is outside the authorized scope."""
    pass

class SafetyPolicyViolation(CyberwolfError):
    """Raised when an operation violates active safety policy or safe mode."""
    pass

class ToolExecutionError(CyberwolfError):
    """Raised when an external or native security tool fails execution."""
    pass

class AIError(CyberwolfError):
    """Raised when AI inference or connection to Ollama fails."""
    pass

class DatabaseError(CyberwolfError):
    """Raised on SQLite database errors."""
    pass

class ValidationError(CyberwolfError):
    """Raised when user or tool inputs fail sanitization."""
    pass
