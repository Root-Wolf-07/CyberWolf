"""CYBERWOLF Target Management Service (V2).

Provides business logic for validating, enrolling, inspecting, and scoping
authorized assessment targets.
"""

from typing import Dict, List, Any, Optional
from app.security.sanitizer import parse_and_validate_target, TargetValidationResult
from app.security.authorization import AuthorizationEngine
from app.core.exceptions import TargetValidationError, AuthorizationError
from app.core.logger import get_logger

logger = get_logger()


class TargetService:
    """Manages target lifecycle, validation, and authorized scopes."""

    def __init__(self, auth_engine: Optional[AuthorizationEngine] = None):
        self.auth_engine = auth_engine or AuthorizationEngine()

    def validate_target(self, target_str: str) -> TargetValidationResult:
        """Parse and strictly validate a target string."""
        return parse_and_validate_target(target_str)

    def add_target(self, target_str: str, authorized: bool = True,
                   scope_id: str = "lab-network", description: Optional[str] = None) -> Dict[str, Any]:
        """Add and authorize a new assessment target."""
        parsed = self.validate_target(target_str)
        if not authorized:
            raise AuthorizationError(
                f"Cannot add target '{target_str}' without authorization confirmation.",
                remediation="Pass --authorized or verify explicit permission."
            )

        success = self.auth_engine.add_authorized_target(
            target=parsed.normalized,
            scope_id=scope_id,
            description=description
        )

        return {
            "target": parsed.normalized,
            "target_type": parsed.target_type,
            "host": parsed.host,
            "scope_id": scope_id,
            "authorized": authorized,
            "persisted": success
        }

    def list_targets(self) -> List[Dict[str, Any]]:
        """List all currently authorized targets across all scopes."""
        return self.auth_engine.list_authorized_targets()

    def check_authorization(self, target_str: str, operation_name: str = "general_assessment") -> Dict[str, Any]:
        """Verify whether a target is currently authorized for an operation."""
        is_auth, msg, scope = self.auth_engine.check_target_scope(target_str, operation_name)
        return {
            "authorized": is_auth,
            "target": target_str,
            "message": msg,
            "scope": scope
        }


_TARGET_SERVICE: Optional[TargetService] = None

def get_target_service() -> TargetService:
    global _TARGET_SERVICE
    if _TARGET_SERVICE is None:
        _TARGET_SERVICE = TargetService()
    return _TARGET_SERVICE
