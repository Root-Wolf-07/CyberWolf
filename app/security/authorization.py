"""CYBERWOLF Target Authorization & Scope Enforcement Subsystem."""

import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Any, Tuple, Optional
from app.core.config import get_config
from app.core.logger import get_logger, audit_log
from app.core.exceptions import ScopeError, AuthorizationError
from app.security.sanitizer import sanitize_target

class AuthorizationEngine:
    """Validates target scope, exclusions, and active consent before any security operation."""
    def __init__(self, config_manager=None):
        self.config_manager = config_manager or get_config()
        self.logger = get_logger()

    def check_target_scope(self, target: str, operation_name: str = "general_assessment") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Check whether target is in authorized scopes.
        
        Returns:
            (is_authorized, reason_or_message, matching_scope_dict)
        """
        clean_target = sanitize_target(target)
        
        # 1. Check excluded targets
        excluded = self.config_manager.targets_data.get("excluded_targets", [])
        for excl in excluded:
            if self._target_matches(clean_target, excl):
                msg = f"Target '{clean_target}' is in the explicit exclusion list ({excl})."
                audit_log("SCOPE_CHECK", "REJECT", clean_target, decision="REJECTED", details=msg)
                return False, msg, None

        # 2. Check authorized scopes
        scopes = self.config_manager.targets_data.get("scopes", [])
        for scope in scopes:
            scope_targets = scope.get("targets", [])
            allowed_ops = scope.get("allowed_operations", [])
            
            for st in scope_targets:
                if self._target_matches(clean_target, st):
                    # Check operation permission
                    if operation_name and operation_name != "general_assessment" and allowed_ops and (operation_name not in allowed_ops and "all" not in allowed_ops):
                        msg = f"Operation '{operation_name}' is not permitted for scope '{scope.get('name')}'."
                        audit_log("SCOPE_CHECK", "REJECT", clean_target, decision="REJECTED", details=msg)
                        return False, msg, scope
                    
                    audit_log("SCOPE_CHECK", "APPROVE", clean_target, decision="APPROVED", details=f"Matched scope '{scope.get('name')}'")
                    return True, f"Target matched scope: {scope.get('name')}", scope

        # 3. Target is outside pre-configured scopes
        msg = f"Target '{clean_target}' is outside configured scopes in targets.yaml."
        audit_log("SCOPE_CHECK", "UNAUTHORIZED", clean_target, decision="REJECTED", details=msg)
        return False, msg, None

    def _target_matches(self, target: str, pattern: str) -> bool:
        """Check if target matches an IP, CIDR, wildcard domain, or literal."""
        target_host = target
        if target.startswith("http://") or target.startswith("https://"):
            target_host = urlparse(target).hostname or target

        if pattern.startswith("*."):
            suffix = pattern[1:]
            return target_host.endswith(suffix)

        if target_host.lower() == pattern.lower():
            return True

        # IP vs CIDR comparison
        try:
            target_ip = ipaddress.ip_address(target_host)
            if "/" in pattern:
                net = ipaddress.ip_network(pattern, strict=False)
                return target_ip in net
            else:
                pat_ip = ipaddress.ip_address(pattern)
                return target_ip == pat_ip
        except ValueError:
            pass

        return False

    def require_authorization_interactive(self, target: str, operation_name: str) -> bool:
        """Interactive authorization workflow when running in CLI."""
        clean_target = sanitize_target(target)
        is_auth, reason, scope = self.check_target_scope(clean_target, operation_name)
        
        if is_auth:
            return True
            
        print("\n" + "=" * 60)
        print("          CYBERWOLF TARGET AUTHORIZATION REQUIRED")
        print("=" * 60)
        print(f" Target: {clean_target}")
        print(f" Operation: {operation_name}")
        print(f" Status: Outside pre-configured targets.yaml")
        print("\n Legal and Safety Declaration:")
        print(" [1] I own this system/network")
        print(" [2] I have explicit written authorization for penetration testing")
        print(" [3] This is an authorized isolated lab/CTF system")
        print(" [4] Cancel and abort operation")
        print("-" * 60)
        
        try:
            choice = input(" Select authorization basis (1/2/3/4): ").strip()
            if choice in ["1", "2", "3"]:
                confirm = input(f" Confirm authorization for target '{clean_target}'? [y/N]: ").strip().lower()
                if confirm in ["y", "yes"]:
                    audit_log("USER_AUTHORIZATION", "MANUAL_CONSENT", clean_target,
                              decision="CONFIRMED", details=f"User selected basis: {choice}")
                    return True
        except (KeyboardInterrupt, EOFError):
            pass
            
        audit_log("USER_AUTHORIZATION", "ABORT", clean_target, decision="REJECTED", details="User aborted authorization")
        return False
