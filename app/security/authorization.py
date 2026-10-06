"""CYBERWOLF Target Authorization & Scope Enforcement Subsystem (V2).

Enforces mandatory authorization-first security model:
Target -> Target Parser -> Authorization Check -> Scope Validation -> Policy Validation -> Tool Validation -> Execution
"""

import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import yaml

from app.core.config import get_config
from app.core.logger import get_logger, audit_log
from app.core.exceptions import ScopeError, AuthorizationError
from app.security.sanitizer import parse_and_validate_target, sanitize_target


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
        parsed_target = parse_and_validate_target(target)
        clean_target = parsed_target.normalized

        # 1. Check excluded targets list
        excluded = self.config_manager.targets_data.get("excluded_targets", [])
        for excl in excluded:
            if self._target_matches(clean_target, excl):
                msg = (
                    f"Target rejected. Reason: '{clean_target}' matches explicit exclusion '{excl}'. "
                    f"Action: Remove exclusion or select an authorized target."
                )
                audit_log("SCOPE_CHECK", "REJECT", clean_target, decision="REJECTED", details=msg)
                return False, msg, None

        # 2. Check configured authorized scopes
        scopes = self.config_manager.targets_data.get("scopes", [])
        for scope in scopes:
            scope_targets = scope.get("targets", [])
            allowed_ops = scope.get("allowed_operations", [])

            for st in scope_targets:
                if self._target_matches(clean_target, st):
                    # Check operation permission
                    op_norm = operation_name.lower().replace("-", "_")
                    op_map = {
                        "network": "network_scan",
                        "scan": "network_scan",
                        "web": "web_assessment",
                        "vuln": "vuln_scan",
                        "sql": "sql_test",
                        "pentest": "pentest_validation"
                    }
                    target_op = op_map.get(op_norm, op_norm)

                    if operation_name and operation_name != "general_assessment" and allowed_ops:
                        if target_op not in allowed_ops and operation_name not in allowed_ops and "all" not in allowed_ops:
                            msg = (
                                f"Target rejected. Reason: Operation '{operation_name}' is not permitted for scope '{scope.get('name')}'. "
                                f"Action: Update scope permissions in targets.yaml or choose an allowed operation."
                            )
                            audit_log("SCOPE_CHECK", "REJECT", clean_target, decision="REJECTED", details=msg)
                            return False, msg, scope

                    audit_log("SCOPE_CHECK", "APPROVE", clean_target, decision="APPROVED", details=f"Matched scope '{scope.get('name')}'")
                    return True, f"Target matched authorized scope: {scope.get('name')}", scope

        # 3. Target is outside pre-configured scopes
        msg = (
            f"Target rejected. Reason: Target '{clean_target}' is outside configured scopes. "
            f"Action: Add the target to an authorized lab scope before scanning using 'cyberwolf target add {clean_target} --authorized'."
        )
        audit_log("SCOPE_CHECK", "UNAUTHORIZED", clean_target, decision="REJECTED", details=msg)
        return False, msg, None

    def add_authorized_target(self, target: str, scope_id: str = "lab-network",
                              description: Optional[str] = None) -> bool:
        """Add a target to the configured target scopes in config/targets.yaml."""
        parsed = parse_and_validate_target(target)
        targets_file = self.config_manager.base_dir / "config" / "targets.yaml"

        scopes = self.config_manager.targets_data.get("scopes", [])
        target_added = False

        for scope in scopes:
            if scope.get("id") == scope_id:
                if parsed.normalized not in scope.get("targets", []):
                    scope.setdefault("targets", []).append(parsed.normalized)
                    target_added = True
                break

        if not target_added:
            # Create new scope for this scope_id
            new_scope = {
                "id": scope_id,
                "name": description or f"Authorized Scope {scope_id}",
                "risk_level": "medium",
                "targets": [parsed.normalized],
                "allowed_operations": ["all"]
            }
            scopes.append(new_scope)
            target_added = True

        if target_added and targets_file.exists():
            try:
                with open(targets_file, "w", encoding="utf-8") as f:
                    yaml.dump(self.config_manager.targets_data, f, default_flow_style=False)
                audit_log("TARGET_MANAGEMENT", "ADD_TARGET", target=parsed.normalized,
                          decision="APPROVED", details=f"Added to scope {scope_id}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to persist target to targets.yaml: {e}")

        return target_added

    def list_authorized_targets(self) -> List[Dict[str, Any]]:
        """Return formatted summary of all configured authorized targets and scopes."""
        result = []
        scopes = self.config_manager.targets_data.get("scopes", [])
        for s in scopes:
            for t in s.get("targets", []):
                result.append({
                    "target": t,
                    "scope_id": s.get("id"),
                    "scope_name": s.get("name"),
                    "risk_level": s.get("risk_level", "low"),
                    "allowed_operations": s.get("allowed_operations", [])
                })
        return result

    def _target_matches(self, target: str, pattern: str) -> bool:
        """Check if target matches an IP, CIDR, wildcard domain, or literal string."""
        target_host = target
        if target.startswith("http://") or target.startswith("https://"):
            target_host = urlparse(target).hostname or target
        elif ":" in target and not target.startswith("["):
            target_host = target.split(":")[0]

        # Wildcard domain match (*.domain.com)
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return target_host.endswith(suffix)

        if target_host.lower() == pattern.lower() or target.lower() == pattern.lower():
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
        """Interactive authorization workflow when running in interactive CLI mode."""
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

        try:
            choice = input("\n Select authorization basis [1-4]: ").strip()
            if choice in ["1", "2", "3"]:
                basis = {
                    "1": "OWNER_DECLARED",
                    "2": "WRITTEN_AUTH_DECLARED",
                    "3": "ISOLATED_LAB_DECLARED"
                }[choice]
                audit_log("INTERACTIVE_AUTHORIZATION", "CONSENT_GRANTED", clean_target,
                          decision="APPROVED", details=f"Operator declared basis: {basis}")
                print(f"[+] Authorization recorded ({basis}). Proceeding with assessment.\n")
                return True
            else:
                audit_log("INTERACTIVE_AUTHORIZATION", "CONSENT_REFUSED", clean_target,
                          decision="REJECTED", details="Operator cancelled")
                print("[-] Assessment aborted by operator.\n")
                return False
        except (KeyboardInterrupt, EOFError):
            print("\n[-] Operation aborted.")
            return False

    def is_authorized(self, target: str, operation_name: str = "general_assessment") -> Tuple[bool, str]:
        """Check whether target is authorized, returning (is_authorized, basis)."""
        ok, msg, scope = self.check_target_scope(target, operation_name)
        if ok:
            basis = "EXPLICIT_ENROLLED" if scope and scope.get("id") in ["unit-test-lab", "lab-network"] else "CONFIG_SCOPE"
            return True, basis
        return False, "REJECTED_UNAUTHORIZED"

    def get_rejection_guidance(self, target: str) -> str:
        """Return actionable rejection message for unauthorized targets."""
        ok, msg, _ = self.check_target_scope(target)
        return msg


TargetAuthorizer = AuthorizationEngine


def add_authorized_target(target: str, scope_id: str = "lab-network", scope_name: Optional[str] = None,
                          description: Optional[str] = None) -> bool:
    """Convenience helper to enroll target in authorization scopes."""
    engine = AuthorizationEngine()
    sid = scope_name or scope_id
    return engine.add_authorized_target(target, scope_id=sid, description=description)

