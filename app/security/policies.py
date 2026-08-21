"""CYBERWOLF Safety Policies & Mode Controller."""

from typing import Dict, Any, Tuple
from app.core.config import get_config
from app.core.logger import get_logger, audit_log
from app.core.exceptions import SafetyPolicyViolation

class PolicyEngine:
    """Enforces execution limits, rate limits, and safety mode rules."""
    def __init__(self, config_manager=None):
        self.config_manager = config_manager or get_config()
        self.logger = get_logger()

    def validate_action(self, action_category: str, is_destructive: bool = False) -> Tuple[bool, str]:
        """Check if an action is permitted under the current mode."""
        mode = self.config_manager.get_active_mode()
        policies = self.config_manager.policies_data.get("policies", {}).get("modes", {})
        mode_policy = policies.get(mode, {})

        if is_destructive:
            audit_log("POLICY_CHECK", "BLOCKED_DESTRUCTIVE", decision="REJECTED",
                      details=f"Destructive action blocked under mode {mode}")
            return False, f"Destructive actions are prohibited under mode {mode}."

        if action_category == "port_scan" and not mode_policy.get("allows_port_scan", True):
            return False, f"Port scanning disabled in {mode} mode (Passive mode active)."

        if action_category == "web_fuzzing" and not mode_policy.get("allows_web_fuzzing", False):
            return False, f"Web fuzzing disabled in {mode} mode. Switch to ACTIVE_SCAN or LAB_MODE."

        if action_category == "sqli_probes" and not mode_policy.get("allows_sqli_probes", True):
            return False, f"Active SQLi probing disabled in {mode} mode."

        if action_category == "exploit_validation" and not mode_policy.get("allows_exploit_validation", False):
            return False, f"Exploitation validation disabled in {mode} mode. Switch to AUTHORIZED_PENTEST or LAB_MODE."

        return True, "Action allowed by active policy."
