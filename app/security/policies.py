"""CYBERWOLF Central Policy Engine & Operational Mode Controller (V2).

Enforces execution limits, mode rules, rate limiting, and tool allowlisting:
- PASSIVE (non-intrusive only)
- SAFE_SCAN (standard discovery, non-destructive)
- ACTIVE_SCAN (in-depth enumeration & directory fuzzing)
- AUTHORIZED_PENTEST (controlled PoC verification with explicit confirmation)
- LAB_MODE (dedicated security research & CTF testing)
"""

from typing import Dict, Any, Tuple, Optional, List
from app.core.config import get_config
from app.core.logger import get_logger, audit_log
from app.core.exceptions import PolicyViolationError
from app.database.models import Policy


class PolicyEngine:
    """Enforces execution limits, allowed tools, and safety mode rules."""

    def __init__(self, config_manager=None):
        self.config_manager = config_manager or get_config()
        self.logger = get_logger()

    def get_active_policy(self) -> Policy:
        """Construct canonical Policy model based on current active mode."""
        mode = self.config_manager.get_active_mode()
        modes_cfg = self.config_manager.policies_data.get("policies", {}).get("modes", {})
        m_data = modes_cfg.get(mode, {})

        return Policy(
            name=mode,
            allow_network_scan=m_data.get("allows_port_scan", mode != "PASSIVE"),
            allow_web_scan=True,
            allow_packet_capture=True,
            allow_bruteforce=mode in ["AUTHORIZED_PENTEST", "LAB_MODE"],
            allow_destructive=False,  # Always false by default
            max_scan_duration=900,
            allowed_tools=m_data.get("allowed_tools", ["nmap", "nuclei", "nikto", "ffuf", "tshark"]),
            rate_limit_delay_ms=self.config_manager.policies_data.get("policies", {}).get("rate_limits", {}).get("default_delay_ms", 50),
            max_concurrent_connections=self.config_manager.policies_data.get("policies", {}).get("rate_limits", {}).get("max_concurrent_connections", 20)
        )

    def list_policies(self) -> List[Policy]:
        """Return all available mode policy profiles."""
        modes_cfg = self.config_manager.policies_data.get("policies", {}).get("modes", {})
        policies = []
        for m_name, m_data in modes_cfg.items():
            policies.append(Policy(
                name=m_name,
                allow_network_scan=m_data.get("allows_port_scan", m_name != "PASSIVE"),
                allow_web_scan=True,
                allow_packet_capture=True,
                allow_bruteforce=m_name in ["AUTHORIZED_PENTEST", "LAB_MODE"],
                allow_destructive=False,
                max_scan_duration=900,
                allowed_tools=m_data.get("allowed_tools", ["nmap", "nuclei", "nikto", "ffuf", "tshark"])
            ))
        return policies

    def validate_action(self, action_category: str, is_destructive: bool = False) -> Tuple[bool, str]:
        """Check if an action category is permitted under the active mode."""
        mode = self.config_manager.get_active_mode()
        policies = self.config_manager.policies_data.get("policies", {}).get("modes", {})
        mode_policy = policies.get(mode, {})

        if is_destructive:
            msg = f"Destructive actions are strictly prohibited under mode '{mode}'."
            audit_log("POLICY_CHECK", "BLOCKED_DESTRUCTIVE", decision="REJECTED", details=msg)
            return False, msg

        if action_category == "port_scan" and not mode_policy.get("allows_port_scan", True):
            return False, f"Port scanning is disabled in {mode} mode. Switch to SAFE_SCAN or ACTIVE_SCAN."

        if action_category == "web_fuzzing" and not mode_policy.get("allows_web_fuzzing", False):
            return False, f"Web fuzzing is disabled in {mode} mode. Switch to ACTIVE_SCAN or LAB_MODE."

        if action_category == "sqli_probes" and not mode_policy.get("allows_sqli_probes", True):
            return False, f"Active SQLi probing is disabled in {mode} mode."

        if action_category == "exploit_validation" and not mode_policy.get("allows_exploit_validation", False):
            return False, f"Controlled exploit validation is disabled in {mode} mode. Switch to AUTHORIZED_PENTEST or LAB_MODE."

        return True, "Action allowed by active security policy."

    def validate_tool_execution(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a specific tool is authorized under current policy rules."""
        active_policy = self.get_active_policy()
        lower_name = tool_name.lower()

        # Check forbidden tools in passive mode
        if active_policy.name == "PASSIVE":
            if lower_name in ["nmap", "nuclei", "nikto", "ffuf", "hydra", "metasploit"]:
                return False, f"Active scanner '{tool_name}' is not permitted in PASSIVE observation mode."

        return True, f"Tool '{tool_name}' allowed under {active_policy.name} policy."
