"""Unit tests for CYBERWOLF Central Policy Engine."""

import pytest
from app.security.policies import PolicyEngine
from app.database.models import Policy


def test_active_policy_properties():
    """Verify default active policy properties."""
    pe = PolicyEngine()
    policy = pe.get_active_policy()
    assert isinstance(policy, Policy)
    assert policy.allow_network_scan is True
    assert policy.allow_destructive is False
    assert policy.max_scan_duration > 0
    assert "nmap" in policy.allowed_tools


def test_destructive_action_strictly_blocked():
    """Verify destructive actions are blocked across modes."""
    pe = PolicyEngine()
    ok, reason = pe.validate_action("exploit_validation", is_destructive=True)
    assert not ok
    assert "strictly prohibited" in reason


def test_list_all_policy_profiles():
    """Verify listing all configured security policy modes."""
    pe = PolicyEngine()
    all_policies = pe.list_policies()
    assert len(all_policies) >= 3
    names = [p.name for p in all_policies]
    assert "PASSIVE" in names
    assert "SAFE_SCAN" in names
    assert "LAB_MODE" in names


def test_tool_allowlisting():
    """Verify tool authorization check."""
    pe = PolicyEngine()
    ok, _ = pe.validate_tool_execution("nmap")
    assert ok
