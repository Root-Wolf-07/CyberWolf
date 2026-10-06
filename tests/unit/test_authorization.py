"""Unit tests for CYBERWOLF Authorization & Scope Enforcement."""

import pytest
from app.security.authorization import TargetAuthorizer, add_authorized_target
from app.core.exceptions import AuthorizationError


def test_preconfigured_loopback_authorized():
    """Verify localhost loopback is authorized by default."""
    auth = TargetAuthorizer()
    ok, basis = auth.is_authorized("127.0.0.1")
    assert ok
    assert basis in ["CONFIG_SCOPE", "OWNER_DECLARED", "EXPLICIT_ENROLLED"]


def test_subnet_membership_authorized():
    """Verify target within configured lab subnet is recognized."""
    auth = TargetAuthorizer()
    ok, basis = auth.is_authorized("192.168.1.55")
    assert ok


def test_arbitrary_external_target_rejected():
    """Verify external unauthorized target is blocked with actionable guidance."""
    auth = TargetAuthorizer()
    ok, basis = auth.is_authorized("203.0.113.199")
    assert not ok
    assert basis == "REJECTED_UNAUTHORIZED"

    # Verify actionable guidance text
    err_text = auth.get_rejection_guidance("203.0.113.199")
    assert "Target rejected" in err_text
    assert "Action:" in err_text


def test_dynamic_target_enrollment():
    """Verify runtime enrollment allows scanning previously unauthorized target."""
    target = "198.51.100.77"
    auth = TargetAuthorizer()
    ok, _ = auth.is_authorized(target)
    assert not ok

    try:
        # Enroll
        add_authorized_target(target, scope_name="unit-test-lab")

        # Re-check
        ok_now, basis = auth.is_authorized(target)
        assert ok_now
        assert basis == "EXPLICIT_ENROLLED"
    finally:
        # Clean up dynamic scope from memory and file so tests remain idempotent
        scopes = auth.config_manager.targets_data.get("scopes", [])
        auth.config_manager.targets_data["scopes"] = [s for s in scopes if s.get("id") != "unit-test-lab"]
        targets_file = auth.config_manager.base_dir / "config" / "targets.yaml"
        if targets_file.exists():
            import yaml
            with open(targets_file, "w", encoding="utf-8") as f:
                yaml.dump(auth.config_manager.targets_data, f, default_flow_style=False)
