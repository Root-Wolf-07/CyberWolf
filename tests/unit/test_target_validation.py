"""Unit tests for CYBERWOLF Target Validation & Parsing Engine."""

import pytest
from app.security.sanitizer import parse_and_validate_target, TargetType
from app.core.exceptions import TargetValidationError


def test_valid_ipv4():
    """Verify standard IPv4 address validation."""
    res = parse_and_validate_target("192.168.1.100")
    assert res.is_valid
    assert res.target_type == TargetType.IPV4
    assert res.clean_target == "192.168.1.100"
    assert res.ip_address == "192.168.1.100"


def test_valid_ipv6():
    """Verify standard IPv6 address validation."""
    res = parse_and_validate_target("::1")
    assert res.is_valid
    assert res.target_type == TargetType.IPV6
    assert res.clean_target == "::1"


def test_valid_hostname():
    """Verify clean hostname parsing."""
    res = parse_and_validate_target("sec-lab.target.local")
    assert res.is_valid
    assert res.target_type == TargetType.HOSTNAME
    assert res.hostname == "sec-lab.target.local"


def test_valid_url():
    """Verify HTTP and HTTPS URL parsing."""
    res = parse_and_validate_target("http://192.168.1.50:8080/login?user=admin")
    assert res.is_valid
    assert res.target_type == TargetType.URL
    assert res.port == 8080
    assert res.clean_target == "http://192.168.1.50:8080/login?user=admin"


def test_valid_host_port():
    """Verify host:port parsing."""
    res = parse_and_validate_target("10.0.0.1:443")
    assert res.is_valid
    assert res.port == 443
    assert res.clean_target == "10.0.0.1:443"


def test_valid_cidr():
    """Verify CIDR subnet validation."""
    res = parse_and_validate_target("192.168.10.0/24")
    assert res.is_valid
    assert res.target_type == TargetType.CIDR
    assert res.clean_target == "192.168.10.0/24"


def test_reject_dangerous_command_injection_characters():
    """Ensure shell metacharacters raise TargetValidationError."""
    dangerous = [
        "192.168.1.1; cat /etc/passwd",
        "127.0.0.1 && whoami",
        "test.com | ls -la",
        "10.0.0.1 `id`",
        "$(whoami).attacker.com",
        "target.local\n127.0.0.1"
    ]
    for d in dangerous:
        with pytest.raises(TargetValidationError):
            parse_and_validate_target(d)


def test_reject_excessively_broad_cidr():
    """Ensure /0 to /7 overly broad CIDR blocks are rejected for safety."""
    with pytest.raises(TargetValidationError):
        parse_and_validate_target("0.0.0.0/0")

    with pytest.raises(TargetValidationError):
        parse_and_validate_target("10.0.0.0/6")


def test_reject_unsupported_url_schemes():
    """Ensure non-HTTP protocols (e.g. file://, gopher://) are rejected."""
    with pytest.raises(TargetValidationError):
        parse_and_validate_target("file:///etc/passwd")

    with pytest.raises(TargetValidationError):
        parse_and_validate_target("gopher://127.0.0.1:70")
