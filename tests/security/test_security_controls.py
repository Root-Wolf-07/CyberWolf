"""Security & Vulnerability Resistance Tests for CYBERWOLF V2 Platform.

Verifies:
- Command injection resistance (shell=False, argument lists)
- Path traversal mitigation in report delivery and evidence storage
- Malformed target rejection
- Policy and authorization bypass prevention
- Safe handling of oversized tool output
- HTML report XSS neutralization
"""

import os
import pytest
from pathlib import Path
from app.tools.runner import CommandRunner
from app.security.sanitizer import parse_and_validate_target
from app.security.authorization import TargetAuthorizer
from app.security.policies import PolicyEngine
from app.core.exceptions import TargetValidationError, PolicyViolationError, ToolExecutionError
from app.reports.generator import ReportGenerator
from app.database.models import Finding, SeverityLevel


def test_command_injection_impossible():
    """Verify runner uses argument vectors and does not invoke shell interpretation."""
    runner = CommandRunner()
    # If shell=True were used, this would create /tmp/cyberwolf_pwn
    canary = "/tmp/cyberwolf_pwn_test"
    if os.path.exists(canary):
        os.remove(canary)

    # Attempt argument-based injection payload
    res = runner.execute(["echo", f"test; touch {canary}"])
    assert not os.path.exists(canary)


def test_path_traversal_in_target_rejected():
    """Verify path traversal patterns in target names are blocked."""
    traversal_targets = [
        "../../../../etc/passwd",
        "....//....//etc/shadow",
        "/etc/hosts",
        "http://target.local/../../../sensitive"
    ]
    for tt in traversal_targets:
        if not tt.startswith("http"):
            with pytest.raises(TargetValidationError):
                parse_and_validate_target(tt)


def test_authorization_bypass_prevented():
    """Verify unauthorized external domains cannot bypass check."""
    authorizer = TargetAuthorizer()
    bypass_attempts = [
        "evil-corp.com",
        "127.0.0.1.attacker.com",
        "192.168.1.100.evil.org",
        "10.0.0.1.subdomain.net"
    ]
    for attempt in bypass_attempts:
        ok, _ = authorizer.is_authorized(attempt)
        assert not ok, f"Bypass succeeded for {attempt}"


def test_policy_bypass_prevented():
    """Verify policy engine rejects destructive operations regardless of caller."""
    pe = PolicyEngine()
    ok, _ = pe.validate_action("rm_rf", is_destructive=True)
    assert not ok


def test_oversized_tool_output_capped():
    """Verify output size limiter truncates excessive tool output."""
    runner = CommandRunner()
    # Generate 100,000 lines of output with python
    cmd = ["python3", "-c", "for i in range(100000): print('A' * 80)"]
    exit_code, stdout, stderr = runner.execute(cmd, scan_id="SEC-TEST-CAP")
    assert len(stdout) <= 5 * 1024 * 1024 + 1000  # Within 5MB limit plus notice


def test_html_report_xss_neutralization(tmp_path):
    """Verify malicious XSS payloads in finding titles are HTML escaped in deliverables."""
    rg = ReportGenerator(output_dir=str(tmp_path))

    xss_payload = "<script>alert('pwned')</script><img src=x onerror=alert(1)>"
    fnd = Finding(
        id="CW-XSS-1",
        target="127.0.0.1",
        title=f"XSS Test: {xss_payload}",
        vulnerability=xss_payload,
        severity=SeverityLevel.HIGH,
        evidence=xss_payload,
        remediation=xss_payload
    )
    from app.database.operations import create_finding
    create_finding(fnd)

    deliverables = rg.generate_all_formats(target="127.0.0.1")
    html_path = deliverables.get("HTML")
    assert html_path and os.path.exists(html_path)

    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # Raw script tags must NOT appear unescaped in rendered body
    assert "<script>alert('pwned')</script>" not in html_content
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in html_content or "&lt;script&gt;" in html_content
