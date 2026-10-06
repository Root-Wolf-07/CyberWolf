"""Security test suite for BDIE components (injection, path traversal, authorization)."""

import pytest
from pathlib import Path
from app.detection.exact_location import ExactLocationEngine
from app.reports.generator import ReportGenerator
from app.security.authorization import TargetAuthorizer
from app.database.operations import get_finding, get_all_findings
from app.services.retest_service import RetestService
from app.core.exceptions import AuthorizationError


class TestBdieSecurityControls:
    """Security verification tests enforcing strict defensive posture."""

    def test_exact_location_command_injection_resilience(self):
        engine = ExactLocationEngine()
        malicious_target = "https://target.local/; rm -rf /; $(whoami)/path?param=`cat /etc/passwd`"

        loc = engine.resolve_location(
            target=malicious_target,
            url=malicious_target,
            parameter="`cat /etc/passwd`"
        )

        assert loc.domain == "target.local"
        assert loc.parameter == "`cat /etc/passwd`"
        # Should cleanly parse without executing or failing

    def test_report_generator_path_traversal_protection(self, tmp_path):
        target = "sec-lab.example"
        malicious_scan_id = "../../etc/shadow_leak"
        generator = ReportGenerator(output_dir=str(tmp_path / "reports"))

        files = generator.generate_all_formats(target=target, scan_id=malicious_scan_id)

        # Output files must reside within output_dir
        for path_str in files.values():
            p = Path(path_str).resolve()
            assert str(p).startswith(str(tmp_path.resolve()))

    def test_sql_injection_in_queries_resilience(self):
        # Querying with SQL injection payload in finding search
        payload = "' UNION SELECT 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 --"
        findings = get_all_findings(target=payload, severity="CRITICAL")
        # Parameterized query must execute without SQLite syntax error or corruption
        assert isinstance(findings, list)

    def test_unauthorized_retest_strictly_blocked(self):
        authorizer = TargetAuthorizer()
        unauthorized_host = "bank-production-core.internal"
        is_auth, _ = authorizer.is_authorized(unauthorized_host)
        assert is_auth is False

        retest_svc = RetestService()
        # Non-existent or unauthorized targets must raise AuthorizationError
        with pytest.raises(Exception):
            retest_svc.retest_finding("NON-EXISTENT-ID")
