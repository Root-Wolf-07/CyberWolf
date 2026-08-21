"""Unit tests for Authorization Engine and SQLite Database Layer."""

import os
import unittest
from app.security.authorization import AuthorizationEngine
from app.security.policies import PolicyEngine
from app.database.db_manager import DatabaseManager, get_db
from app.database.models import Finding
from app.database.operations import (
    create_scan, complete_scan, upsert_host, upsert_port,
    create_finding, get_all_findings, get_findings_summary,
    get_database_status, search_database, export_database_json
)

class TestAuthorizationAndPolicies(unittest.TestCase):
    def setUp(self):
        self.auth = AuthorizationEngine()
        self.policy = PolicyEngine()

    def test_scope_checks(self):
        # Localhost should match local-loopback scope
        auth_ok, msg, scope = self.auth.check_target_scope("127.0.0.1")
        self.assertTrue(auth_ok)
        self.assertIsNotNone(scope)

        # Excluded target
        excl_ok, excl_msg, _ = self.auth.check_target_scope("8.8.8.8")
        self.assertFalse(excl_ok)
        self.assertIn("explicit exclusion", excl_msg)

    def test_policy_validation(self):
        # Destructive action check
        ok, msg = self.policy.validate_action("exploit", is_destructive=True)
        self.assertFalse(ok)

class TestDatabase(unittest.TestCase):
    def test_db_crud(self):
        db = get_db()
        # Create scan
        scan_id = create_scan("test_scan", "127.0.0.1")
        self.assertTrue(scan_id.startswith("SCAN-"))

        # Upsert Host and Port
        host_id = upsert_host("127.0.0.1", hostname="localhost", os_name="macOS")
        self.assertIsInstance(host_id, int)
        port_id = upsert_port(host_id, 8080, "tcp", "open", "http-alt")
        self.assertIsInstance(port_id, int)

        # Create finding
        finding = Finding(
            id="CW-TEST-0001",
            target="127.0.0.1",
            vulnerability="Test Exposure",
            severity="HIGH",
            evidence="Test port 8080 open",
            confidence="HIGH",
            source_tool="Unit Test",
            remediation="Close port"
        )
        create_finding(finding)

        # Fetch findings
        findings = get_all_findings(target="127.0.0.1")
        self.assertTrue(any(f["id"] == "CW-TEST-0001" for f in findings))

        # Check summary
        summary = get_findings_summary()
        self.assertGreaterEqual(summary["TOTAL"], 1)

        # Search database
        search_res = search_database("Exposure")
        self.assertTrue(len(search_res["findings"]) >= 1)

        # Export database
        export_data = export_database_json()
        self.assertIn("findings", export_data)
        self.assertIn("hosts", export_data)

if __name__ == "__main__":
    unittest.main()
