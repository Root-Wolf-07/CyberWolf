"""Unit tests for Report Generator."""

import os
import unittest
from app.reports.generator import ReportGenerator, REPORT_DISCLAIMER
from app.database.operations import create_finding
from app.database.models import Finding

class TestReports(unittest.TestCase):
    def setUp(self):
        self.generator = ReportGenerator()
        # Ensure at least one finding exists
        f = Finding(
            id="CW-REP-TEST-0001",
            target="test.local",
            vulnerability="Missing Security Headers",
            severity="MEDIUM",
            evidence="No HSTS header present",
            confidence="HIGH",
            source_tool="Web Engine",
            remediation="Add Strict-Transport-Security"
        )
        create_finding(f)

    def test_multi_format_generation(self):
        files = self.generator.generate_all_formats("test.local", title="Unit Test Assessment")
        self.assertIn("JSON", files)
        self.assertIn("TXT", files)
        self.assertIn("HTML", files)
        self.assertIn("CSV", files)

        for fmt, path in files.items():
            self.assertTrue(os.path.exists(path))
            self.assertGreater(os.path.getsize(path), 0)

if __name__ == "__main__":
    unittest.main()
