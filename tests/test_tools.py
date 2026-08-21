"""Unit tests for Tool Discovery and Subprocess Runner."""

import unittest
from app.tools.detector import get_tool_detector
from app.tools.runner import ToolRunner
from app.tools.adapters.nmap_adapter import NmapAdapter
from app.tools.adapters.nuclei_adapter import NucleiAdapter

class TestTools(unittest.TestCase):
    def test_tool_detector(self):
        detector = get_tool_detector()
        report = detector.get_full_doctor_report()
        self.assertIn("platform", report)
        self.assertIn("dependencies", report)
        self.assertIn("security_tools", report)
        self.assertEqual(len(report["security_tools"]), 15)

    def test_runner_safe_execution(self):
        # Run standard python version command
        code, stdout, stderr = ToolRunner.execute(["python3", "--version"])
        self.assertEqual(code, 0)
        self.assertIn("Python", stdout)

    def test_nmap_parser(self):
        adapter = NmapAdapter()
        mock_output = """
Nmap scan report for 192.168.1.50
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    Apache 2.4.41
3306/tcp open  mysql   MySQL 5.7.33
"""
        parsed = adapter.parse_output(mock_output, 0)
        self.assertTrue(parsed["success"])
        self.assertEqual(len(parsed["hosts"]), 1)
        self.assertEqual(len(parsed["hosts"][0]["ports"]), 3)
        # Port 3306 should generate an exposed service finding
        self.assertTrue(len(parsed["findings"]) >= 1)

    def test_nuclei_parser(self):
        adapter = NucleiAdapter()
        mock_json_line = '{"template-id":"cve-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"http://127.0.0.1:8080"}'
        parsed = adapter.parse_output(mock_json_line, 0)
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertEqual(parsed["findings"][0]["severity"], "CRITICAL")
        self.assertEqual(parsed["findings"][0]["cve"], "CVE-2021-44228")

if __name__ == "__main__":
    unittest.main()
