"""Unit tests for CYBERWOLF Config and Input Sanitizer."""

import unittest
from app.core.config import ConfigManager, get_config
from app.security.sanitizer import sanitize_target, sanitize_ports, sanitize_file_path
from app.core.exceptions import ValidationError

class TestConfig(unittest.TestCase):
    def test_config_loader(self):
        cfg = get_config()
        self.assertEqual(cfg.get("app", {}).get("name"), "CYBERWOLF")
        self.assertIn("SAFE_SCAN", cfg.get("security", {}).get("allowed_modes", []))
        self.assertIsNotNone(cfg.get_db_path())

    def test_set_active_mode(self):
        cfg = get_config()
        self.assertTrue(cfg.set_active_mode("ACTIVE_SCAN"))
        self.assertEqual(cfg.get_active_mode(), "ACTIVE_SCAN")
        self.assertFalse(cfg.set_active_mode("INVALID_MODE"))

class TestSanitizer(unittest.TestCase):
    def test_valid_targets(self):
        self.assertEqual(sanitize_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(sanitize_target("192.168.1.0/24"), "192.168.1.0/24")
        self.assertEqual(sanitize_target("localhost"), "localhost")
        self.assertEqual(sanitize_target("https://example.local/api"), "https://example.local/api")

    def test_dangerous_targets(self):
        with self.assertRaises(ValidationError):
            sanitize_target("127.0.0.1; rm -rf /")
        with self.assertRaises(ValidationError):
            sanitize_target("127.0.0.1 | cat /etc/passwd")
        with self.assertRaises(ValidationError):
            sanitize_target("127.0.0.1`id`")

    def test_port_sanitization(self):
        self.assertEqual(sanitize_ports("80,443,8080"), "80,443,8080")
        self.assertEqual(sanitize_ports("1-1000"), "1-1000")
        with self.assertRaises(ValidationError):
            sanitize_ports("80; touch hack")

    def test_file_path_sanitization(self):
        self.assertEqual(sanitize_file_path("report.html"), "report.html")
        with self.assertRaises(ValidationError):
            sanitize_file_path("../../../etc/shadow")

if __name__ == "__main__":
    unittest.main()
