"""Unit tests for Network, Web, SQLi, and Traffic Scanners."""

import unittest
from app.scanners.network_scanner import NetworkScanner
from app.scanners.sqli_scanner import SQLiScanner
from app.monitors.traffic_monitor import TrafficMonitor
from app.monitors.ddos_detector import DDoSDetector

class TestScannersAndMonitors(unittest.TestCase):
    def test_native_network_scanner(self):
        scanner = NetworkScanner()
        # Scan loopback on specific test ports
        res = scanner.scan("127.0.0.1", port_spec="80,443,8080")
        self.assertTrue(res["success"])
        self.assertEqual(len(res["hosts"]), 1)
        self.assertEqual(res["hosts"][0]["ip"], "127.0.0.1")

    def test_traffic_monitor(self):
        monitor = TrafficMonitor()
        snapshot = monitor.capture_snapshot(duration_sec=1, packet_limit=20)
        self.assertIn("packet_count", snapshot)
        self.assertIn("anomaly_score", snapshot)
        self.assertGreaterEqual(snapshot["anomaly_score"], 0)

    def test_ddos_detector(self):
        detector = DDoSDetector()
        report = detector.evaluate_live_traffic(duration_sec=1)
        self.assertIn("anomaly_score", report)
        self.assertIn("status", report)
        self.assertIn("action", report)

if __name__ == "__main__":
    unittest.main()
