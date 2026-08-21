"""CYBERWOLF DDoS & Traffic Anomaly Detection Subsystem."""

import time
from typing import Dict, Any, Optional
from datetime import datetime
from app.monitors.traffic_monitor import TrafficMonitor
from app.core.logger import get_logger, audit_log

logger = get_logger()

class DDoSDetector:
    """Defensive telemetry monitor evaluating traffic rate spikes and DoS conditions."""
    
    def __init__(self):
        self.traffic_monitor = TrafficMonitor()
        self.baseline_rps = 15
        self.baseline_pps = 50
        self.baseline_bandwidth_mbps = 5.0
        self.baseline_connections = 120

    def evaluate_live_traffic(self, duration_sec: int = 5) -> Dict[str, Any]:
        """Perform defensive telemetry analysis to detect traffic anomalies."""
        snapshot = self.traffic_monitor.capture_snapshot(duration_sec=duration_sec)
        
        pps = snapshot.get("packets_per_second", 0)
        bytes_total = snapshot.get("total_bytes", 0)
        mbps = round((bytes_total * 8) / (max(duration_sec, 1) * 1_000_000), 2)
        rps = round(pps * 0.4, 1) # Estimated request rate
        connections = int(pps * 2.5)

        anomaly_score = snapshot.get("anomaly_score", 0)
        
        # Calculate deviation factors
        if mbps > (self.baseline_bandwidth_mbps * 4):
            anomaly_score += 45
        elif mbps > (self.baseline_bandwidth_mbps * 2):
            anomaly_score += 20

        if pps > (self.baseline_pps * 3):
            anomaly_score += 35

        score = min(max(anomaly_score, 0), 100)

        if score >= 75:
            status = "HIGH TRAFFIC ANOMALY"
            possible_cause = "Traffic surge / scanning / DoS-like behavior"
            action = "Investigate source distribution, upstream rate limits, and service logs."
        elif score >= 40:
            status = "ELEVATED TRAFFIC / ANOMALY"
            possible_cause = "Moderate traffic burst or background sync activity"
            action = "Monitor endpoint telemetry and verify active clients."
        else:
            status = "NORMAL TRAFFIC"
            possible_cause = "Standard operational baseline"
            action = "No defensive intervention required."

        report = {
            "timestamp": datetime.now().isoformat(),
            "traffic_mbps": mbps,
            "normal_avg_mbps": self.baseline_bandwidth_mbps,
            "pps": pps,
            "normal_avg_pps": self.baseline_pps,
            "rps": rps,
            "normal_avg_rps": self.baseline_rps,
            "connections": connections,
            "normal_avg_connections": self.baseline_connections,
            "anomaly_score": score,
            "status": status,
            "possible_cause": possible_cause,
            "action": action,
            "telemetry_details": snapshot
        }

        audit_log("DDOS_MONITOR", "EVALUATE", decision=status, details=f"Score: {score}/100")
        return report
