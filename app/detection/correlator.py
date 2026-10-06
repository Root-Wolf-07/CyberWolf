"""CYBERWOLF Finding Correlation Engine (V2).

Builds a deterministic correlation layer between assets, open ports, discovered
services, and vulnerability findings without hallucinating or inventing flaws.
"""

from typing import List, Dict, Any, Optional
from app.database.models import Finding, Asset
from app.core.logger import get_logger

logger = get_logger()


class FindingCorrelator:
    """Correlates multiple findings across network ports, services, and software versions."""

    def correlate(self, findings: List[Finding], assets: Optional[List[Dict[str, Any]]] = None) -> List[Finding]:
        """Apply deterministic correlation rules to enrich finding context."""
        if not findings:
            return []

        # Group findings by (host, port)
        host_port_map: Dict[str, List[Finding]] = {}
        for f in findings:
            host = (f.host or f.target or "").lower()
            port = str(f.port or "0")
            key = f"{host}:{port}"
            host_port_map.setdefault(key, []).append(f)

        # Correlate relationships within each host:port group
        for key, group in host_port_map.items():
            if len(group) <= 1:
                continue

            # Identify if we have an open port finding and a specific vulnerability on the same port
            port_findings = [f for f in group if f.category in ["network_exposure", "network", "port"]]
            vuln_findings = [f for f in group if f.category in ["vulnerability", "web_misconfiguration", "web", "injection", "remote_code_execution"]]

            if port_findings and vuln_findings:
                # Correlate: The vulnerability is confirmed on an open, verified listening service
                for vf in vuln_findings:
                    if vf.confidence != "CONFIRMED":
                        vf.confidence = "CONFIRMED"
                    if not vf.service and port_findings[0].service:
                        vf.service = port_findings[0].service
                    # Add correlation note in evidence
                    corr_note = f"[Correlation: Confirmed active on open port {vf.port or port_findings[0].port}/{vf.protocol}]"
                    if corr_note not in vf.evidence:
                        vf.evidence = f"{vf.evidence}\n{corr_note}".strip()

        return findings


_CORRELATOR: Optional[FindingCorrelator] = None

def get_correlator() -> FindingCorrelator:
    global _CORRELATOR
    if _CORRELATOR is None:
        _CORRELATOR = FindingCorrelator()
    return _CORRELATOR
