"""CYBERWOLF Transparent Risk Engine (V2).

Calculates explainable, deterministic security risk scores based on:
- Severity weight (CRITICAL: 1.0, HIGH: 0.8, MEDIUM: 0.5, LOW: 0.2, INFO: 0.05)
- Confidence weight (CONFIRMED: 1.0, HIGH: 0.9, MEDIUM: 0.7, LOW: 0.4)
- Exposure weight (Public IP: 1.0, Subnet: 0.85, Loopback: 0.6)
- Exploitability factor (Known CVE/PoC: 1.0, Active Probe: 0.85, Misconfig: 0.7)
- Asset importance (High criticality: 1.0, Standard: 0.85)

Formula:
  Score = round(10.0 * (severity_w * 0.45 + exploitability_w * 0.25 + exposure_w * 0.15 + confidence_w * 0.15) * asset_criticality, 1)
Range: 0.0 to 10.0
"""

import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from app.database.models import Finding, SeverityLevel, ConfidenceLevel, Asset


class RiskEngine:
    """Calculates transparent, fully explainable risk scores for findings and assets."""

    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 1.0,
        SeverityLevel.HIGH: 0.80,
        SeverityLevel.MEDIUM: 0.50,
        SeverityLevel.LOW: 0.20,
        SeverityLevel.INFO: 0.05
    }

    CONFIDENCE_WEIGHTS = {
        ConfidenceLevel.CONFIRMED: 1.0,
        ConfidenceLevel.HIGH: 0.90,
        ConfidenceLevel.MEDIUM: 0.70,
        ConfidenceLevel.LOW: 0.40
    }

    def score_finding(self, finding: Finding, asset_criticality: float = 1.0) -> Dict[str, Any]:
        """Compute transparent risk score and factors for an individual finding."""
        sev = finding.severity.upper() if finding.severity else "INFO"
        conf = finding.confidence.upper() if finding.confidence else "HIGH"

        severity_w = self.SEVERITY_WEIGHTS.get(sev, 0.05)
        confidence_w = self.CONFIDENCE_WEIGHTS.get(conf, 0.70)

        # Determine network exposure
        exposure_w = self._determine_exposure(finding.host or finding.target)

        # Determine exploitability factor
        exploitability_w = 0.60
        if sev == "INFO":
            exploitability_w = 0.10
        elif finding.cve_ids or (finding.cve and "CVE" in finding.cve):
            exploitability_w = 1.0
        elif finding.category in ["injection", "remote_code_execution"]:
            exploitability_w = 0.95
        elif "open" in (finding.evidence or "").lower() or finding.category == "network_exposure":
            exploitability_w = 0.75

        # Weighted calculation out of 10.0
        raw_score = (
            (severity_w * 0.45) +
            (exploitability_w * 0.25) +
            (exposure_w * 0.15) +
            (confidence_w * 0.15)
        ) * 10.0 * min(max(asset_criticality, 0.5), 1.5)

        score = round(min(max(raw_score, 0.0), 10.0), 1)

        factors = {
            "severity_weight": round(severity_w, 2),
            "confidence_weight": round(confidence_w, 2),
            "exposure_weight": round(exposure_w, 2),
            "exploitability_weight": round(exploitability_w, 2),
            "asset_criticality": round(asset_criticality, 2)
        }

        # Update finding fields
        finding.risk_score = score
        finding.risk_factors = factors

        return {
            "score": score,
            "severity": sev,
            "confidence": conf,
            "factors": factors
        }

    def calculate_finding_risk(self, finding: Finding, asset_criticality: float = 1.0) -> float:
        """Compute and return float risk score (0.0 to 10.0) for a finding."""
        result = self.score_finding(finding, asset_criticality=asset_criticality)
        return float(result.get("score", 0.0))

    def calculate_risk(self, finding: Finding, asset_criticality: float = 1.0) -> Tuple[float, Dict[str, Any]]:
        """Compute and return tuple (score, factors) for a finding."""
        result = self.score_finding(finding, asset_criticality=asset_criticality)
        return float(result.get("score", 0.0)), result.get("factors", {})

    def score_findings_batch(self, findings: List[Finding]) -> List[Finding]:
        """Score an entire list of findings in-place."""
        for f in findings:
            self.score_finding(f)
        return findings

    def calculate_asset_risk(self, findings: List[Finding]) -> Tuple[float, str]:
        """Calculate overall aggregate risk score and risk level for an asset."""
        if not findings:
            return 0.0, "LOW"

        # Risk is driven primarily by highest critical finding plus cumulative factor
        scores = [f.risk_score for f in findings if f.risk_score > 0]
        if not scores:
            for f in findings:
                self.score_finding(f)
            scores = [f.risk_score for f in findings]

        max_score = max(scores) if scores else 0.0
        # Dampened addition for additional findings
        additional = min(sum(s * 0.05 for s in scores) - (max_score * 0.05), 2.0)
        overall_score = round(min(max_score + max(additional, 0.0), 10.0), 1)

        if overall_score >= 8.5:
            risk_level = "CRITICAL"
        elif overall_score >= 6.5:
            risk_level = "HIGH"
        elif overall_score >= 4.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return overall_score, risk_level

    def _determine_exposure(self, host: Optional[str]) -> float:
        """Infer network exposure from host representation."""
        if not host:
            return 0.70
        clean = host.strip().lower()
        if clean in ["localhost", "127.0.0.1", "::1"]:
            return 0.60

        try:
            ip = ipaddress.ip_address(clean.split(":")[0])
            if ip.is_loopback:
                return 0.60
            if ip.is_private:
                return 0.80
            return 1.0  # Public IP
        except ValueError:
            pass

        # Domains / hostnames
        if clean.endswith(".local") or clean.endswith(".internal"):
            return 0.75
        return 0.95


_RISK_ENGINE: Optional[RiskEngine] = None

def get_risk_engine() -> RiskEngine:
    global _RISK_ENGINE
    if _RISK_ENGINE is None:
        _RISK_ENGINE = RiskEngine()
    return _RISK_ENGINE
