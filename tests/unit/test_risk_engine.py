"""Unit tests for CYBERWOLF Transparent Risk Engine."""

import pytest
from app.detection.risk_engine import RiskEngine
from app.database.models import Finding, SeverityLevel, ConfidenceLevel


def test_risk_scoring_bounds_and_determinism():
    """Verify calculated risk scores are deterministic and within 0.0 - 10.0 range."""
    re = RiskEngine()

    critical_finding = Finding(
        id="CW-RISK-1",
        target="192.168.1.100",
        title="Remote Code Execution",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.CONFIRMED,
        cve="CVE-2021-44228"
    )

    score = re.calculate_finding_risk(critical_finding)
    assert 0.0 <= score <= 10.0
    assert score >= 7.0  # Critical + Confirmed with CVE must score high

    # Repeat check for determinism
    score2 = re.calculate_finding_risk(critical_finding)
    assert score == score2


def test_info_finding_low_risk():
    """Verify informational findings score low risk."""
    re = RiskEngine()

    info_finding = Finding(
        id="CW-RISK-2",
        target="127.0.0.1",
        title="Open Port 80",
        severity=SeverityLevel.INFO,
        confidence=ConfidenceLevel.HIGH
    )

    score = re.calculate_finding_risk(info_finding)
    assert score <= 3.0


def test_asset_risk_aggregation():
    """Verify asset risk calculation produces score and categorical risk level."""
    re = RiskEngine()

    findings = [
        Finding(id="1", target="10.0.0.1", title="A", severity=SeverityLevel.HIGH, confidence=ConfidenceLevel.HIGH),
        Finding(id="2", target="10.0.0.1", title="B", severity=SeverityLevel.MEDIUM, confidence=ConfidenceLevel.MEDIUM),
    ]

    score, level = re.calculate_asset_risk(findings)
    assert 0.0 <= score <= 10.0
    assert level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
