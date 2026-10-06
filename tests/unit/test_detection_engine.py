"""Unit tests for CYBERWOLF Normalization, Deduplication, and Correlation."""

import pytest
from app.detection.normalizer import FindingNormalizer
from app.detection.deduplicator import FindingDeduplicator
from app.detection.correlator import FindingCorrelator
from app.database.models import Finding, SeverityLevel, ConfidenceLevel


def test_normalizer_severity_mapping():
    """Verify normalizer standardizes disparate tool severity ratings."""
    norm = FindingNormalizer()
    assert norm.normalize_severity("critical") == SeverityLevel.CRITICAL
    assert norm.normalize_severity("high") == SeverityLevel.HIGH
    assert norm.normalize_severity("medium") == SeverityLevel.MEDIUM
    assert norm.normalize_severity("warn") == SeverityLevel.MEDIUM
    assert norm.normalize_severity("low") == SeverityLevel.LOW
    assert norm.normalize_severity("informational") == SeverityLevel.INFO
    assert norm.normalize_severity("unknown_rating") == SeverityLevel.INFO


def test_deduplicator_provenance_preservation():
    """Verify deduplicator combines duplicate findings while preserving all source tools."""
    dedup = FindingDeduplicator()

    f1 = Finding(
        id="CW-TEST-1",
        target="192.168.1.50",
        title="Apache Outdated Version",
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.MEDIUM,
        port=80,
        protocol="tcp",
        source_tool="Nikto",
        source_tools=["Nikto"],
        evidence="Nikto detected Apache 2.4.41"
    )

    f2 = Finding(
        id="CW-TEST-2",
        target="192.168.1.50",
        title="Apache Outdated Version",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        port=80,
        protocol="tcp",
        source_tool="Nuclei",
        source_tools=["Nuclei"],
        evidence="Nuclei detected outdated Apache"
    )

    merged = dedup.deduplicate([f1, f2])
    assert len(merged) == 1
    m = merged[0]
    # Provenance preserved
    assert "Nikto" in m.source_tools
    assert "Nuclei" in m.source_tools
    # Promoted severity
    assert m.severity == SeverityLevel.HIGH
    # Evidence merged
    assert "Nikto" in m.evidence
    assert "Nuclei" in m.evidence


def test_correlator_service_enrichment():
    """Verify correlator links open port discoveries to vulnerability findings."""
    correlator = FindingCorrelator()

    port_fnd = Finding(
        id="CW-PORT-80",
        target="192.168.1.20",
        title="Open Port: 80/tcp (http)",
        severity=SeverityLevel.INFO,
        category="network",
        port=80,
        service="http",
        source_tool="Nmap"
    )

    vuln_fnd = Finding(
        id="CW-VULN-80",
        target="192.168.1.20",
        title="HTTP Header Missing",
        severity=SeverityLevel.LOW,
        category="web",
        port=80,
        source_tool="Nikto"
    )

    correlated = correlator.correlate([port_fnd, vuln_fnd])
    assert len(correlated) == 2
    # Verify service metadata linked
    v = next(f for f in correlated if f.id == "CW-VULN-80")
    assert v.service == "http"
