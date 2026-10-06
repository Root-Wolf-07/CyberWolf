"""Unit tests for Investigation Engine, Observed vs Verified separation, and Intelligence grounding."""

import pytest
from app.database.models import Finding
from app.intelligence.investigation import InvestigationEngine


class TestInvestigationAndIntelligence:
    """Test suite ensuring separation of observed facts, verified behavior, and zero hallucination."""

    def test_observed_vs_verified_distinction(self):
        engine = InvestigationEngine()
        finding = Finding(
            id="CW-INV-001",
            title="Log4j JNDI Lookup Vulnerability",
            severity="CRITICAL",
            target="sec-lab.target.local",
            observed_behavior="Scanner logged DNS query triggered by JNDI string.",
            verified_behavior=None,  # Not verified yet
            cve="CVE-2021-44228",
            cwe="CWE-502"
        )

        report = engine.generate_investigation_report(finding)

        assert report["observed_facts"]["what_was_detected"] == "Scanner logged DNS query triggered by JNDI string."
        # Verified must explicitly state lack of active confirmation
        assert "not independently probe-verified" in report["observed_facts"]["what_was_verified"].lower()
        assert report["security_exploitation"]["limitations"] is not None

    def test_no_invented_cve_or_evidence(self):
        engine = InvestigationEngine()
        finding = Finding(
            id="CW-INV-002",
            title="Generic Custom Service Anomaly",
            severity="LOW",
            target="10.0.0.5",
            evidence=None,
            observed_behavior=None,
            cve=None,
            cwe=None
        )

        report = engine.generate_investigation_report(finding)

        assert report["knowledge_grounding"]["cve"] == "Not identified / None"
        assert report["knowledge_grounding"]["verified_mapping"] is False
        assert "Insufficient evidence" in report["observed_facts"]["evidence"]
        assert report["security_exploitation"]["level"] == "LOW"

    def test_security_exploitation_prerequisites_and_limitations(self):
        engine = InvestigationEngine()
        finding = Finding(
            id="CW-INV-003",
            title="SQL Injection in Admin Search",
            severity="HIGH",
            target="https://target.corp/admin/search",
            url="https://target.corp/admin/search",
            parameter="q",
            exploitability_level="HIGH"
        )

        report = engine.generate_investigation_report(finding)
        sec = report["security_exploitation"]

        assert sec["level"] == "HIGH"
        assert "Network access" in sec["prerequisites"] or "reachability" in sec["prerequisites"]
        assert "Non-destructive" in sec["limitations"]
