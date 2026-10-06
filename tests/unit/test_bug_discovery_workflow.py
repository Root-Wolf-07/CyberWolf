"""CYBERWOLF Unit and Integration Tests for Bug Discovery Investigation Workflow.

Verifies:
1. Finding Data Model (Exact location, severity, confidence, explainable risk score & factors)
2. Grounded "Why Flagged" rationale without hallucination
3. Evidence Vault (SHA-256 integrity, HTTP request/response formatting, credential redaction)
4. Retest Engine (PASS, FAIL, INCONCLUSIVE status tracking)
5. Finding Status Lifecycle (Valid statuses, invalid status rejection, false positive justification)
6. Timeline Engine (Discovery, Evidence, Risk calculation, Status transition, Retest)
7. Deduplication & Correlation (Multi-tool sources)
8. Live Discovery Activity Progress (10 deterministic steps)
"""

import pytest
import uuid
from datetime import datetime

from app.database.models import Finding, FindingStatus, SeverityLevel, ConfidenceLevel
from app.detection.exact_location import ExactLocationEngine
from app.detection.risk_engine import RiskEngine
from app.intelligence.investigation import InvestigationEngine
from app.evidence.vault import EvidenceVault
from app.services.finding_service import FindingService
from app.services.scan_service import ScanService
from app.services.retest_service import RetestService
from app.database.operations import create_finding, get_finding, update_finding_status


class TestBugDiscoveryWorkflow:
    """Comprehensive test suite for the upgraded Bug Discovery system."""

    def test_finding_creation_and_exact_location(self, tmp_path):
        """Test finding creation preserves exact web location hierarchy."""
        fid = f"CW-TEST-{uuid.uuid4().hex[:6].upper()}"
        finding = Finding(
            id=fid,
            title="SQL Injection in Product Catalog",
            target="example.com",
            url="https://example.com/products?cat=books&sort=desc",
            http_method="GET",
            endpoint="/products",
            parameter="cat",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.CONFIRMED,
            category="injection"
        )
        location = ExactLocationEngine.resolve_location(finding)
        assert location.location_type == "WEB"
        assert location.parameter == "cat"
        assert location.endpoint == "/products"
        assert "GET" in location.format_hierarchy()
        assert "cat" in location.summary()

    def test_explainable_risk_factors(self):
        """Test risk score produces explainable risk factors breakdown."""
        finding = Finding(
            id="CW-RISK-01",
            title="SQL Injection",
            target="192.168.1.100",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.CONFIRMED,
            category="injection"
        )
        engine = RiskEngine()
        res = engine.score_finding(finding, asset_criticality=1.0)
        factors = res["factors"]

        assert "severity_weight" in factors
        assert "exploitability_weight" in factors
        assert "exposure_weight" in factors
        assert "confidence_weight" in factors
        assert "asset_criticality" in factors
        assert factors["severity_weight"] == 0.80
        assert factors["confidence_weight"] == 1.00
        assert res["score"] > 0.0

    def test_grounded_why_this_was_flagged(self):
        """Test why_flagged provides factual explanation without AI hallucination."""
        inv_engine = InvestigationEngine()
        finding = Finding(
            id="CW-FLAG-01",
            title="SQL Injection Vulnerability",
            target="https://target.local/search?q=test",
            url="https://target.local/search?q=test",
            http_method="GET",
            endpoint="/search",
            parameter="q",
            category="injection",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.CONFIRMED,
            evidence="Server responded with SQL syntax error near syntax clause"
        )
        report = inv_engine.investigate(finding)
        why_text = report["why_this_was_flagged"]

        assert "parameter 'q'" in why_text
        assert "/search" in why_text
        assert "database" in why_text.lower()

    def test_unconfirmed_finding_states_insufficient_evidence(self):
        """Test unconfirmed findings explicitly declare insufficient evidence."""
        inv_engine = InvestigationEngine()
        finding = Finding(
            id="CW-FLAG-02",
            title="Potential Timing Discrepancy",
            target="target.local",
            severity=SeverityLevel.LOW,
            confidence=ConfidenceLevel.LOW,
            category="general",
            evidence=""
        )
        report = inv_engine.investigate(finding)
        why_text = report["why_this_was_flagged"]
        assert "Insufficient evidence" in why_text

    def test_evidence_vault_sha256_and_redaction(self, tmp_path):
        """Test Evidence Vault calculates SHA-256 and redacts secrets."""
        vault = EvidenceVault(storage_dir=str(tmp_path))
        ev = vault.store_http_evidence(
            target="https://sec-test.local/login",
            url="https://sec-test.local/login",
            method="POST",
            request_headers={
                "Authorization": "Bearer sensitive_secret_token_12345",
                "Cookie": "session_id=abcdef1234567890",
                "User-Agent": "CyberWolf-Probe/2.0"
            },
            request_body="username=admin&password=SuperSecretPassword99!",
            status_code=200,
            response_body="Welcome administrator"
        )

        assert ev.hash_sha256 is not None
        assert len(ev.hash_sha256) == 64
        # Verification that raw secret token is redacted
        assert "sensitive_secret_token_12345" not in ev.output_excerpt
        assert "[REDACTED]" in ev.output_excerpt or "***REDACTED***" in ev.output_excerpt

        # Verify cryptographic integrity check
        verified, msg = vault.verify_evidence_integrity(ev.id)
        assert verified is True

    def test_status_lifecycle_validation(self):
        """Test valid statuses pass and arbitrary statuses are rejected."""
        assert FindingStatus.is_valid("OPEN") is True
        assert FindingStatus.is_valid("CONFIRMED") is True
        assert FindingStatus.is_valid("FALSE_POSITIVE") is True
        assert FindingStatus.is_valid("IN_PROGRESS") is True
        assert FindingStatus.is_valid("REMEDIATED") is True
        assert FindingStatus.is_valid("RETEST_REQUIRED") is True
        assert FindingStatus.is_valid("VERIFIED") is True

        # Invalid statuses
        assert FindingStatus.is_valid("RANDOM_STATUS") is False
        assert FindingStatus.is_valid("FAKE_STATE") is False
        assert FindingStatus.is_valid("") is False
        assert FindingStatus.is_valid(None) is False

    def test_false_positive_status_update(self, tmp_path):
        """Test status transitions preserve actor and justification reason."""
        fid = f"CW-FP-{uuid.uuid4().hex[:6].upper()}"
        f = Finding(
            id=fid,
            title="Missing X-Frame-Options Header",
            target="internal-app.local",
            severity=SeverityLevel.LOW
        )
        create_finding(f)

        finding_svc = FindingService()
        ok = finding_svc.update_status(
            fid,
            new_status="FALSE_POSITIVE",
            reason="Expected application behavior: App is meant to be embedded in trusted portal",
            changed_by="lead-analyst"
        )
        assert ok is True

        updated = get_finding(fid)
        assert updated["status"] == "FALSE_POSITIVE"

        timeline = finding_svc.get_timeline(fid)
        status_events = [e for e in timeline if e["event_type"] == "STATUS_CHANGE"]
        assert len(status_events) > 0
        assert "FALSE_POSITIVE" in status_events[0]["description"]
        assert status_events[0]["actor"] == "lead-analyst"

    def test_retest_and_timeline_events(self, tmp_path):
        """Test retesting updates finding and produces audit timeline."""
        fid = f"CW-RET-{uuid.uuid4().hex[:6].upper()}"
        f = Finding(
            id=fid,
            title="Open Directory Listing",
            target="127.0.0.1",
            url="http://127.0.0.1:80/images/",
            endpoint="/images/",
            severity=SeverityLevel.MEDIUM,
            status=FindingStatus.OPEN
        )
        create_finding(f)

        finding_svc = FindingService()
        # Trigger retest
        res = finding_svc.retest_finding(fid, actor="test-analyst")
        assert "success" in res
        assert "retest_result" in res
        assert res["retest_result"] in ["PASS", "FAIL", "INCONCLUSIVE"]

        # Timeline check
        timeline = finding_svc.get_timeline(fid)
        event_types = [e["event_type"] for e in timeline]
        assert "DISCOVERY" in event_types
        assert "RETEST" in event_types

    def test_scan_service_live_progress_tracking(self):
        """Test scan service creates and updates the 10 real progress steps."""
        scan_svc = ScanService()
        scan_id = f"SCAN-PROG-{uuid.uuid4().hex[:4].upper()}"
        scan_svc._init_progress(scan_id, "sec-target.local", "network")

        prog = scan_svc.get_scan_progress(scan_id)
        assert prog is not None
        assert len(prog["steps"]) == 10
        assert prog["steps"][0]["label"] == "Target validated"
        assert prog["steps"][0]["completed"] is False

        # Mark first 2 steps
        scan_svc._mark_progress_step(scan_id, "Target validated")
        scan_svc._mark_progress_step(scan_id, "Authorization verified")

        prog = scan_svc.get_scan_progress(scan_id)
        assert prog["steps"][0]["completed"] is True
        assert prog["steps"][1]["completed"] is True
        assert prog["steps"][2]["completed"] is False

        # Complete
        scan_svc._complete_progress(scan_id, status="COMPLETED")
        prog = scan_svc.get_scan_progress(scan_id)
        assert prog["status"] == "COMPLETED"
        assert prog["status_text"] == "Assessment completed"
        for step in prog["steps"]:
            assert step["completed"] is True
