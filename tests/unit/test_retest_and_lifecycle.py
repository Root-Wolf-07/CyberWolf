"""Unit tests for BDIE Finding Lifecycle & Retesting Engine."""

import pytest
from unittest.mock import patch, MagicMock
from app.database.models import Finding, FindingStatus, RetestResult
from app.database.operations import (
    create_finding, get_finding, update_finding_status,
    get_finding_status_history, get_finding_retests
)
from app.services.retest_service import RetestService
from app.security.authorization import add_authorized_target
from app.core.exceptions import AuthorizationError


class TestRetestAndLifecycle:
    """Test suite for lifecycle transitions and authorized verification probes."""

    def test_status_lifecycle_transitions(self):
        fid = "CW-LIFE-TEST-001"
        finding = Finding(
            id=fid,
            title="Exposed Test Admin Panel",
            severity="HIGH",
            target="127.0.0.1",
            status=FindingStatus.NEW
        )
        create_finding(finding)

        # Transition 1: NEW -> TRIAGED
        ok = update_finding_status(fid, FindingStatus.TRIAGED, reason="Triage verified legitimate exposure", changed_by="SecLead")
        assert ok is True
        f = get_finding(fid)
        assert f["status"] == FindingStatus.TRIAGED

        # Transition 2: TRIAGED -> CONFIRMED
        ok = update_finding_status(fid, FindingStatus.CONFIRMED, verified=True, reason="Validated on staging host", changed_by="Pentester")
        assert ok is True
        f = get_finding(fid)
        assert f["status"] == FindingStatus.CONFIRMED

        # Transition 3: CONFIRMED -> REMEDIATION_REQUIRED
        ok = update_finding_status(fid, FindingStatus.REMEDIATION_REQUIRED, reason="Assigned ticket SEC-101", changed_by="Triage")
        assert ok is True
        f = get_finding(fid)
        assert f["status"] == FindingStatus.REMEDIATION_REQUIRED

        # Audit History Check
        history = get_finding_status_history(fid)
        assert len(history) >= 3
        assert history[-1]["new_status"] == FindingStatus.REMEDIATION_REQUIRED

    def test_retest_unauthorized_target_rejected(self):
        fid = "CW-UNAUTH-001"
        finding = Finding(
            id=fid,
            title="Unauthorized Scope Test",
            severity="CRITICAL",
            target="unauthorized-external-host.corp",
            status=FindingStatus.CONFIRMED
        )
        create_finding(finding)

        service = RetestService()
        with pytest.raises(AuthorizationError):
            service.retest_finding(fid)

    def test_retest_pass_resolves_finding(self):
        target = "127.0.0.1"
        add_authorized_target(target, scope_name="unit-tests")

        fid = "CW-RETEST-PASS-001"
        finding = Finding(
            id=fid,
            title="Remediated Insecure Header",
            severity="LOW",
            target=target,
            url="http://127.0.0.1/remediated-endpoint",
            status=FindingStatus.CONFIRMED
        )
        create_finding(finding)

        service = RetestService()
        # Mock probe returning PASS
        with patch.object(service, "_probe_target", return_value=(RetestResult.PASS, "Endpoint returned secure state", "EVID-TEST-PASS")):
            result = service.retest_finding(fid)

        assert result["success"] is True
        assert result["retest_result"] == RetestResult.PASS
        assert result["new_status"] == FindingStatus.RESOLVED

        # Check DB updated
        f_db = get_finding(fid)
        assert f_db["status"] == FindingStatus.RESOLVED

        retests = get_finding_retests(fid)
        assert len(retests) >= 1
        assert retests[-1]["result"] == RetestResult.PASS

    def test_retest_fail_requires_remediation(self):
        target = "127.0.0.1"
        add_authorized_target(target, scope_name="unit-tests")

        fid = "CW-RETEST-FAIL-001"
        finding = Finding(
            id=fid,
            title="Unfixed SQL Injection",
            severity="HIGH",
            target=target,
            url="http://127.0.0.1/login",
            status=FindingStatus.RETEST_PENDING
        )
        create_finding(finding)

        service = RetestService()
        # Mock probe returning FAIL
        with patch.object(service, "_probe_target", return_value=(RetestResult.FAIL, "Vulnerability signature still actively triggers error", "EVID-TEST-FAIL")):
            result = service.retest_finding(fid)

        assert result["success"] is True
        assert result["retest_result"] == RetestResult.FAIL
        assert result["new_status"] == FindingStatus.REMEDIATION_REQUIRED

        f_db = get_finding(fid)
        assert f_db["status"] == FindingStatus.REMEDIATION_REQUIRED
