"""Integration tests for BDIE pipeline, reports (21 sections), and REST API."""

import json
import pytest
from pathlib import Path
from app.reports.generator import ReportGenerator
from app.database.models import Finding, FindingStatus
from app.database.operations import create_finding
from app.security.authorization import add_authorized_target
from app.services.finding_service import get_finding_service


class TestBdiePipelineAndReports:
    """Test full BDIE reporting and service integration."""

    def test_21_section_report_generation(self, tmp_path):
        target = "sec-lab.report-test.local"
        add_authorized_target(target, scope_name="report-scope")

        fid = "CW-REP-TEST-21"
        finding = Finding(
            id=fid,
            title="Exposed Database Service with Weak Authentication",
            severity="CRITICAL",
            target=target,
            port=3306,
            protocol="tcp",
            service="mysql",
            service_version="MySQL 5.7.33",
            url=None,
            cve="CVE-2021-22946",
            cwe="CWE-287",
            observed_behavior="Unauthenticated handshake returned server banner MySQL 5.7.33",
            verified_behavior="Confirmed port 3306 accepts TCP connections without TLS enforcement",
            potential_impact="Direct database access and data exfiltration",
            exploitability_level="HIGH",
            remediation="Bind MySQL to localhost and enforce TLS with mutual authentication.",
            verification_procedure="Probe port 3306 from external network to ensure connection is refused.",
            status=FindingStatus.CONFIRMED
        )
        create_finding(finding)

        generator = ReportGenerator(output_dir=str(tmp_path / "reports"))
        files = generator.generate_all_formats(target=target, title="BDIE Automated Test Assessment")

        assert "JSON" in files
        assert "CSV" in files
        assert "HTML" in files
        assert "TXT" in files
        assert Path(files["JSON"]).exists()
        assert Path(files["CSV"]).exists()
        assert Path(files["HTML"]).exists()
        assert Path(files["TXT"]).exists()

        # Validate JSON contains all 21 BDIE sections
        with open(files["JSON"], "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "sections" in data
        secs = data["sections"]
        assert "1_executive_summary" in secs
        assert "2_assessment_scope" in secs
        assert "3_authorization_and_scope_validation" in secs
        assert "4_assessment_timeline" in secs
        assert "5_asset_inventory" in secs
        assert "6_attack_surface" in secs
        assert "7_risk_summary" in secs
        assert "8_vulnerability_summary" in secs
        assert "9_detailed_findings" in secs
        assert "10_exact_locations" in secs
        assert "11_evidence" in secs
        assert "12_observed_behavior" in secs
        assert "13_verified_behavior" in secs
        assert "14_security_impact" in secs
        assert "15_exploitability_assessment" in secs
        assert "16_cve_cwe_owasp_mapping" in secs
        assert "17_remediation" in secs
        assert "18_verification_and_retesting" in secs
        assert "19_tool_execution_history" in secs
        assert "20_evidence_integrity" in secs
        assert "21_final_risk_summary" in secs

        # Validate Exact Location details in JSON
        locs = secs["10_exact_locations"]
        assert len(locs) >= 1
        test_loc = next(l for l in locs if l["finding_id"] == fid)
        assert test_loc["port"] == 3306
        assert test_loc["service"] == "mysql"
        assert test_loc["service_version"] == "MySQL 5.7.33"

        # Validate CSV contains BDIE headers
        with open(files["CSV"], "r", encoding="utf-8") as f:
            csv_content = f.read()
        assert "Exact Location" in csv_content
        assert "Observed Behavior" in csv_content
        assert "Verified Behavior" in csv_content
        assert "Evidence SHA-256" in csv_content
        assert "Retest Result" in csv_content

        # Validate HTML contains exact location and verified distinction
        with open(files["HTML"], "r", encoding="utf-8") as f:
            html_content = f.read()
        assert "EXACT AFFECTED LOCATION" in html_content
        assert "OBSERVED BEHAVIOR" in html_content
        assert "VERIFIED BEHAVIOR" in html_content
        assert "Evidence Integrity & Cryptographic Chain of Custody" in html_content

    def test_finding_service_detail_and_search(self):
        svc = get_finding_service()
        fid = "CW-SRV-TEST-001"
        finding = Finding(
            id=fid,
            title="API Token Leak in Diagnostic Endpoint",
            severity="HIGH",
            target="sec-api.internal",
            url="https://sec-api.internal/debug/vars",
            endpoint="/debug/vars",
            status=FindingStatus.NEW
        )
        create_finding(finding)

        detail = svc.get_finding_detail(fid)
        assert detail is not None
        assert detail["finding"]["id"] == fid
        assert "exact_location" in detail
        assert "investigation" in detail

        # Test search
        results = svc.search_findings(query="Diagnostic Endpoint")
        assert any(r["id"] == fid for r in results)
