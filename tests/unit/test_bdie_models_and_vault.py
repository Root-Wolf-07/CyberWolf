"""Unit tests for BDIE Domain Models & Cryptographic Evidence Vault."""

import hashlib
import json
import pytest
from app.database.models import (
    Finding, FindingStatus, Evidence, EvidenceType, RetestResult,
    ExploitabilityLevel, FindingRetest, FindingStatusHistory
)
from app.evidence.vault import EvidenceVault


class TestBdieModelsAndVault:
    """Test suite for BDIE findings, evidence models, and SHA-256 integrity."""

    def test_finding_model_defaults_and_serialization(self):
        finding = Finding(
            id="BUG-2026-0001",
            title="SQL Injection in Login Endpoint",
            status=FindingStatus.NEW,
            confidence="MEDIUM",
            severity="CRITICAL",
            target="sec-lab.target.local",
            url="https://sec-lab.target.local/login",
            http_method="POST",
            endpoint="/login",
            parameter="username",
            observed_behavior="Server returned syntax error near SELECT * FROM users",
            verified_behavior="Probe confirmed error-based boolean difference",
            exploitability_level=ExploitabilityLevel.HIGH,
            remediation="Use parameterized queries with prepared statements.",
            verification_procedure="Re-test /login with safe single quote probes."
        )

        assert finding.status == FindingStatus.NEW
        assert finding.confidence == "MEDIUM"
        assert finding.severity == "CRITICAL"
        assert finding.url == "https://sec-lab.target.local/login"
        assert finding.http_method == "POST"
        assert finding.parameter == "username"
        assert finding.exploitability_level == "HIGH"

        f_dict = finding.to_dict()
        assert f_dict["id"] == "BUG-2026-0001"
        assert f_dict["parameter"] == "username"
        assert f_dict["status"] == "NEW"

    def test_evidence_model_and_sha256_hash(self, tmp_path):
        vault = EvidenceVault(storage_dir=str(tmp_path / "evidence"))
        raw_output = "HTTP/1.1 500 Internal Server Error\nContent-Type: text/html\n\nDatabase query failed."
        expected_hash = hashlib.sha256(raw_output.encode("utf-8")).hexdigest()

        evidence = vault.store_evidence(
            tool_name="Nuclei",
            target="sec-lab.target.local",
            output_excerpt=raw_output,
            finding_id="BUG-2026-0001",
            evidence_type=EvidenceType.HTTP_RESPONSE
        )

        assert evidence.hash_sha256 == expected_hash
        assert evidence.evidence_type == EvidenceType.HTTP_RESPONSE
        assert evidence.finding_id == "BUG-2026-0001"

        # Verify integrity
        ok, msg = vault.verify_evidence_integrity(evidence.id)
        assert ok is True
        assert "matched" in msg.lower()

    def test_evidence_sensitive_data_redaction(self, tmp_path):
        vault = EvidenceVault(storage_dir=str(tmp_path / "evidence"))
        sensitive_output = "token=secret_token_12345\nPassword: mySuperSecretPassword123"

        evidence = vault.store_evidence(
            tool_name="AuthProbe",
            target="sec-lab.target.local",
            output_excerpt=sensitive_output
        )

        # Output excerpt must be sanitized
        assert "secret_token_12345" not in evidence.output_excerpt
        assert "mySuperSecretPassword123" not in evidence.output_excerpt
        assert "[REDACTED]" in evidence.output_excerpt

    def test_http_evidence_vault_capture(self, tmp_path):
        vault = EvidenceVault(storage_dir=str(tmp_path / "evidence"))
        headers = {"Authorization": "Bearer sensitive_jwt_token", "User-Agent": "CyberWolf/2.0"}
        body = "username=admin&password=unhashed_password"

        evidence = vault.store_http_evidence(
            target="https://target.local/login",
            method="POST",
            url="https://target.local/login",
            request_headers=headers,
            request_body=body,
            status_code=403,
            response_body="Access Denied: Invalid CSRF token",
            finding_id="BUG-2026-0002"
        )

        assert evidence.evidence_type == EvidenceType.HTTP_RESPONSE
        assert evidence.finding_id == "BUG-2026-0002"
        assert evidence.hash_sha256 is not None
        assert "sensitive_jwt_token" not in str(evidence.request_data)
        assert "unhashed_password" not in str(evidence.request_data)
