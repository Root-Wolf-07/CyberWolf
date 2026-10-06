"""Unit tests for CYBERWOLF Cryptographic Evidence Vault."""

import os
import pytest
from app.evidence.vault import EvidenceVault


def test_evidence_storage_and_sha256_hash(tmp_path):
    """Verify evidence storage calculates valid SHA-256 and writes artifact."""
    vault = EvidenceVault(storage_dir=str(tmp_path))

    ev = vault.store_evidence(
        target="192.168.1.100",
        tool_name="Nmap",
        output_text="PORT 80/tcp open http Apache 2.4.41",
        command_used="nmap -p 80 192.168.1.100"
    )

    assert ev.id.startswith("EVID-")
    assert ev.hash_sha256 is not None
    assert len(ev.hash_sha256) == 64  # Valid SHA-256 hex string length

    # Verify integrity verification
    verified, msg = vault.verify_evidence_integrity(ev.id)
    assert verified
    assert "matched" in msg.lower()


def test_sensitive_credential_redaction_in_vault(tmp_path):
    """Verify passwords and API keys in evidence are redacted before storage."""
    vault = EvidenceVault(storage_dir=str(tmp_path))

    ev = vault.store_evidence(
        target="192.168.1.100",
        tool_name="AuthScan",
        output_text="Connecting with password='superSecretPassword123!' and token='ghp_ABC123456789012345678901234567890123'"
    )

    assert "superSecretPassword123!" not in ev.output_excerpt
    assert "[REDACTED]" in ev.output_excerpt
