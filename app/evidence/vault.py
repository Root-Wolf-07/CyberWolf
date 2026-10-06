"""CYBERWOLF Evidence Vault & SHA-256 Provenance Storage (V2).

Safely stores, indexes, and verifies security evidence:
- Enforces SHA-256 hashing on all evidence files and excerpts
- Links evidence to finding_id and scan_id
- Applies strict size limits and sensitive payload redaction
- Provides point-in-time integrity verification
"""

import os
import hashlib
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from app.core.config import get_config
from app.core.logger import get_logger, sanitize_message
from app.database.models import Evidence
from app.database.operations import create_evidence, get_evidence_by_scan, get_evidence_by_finding

logger = get_logger()

MAX_EXCERPT_CHARS = 4000
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10MB limit


class EvidenceVault:
    """Manages physical and database storage of cryptographic security assessment evidence."""

    def __init__(self, storage_dir: Optional[str] = None):
        self.config = get_config()
        self.vault_dir = Path(storage_dir or (self.config.base_dir / "database" / "evidence")).resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def store_evidence(self, target: str, tool_name: str, output_text: Optional[str] = None,
                       command_used: Optional[str] = None, finding_id: Optional[str] = None,
                       scan_id: Optional[str] = None, http_metadata: Optional[Dict[str, Any]] = None,
                       packet_metadata: Optional[Dict[str, Any]] = None,
                       scanner_result: Optional[Dict[str, Any]] = None,
                       evidence_type: str = "TOOL_OUTPUT",
                       request_data: Optional[Dict[str, Any]] = None,
                       response_data: Optional[Dict[str, Any]] = None,
                       observed_data: Optional[Dict[str, Any]] = None,
                       tool_run_id: Optional[str] = None,
                       output_excerpt: Optional[str] = None) -> Evidence:
        """Store evidence artifact, calculate SHA-256, and persist metadata (BDIE V2)."""
        evidence_id = f"EVID-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        # 1. Sanitize sensitive credentials
        raw_text = output_text if output_text is not None else (output_excerpt or "")
        safe_output = sanitize_message(raw_text)

        # 2. Compute SHA-256 hash
        output_bytes = safe_output.encode("utf-8")
        sha256_hash = hashlib.sha256(output_bytes).hexdigest()

        # 3. Store raw artifact file
        artifact_path = self.vault_dir / f"{evidence_id}.txt"
        try:
            with open(artifact_path, "w", encoding="utf-8") as f:
                f.write(safe_output)
        except Exception as e:
            logger.error(f"Failed to write evidence artifact: {e}")
            artifact_path = None

        # 4. Create excerpt
        excerpt = safe_output[:MAX_EXCERPT_CHARS]
        if len(safe_output) > MAX_EXCERPT_CHARS:
            excerpt += f"\n... [Truncated {len(safe_output) - MAX_EXCERPT_CHARS} bytes. Full output in vault]."

        # 5. Build Evidence domain object
        evidence = Evidence(
            id=evidence_id,
            target=target,
            tool_name=tool_name,
            output_excerpt=excerpt,
            command_used=command_used,
            finding_id=finding_id,
            scan_id=scan_id,
            timestamp=datetime.now().isoformat(),
            raw_result_path=str(artifact_path) if artifact_path else None,
            packet_metadata=packet_metadata or {},
            http_metadata=http_metadata or {},
            scanner_result=scanner_result or {},
            hash_sha256=sha256_hash,
            evidence_type=evidence_type,
            request_data=request_data or {},
            response_data=response_data or {},
            observed_data=observed_data or {},
            tool_run_id=tool_run_id
        )

        # 6. Save to SQLite database
        create_evidence(evidence)
        logger.info(f"Evidence {evidence_id} stored in vault (SHA-256: {sha256_hash[:16]}...)")
        return evidence

    def store_http_evidence(self, target: str, url: str, method: str = "GET",
                            request_headers: Optional[Dict[str, str]] = None,
                            request_body: Optional[str] = None,
                            status_code: Optional[int] = None,
                            response_headers: Optional[Dict[str, str]] = None,
                            response_body: Optional[str] = None,
                            finding_id: Optional[str] = None,
                            scan_id: Optional[str] = None,
                            tool_name: str = "CYBERWOLF HTTP Probe") -> Evidence:
        """Helper to store safe, sanitized HTTP request/response evidence pair."""
        req_lines = [f"{method} {url} HTTP/1.1"]
        if request_headers:
            for k, v in request_headers.items():
                if k.lower() in ["authorization", "cookie", "x-api-key"]:
                    v = "[REDACTED]"
                req_lines.append(f"{k}: {v}")
        if request_body:
            req_lines.append("")
            req_lines.append(request_body[:1000])

        res_lines = [f"HTTP/1.1 {status_code or 200}"]
        if response_headers:
            for k, v in response_headers.items():
                if k.lower() in ["set-cookie"]:
                    v = "[REDACTED_COOKIE]"
                res_lines.append(f"{k}: {v}")
        if response_body:
            res_lines.append("")
            res_lines.append(response_body[:2000])

        raw_evidence = "=== HTTP REQUEST ===\n" + "\n".join(req_lines) + "\n\n=== HTTP RESPONSE ===\n" + "\n".join(res_lines)

        req_data = {
            "method": method,
            "url": url,
            "headers": {k: ("[REDACTED]" if k.lower() in ["authorization", "cookie"] else v) for k, v in (request_headers or {}).items()}
        }
        res_data = {
            "status_code": status_code,
            "headers": {k: ("[REDACTED]" if k.lower() in ["set-cookie"] else v) for k, v in (response_headers or {}).items()}
        }

        return self.store_evidence(
            target=target,
            tool_name=tool_name,
            output_text=raw_evidence,
            command_used=f"HTTP {method} {url}",
            finding_id=finding_id,
            scan_id=scan_id,
            http_metadata={"url": url, "method": method, "status_code": status_code},
            evidence_type="HTTP_RESPONSE",
            request_data=req_data,
            response_data=res_data
        )

    def verify_integrity(self, evidence: Evidence) -> bool:
        """Verify that the raw file on disk matches its recorded SHA-256 hash."""
        if not evidence.raw_result_path or not evidence.hash_sha256:
            return False

        path = Path(evidence.raw_result_path)
        if not path.exists():
            logger.warning(f"Evidence file missing at {path}")
            return False

        try:
            with open(path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            return actual_hash.lower() == evidence.hash_sha256.lower()
        except Exception as e:
            logger.error(f"Integrity check failed: {e}")
            return False

    def verify_evidence_integrity(self, evidence_or_id) -> Tuple[bool, str]:
        """Verify evidence integrity by ID or Evidence object."""
        if isinstance(evidence_or_id, str):
            from app.database.operations import get_evidence
            ev_dict = get_evidence(evidence_or_id)
            if not ev_dict:
                return False, f"Evidence {evidence_or_id} not found"
            evidence = Evidence(
                id=ev_dict["id"],
                target=ev_dict["target"],
                tool_name=ev_dict["tool_name"],
                output_excerpt=ev_dict.get("output_excerpt", ""),
                raw_result_path=ev_dict.get("raw_result_path"),
                hash_sha256=ev_dict.get("hash_sha256")
            )
        else:
            evidence = evidence_or_id

        ok = self.verify_integrity(evidence)
        return ok, "SHA-256 hash matched artifact" if ok else "Hash mismatch or missing file"

    def get_scan_evidence(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve all evidence associated with a scan."""
        return get_evidence_by_scan(scan_id)

    def get_finding_evidence(self, finding_id: str) -> List[Dict[str, Any]]:
        """Retrieve all evidence associated with a finding."""
        return get_evidence_by_finding(finding_id)


_EVIDENCE_VAULT: Optional[EvidenceVault] = None

def get_evidence_vault() -> EvidenceVault:
    global _EVIDENCE_VAULT
    if _EVIDENCE_VAULT is None:
        _EVIDENCE_VAULT = EvidenceVault()
    return _EVIDENCE_VAULT
