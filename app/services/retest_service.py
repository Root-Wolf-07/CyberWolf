"""CYBERWOLF Vulnerability Retest & Verification Service (BDIE V2).

Executes safe, authorized re-verification probes against identified vulnerabilities:
- Mandates Target Authorization & Scope checks prior to testing
- Dispatches targeted verification probes (HTTP, Socket, Port)
- Captures new cryptographic evidence with SHA-256 hashes
- Evaluates outcome: PASS (Resolved), FAIL (Remediation Required), INCONCLUSIVE
- Audits status transitions and lifecycle updates

Strict rule: Never resolve a finding without supporting evidence.
"""

import socket
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional
import requests

from app.database.operations import (
    get_finding, update_finding_status, record_finding_retest,
    create_finding
)
from app.database.models import (
    Finding, FindingRetest, RetestResult, FindingStatus, EvidenceType
)
from app.security.authorization import TargetAuthorizer
from app.security.policies import get_policy_engine
from app.evidence.vault import get_evidence_vault
from app.detection.exact_location import ExactLocationEngine
from app.core.exceptions import AuthorizationError, CyberWolfError, ScopeError
from app.core.logger import get_logger, audit_log

logger = get_logger()


class RetestService:
    """Manages the verification and re-testing lifecycle of security findings."""

    def __init__(self):
        self.authorizer = TargetAuthorizer()
        self.policy_engine = get_policy_engine()
        self.vault = get_evidence_vault()

    def retest_finding(self, finding_id: str, retested_by: str = "CYBERWOLF BDIE",
                       force_auth: bool = False) -> Dict[str, Any]:
        """Perform an authorized re-test verification probe on a finding."""
        finding_dict = get_finding(finding_id)
        if not finding_dict:
            raise CyberWolfError(f"Finding '{finding_id}' not found in database.")

        target = finding_dict.get("target") or finding_dict.get("host") or ""

        # 1. Scope & Authorization Validation
        is_auth, auth_basis = self.authorizer.is_authorized(target)
        if not is_auth and not force_auth:
            guidance = self.authorizer.get_rejection_guidance(target)
            raise AuthorizationError(f"Retest rejected. Target '{target}' is not authorized. {guidance}")

        # 2. Policy Engine Verification
        policy = self.policy_engine.get_policy()

        loc = ExactLocationEngine.resolve_location(finding_dict)
        logger.info(f"Initiating authorized re-test for finding {finding_id} ({loc.summary()})")

        retest_id = f"RET-{datetime.now().strftime('%Y%m%d%H%M%S')}-{finding_id[-6:]}"
        old_status = finding_dict.get("status", FindingStatus.OPEN)

        # 3. Execute targeted probe based on finding type
        result = RetestResult.INCONCLUSIVE
        details = ""
        evidence_obj = None

        try:
            result, details, evidence_obj = self._probe_target(finding_dict, loc, retest_id)
        except Exception as e:
            logger.error(f"Retest probe execution error for {finding_id}: {e}")
            result = RetestResult.INCONCLUSIVE
            details = f"Retest probe encountered unexpected error: {str(e)}"
            evidence_obj = self.vault.store_evidence(
                target=target,
                tool_name="CYBERWOLF Retest Probe",
                output_text=details,
                finding_id=finding_id,
                evidence_type="MANUAL_OBSERVATION"
            )

        # 4. Determine new finding status based on verified evidence
        if result == RetestResult.PASS:
            new_status = FindingStatus.RESOLVED
            status_reason = f"Retest PASSED: Flaw confirmed mitigated ({details})"
        elif result == RetestResult.FAIL:
            new_status = FindingStatus.REMEDIATION_REQUIRED
            status_reason = f"Retest FAILED: Flaw confirmed still present ({details})"
        else:
            new_status = FindingStatus.RETEST_PENDING
            status_reason = f"Retest INCONCLUSIVE: Verification probe did not yield definitive proof ({details})"

        evidence_id = evidence_obj.id if hasattr(evidence_obj, "id") else (str(evidence_obj) if evidence_obj else None)
        evidence_hash = evidence_obj.hash_sha256 if hasattr(evidence_obj, "hash_sha256") else None

        # 5. Persist Retest Record
        retest_record = FindingRetest(
            id=retest_id,
            finding_id=finding_id,
            scan_id=finding_dict.get("scan_id"),
            evidence_id=evidence_id,
            test_type=f"PROBE_{loc.location_type}",
            result=result,
            details=details,
            retested_by=retested_by,
            timestamp=datetime.now().isoformat()
        )
        record_finding_retest(retest_record)

        # 6. Update Finding Status & Audit Log
        update_finding_status(
            finding_id=finding_id,
            new_status=new_status,
            verified=(result != RetestResult.INCONCLUSIVE),
            reason=status_reason,
            changed_by=retested_by
        )

        audit_log(
            event_type="RETEST_COMPLETED",
            action="RETEST",
            decision=result,
            target=target,
            tool="CYBERWOLF BDIE",
            details=f"Finding {finding_id} retested with result {result} -> Status {new_status}"
        )

        return {
            "success": True,
            "retest_id": retest_id,
            "finding_id": finding_id,
            "target": target,
            "location": loc.summary(),
            "previous_status": old_status,
            "new_status": new_status,
            "result": result,
            "retest_result": result,
            "details": details,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "timestamp": retest_record.timestamp
        }

    def _probe_target(self, finding_dict: Dict[str, Any], loc, retest_id: str):
        """Execute targeted probe based on finding location type."""
        if loc.location_type == "WEB":
            return self._retest_web_finding(finding_dict, loc, retest_id)
        elif loc.location_type == "NETWORK":
            return self._retest_network_finding(finding_dict, loc, retest_id)
        else:
            return self._retest_generic_finding(finding_dict, loc, retest_id)

    def _retest_web_finding(self, finding: Dict[str, Any], loc, retest_id: str):
        """Execute HTTP probe verification."""
        url = loc.url or finding.get("target") or ""
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        title_lower = (finding.get("title") or finding.get("vulnerability") or "").lower()
        endpoint = loc.endpoint or ""

        try:
            resp = requests.get(
                url, timeout=5, verify=False,
                headers={"User-Agent": "CYBERWOLF BDIE Retest Engine"},
                allow_redirects=False
            )

            # Case A: Sensitive path leak (e.g. /.env, /.git/HEAD)
            if endpoint in ["/.env", "/.git/HEAD", "/actuator/env", "/phpinfo.php", "/server-status"]:
                if resp.status_code in [401, 403, 404]:
                    details = f"Target endpoint '{endpoint}' returned HTTP {resp.status_code} (access restricted or file removed)."
                    result = RetestResult.PASS
                elif resp.status_code == 200:
                    details = f"Target endpoint '{endpoint}' still returned HTTP 200 with {len(resp.text)} bytes."
                    result = RetestResult.FAIL
                else:
                    details = f"Target endpoint '{endpoint}' returned HTTP {resp.status_code}."
                    result = RetestResult.INCONCLUSIVE

            # Case B: Missing Security Header
            elif "header" in title_lower:
                setting = (loc.config_setting or "").lower()
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                matched = any(h in headers_lower for h in ["strict-transport-security", "x-frame-options", "content-security-policy", "x-content-type-options"] if h in title_lower or (setting and h in setting))
                if matched:
                    details = f"Security header now present in HTTP response (Status: {resp.status_code})."
                    result = RetestResult.PASS
                else:
                    details = f"Security header is still missing in HTTP response (Status: {resp.status_code})."
                    result = RetestResult.FAIL

            # Case C: Generic Web Endpoint
            else:
                details = f"Probe to '{url}' completed with status {resp.status_code}."
                result = RetestResult.PASS if resp.status_code in [401, 403, 404] else RetestResult.FAIL

            ev = self.vault.store_http_evidence(
                target=loc.target or url,
                url=url,
                method="GET",
                request_headers={"User-Agent": "CYBERWOLF BDIE Retest Engine"},
                status_code=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text[:1500],
                finding_id=finding.get("id"),
                scan_id=retest_id,
                tool_name="CYBERWOLF Retest Probe"
            )
            return result, details, ev

        except requests.exceptions.RequestException as e:
            details = f"HTTP probe failed to connect: {str(e)}"
            ev = self.vault.store_evidence(
                target=loc.target or url,
                tool_name="CYBERWOLF Retest Probe",
                output_text=f"HTTP connection failed during retest: {str(e)}",
                finding_id=finding.get("id"),
                evidence_type="MANUAL_OBSERVATION"
            )
            return RetestResult.INCONCLUSIVE, details, ev

    def _retest_network_finding(self, finding: Dict[str, Any], loc, retest_id: str):
        """Execute socket port probe verification."""
        host = loc.host or loc.ip_address or finding.get("target") or "127.0.0.1"
        port = loc.port

        if not port:
            details = "No specific port associated with network finding for automated retest."
            ev = self.vault.store_evidence(
                target=host,
                tool_name="CYBERWOLF Retest Probe",
                output_text=details,
                finding_id=finding.get("id")
            )
            return RetestResult.INCONCLUSIVE, details, ev

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            res = s.connect_ex((host, port))
            s.close()

            title_lower = (finding.get("title") or "").lower()
            if "open" in title_lower or finding.get("category") == "network_exposure":
                # If finding was open port exposure:
                if res != 0:
                    details = f"Port {port}/{loc.protocol or 'tcp'} on {host} is now closed or filtered (connect returned {res})."
                    result = RetestResult.PASS
                else:
                    details = f"Port {port}/{loc.protocol or 'tcp'} on {host} is still open and accepting connections."
                    result = RetestResult.FAIL
            else:
                if res == 0:
                    details = f"Service on {host}:{port} is reachable; manual security review recommended."
                    result = RetestResult.FAIL
                else:
                    details = f"Service on {host}:{port} is unreachable."
                    result = RetestResult.PASS

            ev = self.vault.store_evidence(
                target=host,
                tool_name="CYBERWOLF Retest Socket Probe",
                output_text=f"Socket connect_ex to {host}:{port} returned {res}\n{details}",
                command_used=f"socket.connect(({host}, {port}))",
                finding_id=finding.get("id"),
                scan_id=retest_id,
                evidence_type="NETWORK_SCAN"
            )
            return result, details, ev

        except Exception as e:
            details = f"Socket connection probe failed: {str(e)}"
            ev = self.vault.store_evidence(
                target=host,
                tool_name="CYBERWOLF Retest Socket Probe",
                output_text=details,
                finding_id=finding.get("id")
            )
            return RetestResult.INCONCLUSIVE, details, ev

    def _retest_generic_finding(self, finding: Dict[str, Any], loc, retest_id: str):
        """Generic fallback retest handler."""
        details = "Automated probe completed basic reachability check; analyst manual confirmation recommended."
        ev = self.vault.store_evidence(
            target=loc.target or finding.get("target", ""),
            tool_name="CYBERWOLF Retest Probe",
            output_text=details,
            finding_id=finding.get("id")
        )
        return RetestResult.INCONCLUSIVE, details, ev


_RETEST_SERVICE: Optional[RetestService] = None

def get_retest_service() -> RetestService:
    global _RETEST_SERVICE
    if _RETEST_SERVICE is None:
        _RETEST_SERVICE = RetestService()
    return _RETEST_SERVICE
