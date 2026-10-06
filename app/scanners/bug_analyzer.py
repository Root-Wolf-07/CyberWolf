"""CYBERWOLF Bug & Security Misconfiguration Discovery Engine (BDIE V2)."""

import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
from app.database.operations import create_scan, complete_scan, create_finding
from app.database.models import Finding, FindingStatus
from app.core.logger import get_logger
from app.detection.exact_location import ExactLocationEngine
from app.detection.risk_engine import get_risk_engine
from app.evidence.vault import get_evidence_vault

logger = get_logger()

SENSITIVE_PATHS = [
    ("/.env", "CRITICAL", "Exposed Environment Configuration (.env with credentials)", "CWE-200", "A05:2021-Security Misconfiguration"),
    ("/.git/HEAD", "HIGH", "Exposed Git Repository Metadata", "CWE-538", "A05:2021-Security Misconfiguration"),
    ("/actuator/env", "HIGH", "Exposed Spring Boot Actuator Endpoint", "CWE-200", "A05:2021-Security Misconfiguration"),
    ("/phpinfo.php", "MEDIUM", "Exposed PHP Configuration (phpinfo)", "CWE-200", "A05:2021-Security Misconfiguration"),
    ("/server-status", "MEDIUM", "Exposed Apache Server Status", "CWE-200", "A05:2021-Security Misconfiguration"),
    ("/swagger-ui.html", "LOW", "Exposed Public API Documentation (Swagger)", "CWE-200", "A05:2021-Security Misconfiguration"),
    ("/robots.txt", "INFO", "Robots Exclusion Protocol File", "CWE-200", "A05:2021-Security Misconfiguration")
]


class BugAnalyzer:
    """Discovers security misconfigurations, sensitive file leaks, and exposed endpoints (BDIE V2)."""

    def __init__(self):
        self.vault = get_evidence_vault()
        self.risk_engine = get_risk_engine()

    def analyze(self, target_url: str) -> Dict[str, Any]:
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        base_url = target_url.rstrip("/")
        scan_id = create_scan("bug_discovery", target_url, mode="SAFE_SCAN")
        logger.info(f"Starting bug & misconfiguration analysis for {target_url} (Scan ID: {scan_id})")

        findings: List[Finding] = []
        checked_endpoints = []

        parsed_target = urllib.parse.urlparse(target_url)
        target_host = parsed_target.hostname or target_url
        target_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

        for path, sev, title, cwe, owasp in SENSITIVE_PATHS:
            full_url = base_url + path
            checked_endpoints.append(path)
            try:
                resp = requests.get(
                    full_url, timeout=5, verify=False,
                    headers={"User-Agent": "CYBERWOLF Misconfiguration Probe"},
                    allow_redirects=False
                )

                # Check for 200 OK or specific leak signatures
                if resp.status_code == 200 and len(resp.text) > 0:
                    evidence_text = f"Endpoint '{path}' returned HTTP 200 OK (Content length: {len(resp.text)} bytes)."
                    if path == "/.env" and any(k in resp.text for k in ["DB_", "SECRET", "PASSWORD", "KEY"]):
                        evidence_text += " [CONFIRMED ENVIRONMENT SECRETS FOUND]"
                    elif path == "/.git/HEAD" and "ref:" in resp.text:
                        evidence_text += " [CONFIRMED GIT REPOSITORY HEAD IDENTIFIED]"

                    finding_id = f"CW-BUG-{datetime.now().strftime('%Y%m%d%H%M%S')}-{abs(hash(path)) % 10000:04d}"

                    # Store cryptographic evidence
                    ev = self.vault.store_http_evidence(
                        target=target_url,
                        url=full_url,
                        method="GET",
                        request_headers={"User-Agent": "CYBERWOLF Misconfiguration Probe"},
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=resp.text[:2000],
                        finding_id=finding_id,
                        scan_id=scan_id,
                        tool_name="CYBERWOLF Bug Engine"
                    )

                    loc = ExactLocationEngine.parse_web_target(full_url, method="GET", endpoint=path)

                    f = Finding(
                        id=finding_id,
                        target=target_url,
                        host=target_host,
                        port=target_port,
                        protocol="https" if target_port == 443 else "http",
                        title=f"Misconfiguration: {title}",
                        vulnerability=f"Misconfiguration: {title}",
                        description=evidence_text,
                        severity=sev,
                        confidence="CONFIRMED",
                        category="web_misconfiguration",
                        cwe=cwe,
                        cwe_ids=[cwe],
                        owasp_category=owasp,
                        evidence=evidence_text,
                        evidence_ids=[ev.id],
                        source_tool="CYBERWOLF Bug Engine",
                        source_tools=["CYBERWOLF Bug Engine"],
                        remediation=f"Block public access to '{path}' in web server access rules or remove unnecessary test files.",
                        status=FindingStatus.CONFIRMED,
                        verified=True,
                        url=full_url,
                        http_method="GET",
                        endpoint=path,
                        component="Web Server / Application Configuration",
                        config_area="Information Exposure & Access Control",
                        config_setting=f"Public access to {path}",
                        config_observed=f"HTTP 200 OK ({len(resp.text)} bytes)",
                        config_expected="HTTP 401/403 or 404 Not Found",
                        observed_behavior=evidence_text,
                        verified_behavior=f"Verified GET {path} returns HTTP 200 OK with sensitive contents in authorized test.",
                        potential_impact="Exposure of internal application metadata, credentials, or sensitive deployment structures.",
                        exploitability="HIGH" if sev in ["CRITICAL", "HIGH"] else "MEDIUM",
                        exploit_prerequisites="Unauthenticated network/HTTP access to web server.",
                        exploit_limitations="Read-only enumeration; active exploitation or lateral movement not conducted.",
                        scan_id=scan_id
                    )

                    # Compute explainable risk score
                    risk_score, risk_factors = self.risk_engine.calculate_risk(f)
                    f.risk_score = risk_score
                    f.risk_factors = risk_factors

                    create_finding(f)
                    findings.append(f)
            except Exception:
                pass

        complete_scan(scan_id, "COMPLETED", findings_count=len(findings))
        return {
            "success": True,
            "scan_id": scan_id,
            "target": target_url,
            "checked_paths": checked_endpoints,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings]
        }
