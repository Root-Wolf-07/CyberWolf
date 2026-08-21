"""CYBERWOLF Bug & Security Misconfiguration Discovery Engine."""

import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
from app.database.operations import create_scan, complete_scan, create_finding
from app.database.models import Finding
from app.core.logger import get_logger

logger = get_logger()

SENSITIVE_PATHS = [
    ("/.env", "CRITICAL", "Exposed Environment Configuration (.env with credentials)", "CWE-200"),
    ("/.git/HEAD", "HIGH", "Exposed Git Repository Metadata", "CWE-538"),
    ("/actuator/env", "HIGH", "Exposed Spring Boot Actuator Endpoint", "CWE-200"),
    ("/phpinfo.php", "MEDIUM", "Exposed PHP Configuration (phpinfo)", "CWE-200"),
    ("/server-status", "MEDIUM", "Exposed Apache Server Status", "CWE-200"),
    ("/swagger-ui.html", "LOW", "Exposed Public API Documentation (Swagger)", "CWE-200"),
    ("/robots.txt", "INFO", "Robots Exclusion Protocol File", "CWE-200")
]

class BugAnalyzer:
    """Discovers security misconfigurations, sensitive file leaks, and exposed endpoints."""
    
    def analyze(self, target_url: str) -> Dict[str, Any]:
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        base_url = target_url.rstrip("/")
        scan_id = create_scan("bug_discovery", target_url, mode="SAFE_SCAN")
        logger.info(f"Starting bug & misconfiguration analysis for {target_url} (Scan ID: {scan_id})")

        findings: List[Finding] = []
        checked_endpoints = []

        for path, sev, title, cwe in SENSITIVE_PATHS:
            full_url = base_url + path
            checked_endpoints.append(path)
            try:
                resp = requests.get(full_url, timeout=5, verify=False,
                                    headers={"User-Agent": "CYBERWOLF Misconfiguration Probe"},
                                    allow_redirects=False)
                
                # Check for 200 OK or specific leak signatures
                if resp.status_code == 200 and len(resp.text) > 0:
                    evidence_text = f"Endpoint '{path}' returned HTTP 200 OK (Content length: {len(resp.text)} bytes)."
                    if path == "/.env" and any(k in resp.text for k in ["DB_", "SECRET", "PASSWORD", "KEY"]):
                        evidence_text += " [CONFIRMED ENVIRONMENT SECRETS FOUND]"
                    elif path == "/.git/HEAD" and "ref:" in resp.text:
                        evidence_text += " [CONFIRMED GIT REPOSITORY HEAD IDENTIFIED]"

                    f = Finding(
                        id=f"CW-BUG-{datetime.now().strftime('%Y%m%d%H%M%S')}-{abs(hash(path)) % 10000:04d}",
                        target=target_url,
                        vulnerability=f"Misconfiguration: {title}",
                        severity=sev,
                        evidence=evidence_text,
                        confidence="HIGH",
                        cwe=cwe,
                        source_tool="CYBERWOLF Bug Engine",
                        remediation=f"Block public access to '{path}' in web server access rules or remove unnecessary test files."
                    )
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
            "findings": [vars(f) for f in findings]
        }
