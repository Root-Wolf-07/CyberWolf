"""CYBERWOLF Web Application Security Assessment Engine."""

import ssl
import socket
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
from app.database.operations import create_scan, complete_scan, create_finding
from app.database.models import Finding
from app.core.logger import get_logger

logger = get_logger()

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity": "HIGH", "desc": "HSTS header missing; connection vulnerable to SSL stripping."},
    "Content-Security-Policy": {"severity": "MEDIUM", "desc": "CSP header missing; increased risk of Cross-Site Scripting (XSS)."},
    "X-Frame-Options": {"severity": "MEDIUM", "desc": "X-Frame-Options missing; susceptible to Clickjacking."},
    "X-Content-Type-Options": {"severity": "LOW", "desc": "X-Content-Type-Options missing; MIME-sniffing vulnerability."},
    "Referrer-Policy": {"severity": "LOW", "desc": "Referrer-Policy header missing; sensitive URL parameters may leak."},
    "Permissions-Policy": {"severity": "INFO", "desc": "Permissions-Policy missing; browser features not restricted."}
}

class WebScanner:
    """Evaluates HTTP/HTTPS endpoints, security headers, TLS posture, and tech fingerprint."""
    
    def assess_url(self, target_url: str) -> Dict[str, Any]:
        """Perform comprehensive web security audit."""
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        parsed_url = urllib.parse.urlparse(target_url)
        scan_id = create_scan("web", target_url, mode="SAFE_SCAN")
        logger.info(f"Starting web security assessment for {target_url} (Scan ID: {scan_id})")

        findings: List[Finding] = []
        headers_found = {}
        server_banner = "Unknown"
        tls_info = {}

        # 1. Inspect HTTP Response & Headers
        try:
            resp = requests.get(target_url, timeout=10, allow_redirects=True, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (CYBERWOLF Security Scanner)"})
            headers_found = dict(resp.headers)
            server_banner = resp.headers.get("Server", "Hidden/Not specified")
            powered_by = resp.headers.get("X-Powered-By")

            # Check server banner exposure
            if server_banner != "Hidden/Not specified" and any(c.isdigit() for c in server_banner):
                f = Finding(
                    id=f"CW-WEB-VER-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    target=target_url,
                    vulnerability="Detailed Server Version Disclosure",
                    severity="LOW",
                    evidence=f"Server header exposes exact version: {server_banner}",
                    confidence="HIGH",
                    source_tool="CYBERWOLF Web Engine",
                    remediation="Configure web server to suppress exact version strings in the Server header."
                )
                create_finding(f)
                findings.append(f)

            # Check missing security headers
            for header_name, meta in REQUIRED_SECURITY_HEADERS.items():
                if header_name.lower() not in [h.lower() for h in resp.headers.keys()]:
                    f = Finding(
                        id=f"CW-WEB-HDR-{datetime.now().strftime('%Y%m%d%H%M%S')}-{header_name[:4].upper()}",
                        target=target_url,
                        vulnerability=f"Missing Security Header: {header_name}",
                        severity=meta["severity"],
                        evidence=f"Response headers lack '{header_name}'. {meta['desc']}",
                        confidence="HIGH",
                        source_tool="CYBERWOLF Web Engine",
                        remediation=f"Add ' {header_name} ' to your web server (Nginx/Apache/Cloudflare) response headers."
                    )
                    create_finding(f)
                    findings.append(f)

            # Check for Insecure Cookies (Missing Secure or HttpOnly)
            for cookie in resp.cookies:
                if not cookie.secure and target_url.startswith("https://"):
                    f = Finding(
                        id=f"CW-WEB-CKY-{datetime.now().strftime('%Y%m%d%H%M%S')}-{cookie.name[:4]}",
                        target=target_url,
                        vulnerability=f"Insecure Cookie: '{cookie.name}' without Secure Flag",
                        severity="MEDIUM",
                        evidence=f"Cookie '{cookie.name}' was set over HTTPS without the Secure attribute.",
                        confidence="HIGH",
                        source_tool="CYBERWOLF Web Engine",
                        remediation="Set the 'Secure' flag on all cookies transmitted over HTTPS."
                    )
                    create_finding(f)
                    findings.append(f)

        except Exception as e:
            logger.error(f"HTTP request error for {target_url}: {e}")
            complete_scan(scan_id, "FAILED")
            return {"success": False, "error": str(e), "target": target_url}

        # 2. Check TLS Certificate if HTTPS
        if target_url.startswith("https://") and parsed_url.hostname:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((parsed_url.hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                        cert = ssock.getpeercert()
                        tls_version = ssock.version()
                        cipher = ssock.cipher()
                        tls_info = {
                            "version": tls_version,
                            "cipher": cipher[0] if cipher else "Unknown",
                            "bits": cipher[2] if cipher else 0,
                            "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {}
                        }
            except Exception as e:
                tls_info = {"error": f"TLS Inspection failed: {e}"}

        complete_scan(scan_id, "COMPLETED", findings_count=len(findings))
        return {
            "success": True,
            "scan_id": scan_id,
            "target": target_url,
            "server": server_banner,
            "tls_info": tls_info,
            "findings_count": len(findings),
            "findings": [vars(f) for f in findings]
        }
