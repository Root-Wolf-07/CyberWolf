"""CYBERWOLF Nikto Web Scanner Adapter (V2).

Provides web server misconfiguration and outdated software scanning:
- Argument validation & port checks
- Structured CLI command construction
- Output line parser extracting findings
- Canonical Finding normalization
"""

import uuid
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter
from app.database.models import Finding, SeverityLevel, ConfidenceLevel
from app.security.sanitizer import sanitize_target
from app.core.exceptions import ToolNotFoundError, ValidationError


class NiktoAdapter(BaseToolAdapter):
    """Adapter for Nikto Web Server Scanner."""

    def __init__(self):
        super().__init__("Nikto", ["nikto", "nikto.pl"])

    def validate_arguments(self, target: str, options: Optional[Dict[str, Any]] = None) -> bool:
        super().validate_arguments(target, options)
        clean_target = sanitize_target(target)
        opts = options or {}
        if opts.get("port"):
            p = int(opts["port"])
            if p < 1 or p > 65535:
                raise ValidationError(f"Invalid port number: {p}")
        return True

    def build_command(self, target: str, port: Optional[int] = None,
                      ssl: bool = False, **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("Nikto binary not found on system PATH.")

        clean_target = sanitize_target(target)
        cmd = [self.binary_path, "-h", clean_target]

        if port:
            cmd.extend(["-p", str(port)])
        if ssl:
            cmd.append("-ssl")

        return cmd

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        findings_data = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith("+"):
                text = line[1:].strip()
                lower_text = text.lower()
                if any(k in lower_text for k in ["osvdb", "anti-clickjacking", "vulnerable", "header missing", "x-frame-options", "directory indexing", "cve"]):
                    sev = "MEDIUM" if "vulnerable" in lower_text or "osvdb" in lower_text else "LOW"
                    findings_data.append({
                        "vulnerability": "Web Server Security Issue",
                        "title": "Web Server Security Issue",
                        "severity": sev,
                        "confidence": "MEDIUM",
                        "evidence": text,
                        "remediation": "Update server configuration, suppress banner info, and apply recommended HTTP security headers.",
                        "source_tool": "Nikto"
                    })

        return {
            "success": exit_code == 0,
            "findings": findings_data,
            "raw_output": raw_output
        }

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        findings = []
        for f in parsed_results.get("findings", []):
            finding_id = f"CW-NIKTO-{uuid.uuid4().hex[:6].upper()}"
            findings.append(Finding(
                id=finding_id,
                target=target,
                title=f.get("title", "Web Server Security Issue"),
                vulnerability=f.get("vulnerability", "Web Server Security Issue"),
                severity=f.get("severity", "LOW"),
                confidence="MEDIUM",
                category="web_misconfiguration",
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation"),
                source_tool="Nikto",
                source_tools=["Nikto"]
            ))
        return findings
