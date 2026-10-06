"""CYBERWOLF Nuclei Vulnerability Scanner Adapter (V2).

Provides template-based vulnerability assessment:
- Argument validation & safety checks
- JSONL structured output parsing
- CVE, CWE, and CVSS classification extraction
- Canonical Finding normalization
"""

import json
import uuid
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter
from app.database.models import Finding, SeverityLevel, ConfidenceLevel
from app.security.sanitizer import sanitize_target
from app.core.exceptions import ToolNotFoundError, ValidationError


class NucleiAdapter(BaseToolAdapter):
    """Adapter for ProjectDiscovery Nuclei vulnerability scanner."""

    def __init__(self):
        super().__init__("Nuclei", ["nuclei"])

    def validate_arguments(self, target: str, options: Optional[Dict[str, Any]] = None) -> bool:
        super().validate_arguments(target, options)
        clean_target = sanitize_target(target)
        opts = options or {}
        if opts.get("severity"):
            sev = str(opts["severity"]).upper()
            valid_sevs = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            for s in sev.split(","):
                if s.strip() not in valid_sevs:
                    raise ValidationError(f"Invalid Nuclei severity filter: {s.strip()}")
        return True

    def build_command(self, target: str, tags: Optional[str] = None,
                      severity: Optional[str] = None, **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("Nuclei binary not found on system PATH.")

        clean_target = sanitize_target(target)
        cmd = [self.binary_path, "-u", clean_target, "-json-export", "-silent"]

        if tags:
            cmd.extend(["-tags", str(tags).strip()])
        if severity:
            cmd.extend(["-severity", str(severity).strip().lower()])

        return cmd

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        findings_data = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                sev = info.get("severity", "info").upper()

                cve_list = info.get("classification", {}).get("cve-id", [])
                cve_str = ", ".join(cve_list) if isinstance(cve_list, list) else str(cve_list) if cve_list else None

                cwe_list = info.get("classification", {}).get("cwe-id", [])
                cwe_str = ", ".join(cwe_list) if isinstance(cwe_list, list) else str(cwe_list) if cwe_list else None

                cvss_score = info.get("classification", {}).get("cvss-score")

                findings_data.append({
                    "vulnerability": info.get("name", data.get("template-id", "Nuclei Finding")),
                    "title": info.get("name", data.get("template-id", "Nuclei Finding")),
                    "template_id": data.get("template-id"),
                    "matched_at": data.get("matched-at", ""),
                    "severity": sev if sev in SeverityLevel.ALL else "INFO",
                    "confidence": "HIGH",
                    "evidence": f"Matched template: {data.get('template-id')} at {data.get('matched-at', '')}",
                    "cve": cve_str,
                    "cwe": cwe_str,
                    "cvss_score": float(cvss_score) if cvss_score is not None else None,
                    "remediation": info.get("remediation", "Apply vendor security patch or configuration update."),
                    "source_tool": "Nuclei"
                })
            except (json.JSONDecodeError, ValueError):
                continue

        return {
            "success": exit_code == 0,
            "findings": findings_data,
            "raw_output": raw_output
        }

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        findings = []
        for f in parsed_results.get("findings", []):
            finding_id = f"CW-NUCL-{uuid.uuid4().hex[:6].upper()}"
            findings.append(Finding(
                id=finding_id,
                target=target,
                title=f.get("title") or f.get("vulnerability", "Nuclei Finding"),
                vulnerability=f.get("vulnerability") or f.get("title", "Nuclei Finding"),
                severity=f.get("severity", "INFO"),
                confidence="HIGH",
                category="vulnerability",
                evidence=f.get("evidence", ""),
                cve=f.get("cve"),
                cwe=f.get("cwe"),
                remediation=f.get("remediation"),
                source_tool="Nuclei",
                source_tools=["Nuclei"]
            ))
        return findings
