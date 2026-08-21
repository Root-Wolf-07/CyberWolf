"""CYBERWOLF Nuclei Vulnerability Scanner Adapter."""

import json
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter

class NucleiAdapter(BaseToolAdapter):
    """Adapter for ProjectDiscovery Nuclei vulnerability scanner."""
    def __init__(self):
        super().__init__("Nuclei", ["nuclei"])

    def build_command(self, target: str, tags: Optional[str] = None, severity: Optional[str] = None, **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("Nuclei binary not found on system.")

        cmd = [self.binary_path, "-u", target, "-json-export", "-silent"]
        if tags:
            cmd.extend(["-tags", tags])
        if severity:
            cmd.extend(["-severity", severity])
        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                sev = info.get("severity", "info").upper()
                cve_list = info.get("classification", {}).get("cve-id", [])
                cve_str = ", ".join(cve_list) if isinstance(cve_list, list) else str(cve_list)
                cwe_list = info.get("classification", {}).get("cwe-id", [])
                cwe_str = ", ".join(cwe_list) if isinstance(cwe_list, list) else str(cwe_list)

                findings.append({
                    "vulnerability": info.get("name", data.get("template-id", "Nuclei Finding")),
                    "severity": sev if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else "INFO",
                    "confidence": "HIGH",
                    "evidence": f"Matched template: {data.get('template-id')} at {data.get('matched-at', '')}",
                    "cve": cve_str or None,
                    "cwe": cwe_str or None,
                    "remediation": info.get("remediation", "Apply vendor patch or configuration update."),
                    "source_tool": "Nuclei"
                })
            except json.JSONDecodeError:
                continue

        return {
            "success": exit_code == 0,
            "findings": findings,
            "raw_output": raw_output
        }
