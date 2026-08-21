"""CYBERWOLF Nikto Web Scanner Adapter."""

import re
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter

class NiktoAdapter(BaseToolAdapter):
    """Adapter for Nikto Web Server Scanner."""
    def __init__(self):
        super().__init__("Nikto", ["nikto", "nikto.pl"])

    def build_command(self, target: str, port: Optional[int] = None, ssl: bool = False, **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("Nikto binary not found on system.")

        cmd = [self.binary_path, "-h", target]
        if port:
            cmd.extend(["-p", str(port)])
        if ssl:
            cmd.append("-ssl")
        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith("+"):
                text = line[1:].strip()
                if "OSVDB" in text or "anti-clickjacking" in text.lower() or "vulnerable" in text.lower() or "header missing" in text.lower():
                    sev = "MEDIUM" if "vulnerable" in text.lower() else "LOW"
                    findings.append({
                        "vulnerability": "Web Server Security Issue",
                        "severity": sev,
                        "confidence": "MEDIUM",
                        "evidence": text,
                        "remediation": "Update server configuration and apply recommended HTTP security headers.",
                        "source_tool": "Nikto"
                    })
        return {
            "success": exit_code == 0,
            "findings": findings,
            "raw_output": raw_output
        }
