"""CYBERWOLF Vulnerability Assessment Engine.

Integrates Nuclei, Nikto, and native vulnerability normalization.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from app.tools.adapters.nuclei_adapter import NucleiAdapter
from app.tools.adapters.nikto_adapter import NiktoAdapter
from app.tools.runner import ToolRunner
from app.database.operations import create_scan, complete_scan, create_finding
from app.database.models import Finding
from app.core.logger import get_logger

logger = get_logger()

class VulnerabilityScanner:
    """Orchestrates vulnerability assessment tools and normalizes findings."""
    
    def __init__(self):
        self.nuclei_adapter = NucleiAdapter()
        self.nikto_adapter = NiktoAdapter()

    def scan(self, target: str, severity_filter: Optional[str] = None) -> Dict[str, Any]:
        """Run vulnerability assessment over target."""
        scan_id = create_scan("vulnerability", target, mode="SAFE_SCAN")
        logger.info(f"Starting vulnerability scan for {target} (Scan ID: {scan_id})")
        
        all_findings: List[Finding] = []
        raw_tools_used = []

        # 1. Run Nuclei if available
        if self.nuclei_adapter.is_available():
            try:
                cmd = self.nuclei_adapter.build_command(target, severity=severity_filter)
                code, out, err = ToolRunner.execute(cmd, timeout=120, target=target, tool_name="nuclei")
                parsed = self.nuclei_adapter.parse_output(out, code)
                raw_tools_used.append("Nuclei")
                
                for f_data in parsed.get("findings", []):
                    f_id = f"CW-VULN-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
                    f_obj = Finding(
                        id=f_id,
                        target=target,
                        vulnerability=f_data["vulnerability"],
                        severity=f_data["severity"],
                        evidence=f_data["evidence"],
                        confidence=f_data.get("confidence", "HIGH"),
                        source_tool="Nuclei",
                        cve=f_data.get("cve"),
                        cwe=f_data.get("cwe"),
                        remediation=f_data.get("remediation")
                    )
                    create_finding(f_obj)
                    all_findings.append(f_obj)
            except Exception as e:
                logger.error(f"Nuclei scan error: {e}")

        # 2. Run Nikto if web target and available
        if self.nikto_adapter.is_available() and (target.startswith("http://") or target.startswith("https://")):
            try:
                cmd = self.nikto_adapter.build_command(target)
                code, out, err = ToolRunner.execute(cmd, timeout=120, target=target, tool_name="nikto")
                parsed = self.nikto_adapter.parse_output(out, code)
                raw_tools_used.append("Nikto")
                
                for f_data in parsed.get("findings", []):
                    f_id = f"CW-NIKTO-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
                    f_obj = Finding(
                        id=f_id,
                        target=target,
                        vulnerability=f_data["vulnerability"],
                        severity=f_data["severity"],
                        evidence=f_data["evidence"],
                        confidence=f_data.get("confidence", "MEDIUM"),
                        source_tool="Nikto",
                        remediation=f_data.get("remediation")
                    )
                    create_finding(f_obj)
                    all_findings.append(f_obj)
            except Exception as e:
                logger.error(f"Nikto scan error: {e}")

        complete_scan(scan_id, "COMPLETED", findings_count=len(all_findings))
        return {
            "scan_id": scan_id,
            "target": target,
            "tools_executed": raw_tools_used if raw_tools_used else ["Native Vulnerability Engine"],
            "findings_count": len(all_findings),
            "findings": [vars(f) for f in all_findings]
        }
