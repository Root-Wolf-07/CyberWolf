"""CYBERWOLF Unified Scan Pipeline Service (V2).

Implements the canonical end-to-end security assessment orchestration pipeline:
Target -> Validate -> Authorize -> Policy -> Discover Assets -> Execute Tools ->
Collect Raw Results -> Parse -> Normalize -> Deduplicate -> Correlate ->
Score Risk -> Store Evidence -> Generate Reports -> Results Deliverable
"""

import time
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime

from app.security.sanitizer import parse_and_validate_target
from app.security.authorization import AuthorizationEngine
from app.security.policies import PolicyEngine
from app.detection.normalizer import get_normalizer
from app.detection.deduplicator import get_deduplicator
from app.detection.correlator import get_correlator
from app.detection.risk_engine import get_risk_engine
from app.evidence.vault import get_evidence_vault
from app.reports.generator import ReportGenerator
from app.database.operations import (
    create_scan, complete_scan, get_scan, get_all_scans,
    cancel_scan, upsert_asset, upsert_host, upsert_port,
    create_finding
)
from app.database.models import Finding, ScanStatus
from app.core.logger import get_logger, audit_log
from app.core.exceptions import (
    TargetValidationError, AuthorizationError, PolicyViolationError,
    ToolExecutionError
)

# Adapters
from app.tools.adapters.nmap_adapter import NmapAdapter
from app.tools.adapters.nuclei_adapter import NucleiAdapter
from app.tools.adapters.nikto_adapter import NiktoAdapter
from app.tools.adapters.ffuf_adapter import FfufAdapter
from app.tools.adapters.tshark_adapter import TsharkAdapter

# Native scanner fallback engines
from app.scanners.network_scanner import NetworkScanner
from app.scanners.web_scanner import WebScanner
from app.scanners.sqli_scanner import SQLiScanner
from app.scanners.bug_analyzer import BugAnalyzer

logger = get_logger()


class ScanService:
    """Canonical assessment orchestration pipeline serving CLI, API, and Dashboard."""

    def __init__(self):
        self.auth_engine = AuthorizationEngine()
        self.policy_engine = PolicyEngine()
        self.normalizer = get_normalizer()
        self.deduplicator = get_deduplicator()
        self.correlator = get_correlator()
        self.risk_engine = get_risk_engine()
        self.vault = get_evidence_vault()
        self.report_gen = ReportGenerator()

        # Adapters
        self.nmap = NmapAdapter()
        self.nuclei = NucleiAdapter()
        self.nikto = NiktoAdapter()
        self.ffuf = FfufAdapter()
        self.tshark = TsharkAdapter()

        self.scan_progress: Dict[str, Dict[str, Any]] = {}
        self.latest_scan_id: Optional[str] = None

    def _init_progress(self, scan_id: str, target: str, scan_type: str):
        self.latest_scan_id = scan_id
        self.scan_progress[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "RUNNING",
            "status_text": "Assessment in progress...",
            "steps": [
                {"label": "Target validated", "completed": False},
                {"label": "Authorization verified", "completed": False},
                {"label": "Asset identified", "completed": False},
                {"label": "Ports/services discovered", "completed": False},
                {"label": "Web endpoints discovered", "completed": False},
                {"label": "Security checks executed", "completed": False},
                {"label": "Findings normalized", "completed": False},
                {"label": "Evidence captured", "completed": False},
                {"label": "Findings correlated", "completed": False},
                {"label": "Risk calculated", "completed": False}
            ]
        }

    def _mark_progress_step(self, scan_id: str, label: str):
        if scan_id in self.scan_progress:
            for s in self.scan_progress[scan_id]["steps"]:
                if s["label"] == label:
                    s["completed"] = True

    def _complete_progress(self, scan_id: str, findings_count: int = 0, status: str = "COMPLETED"):
        if scan_id in self.scan_progress:
            self.scan_progress[scan_id]["status"] = status
            self.scan_progress[scan_id]["status_text"] = "Assessment completed"
            self.scan_progress[scan_id]["findings_count"] = findings_count
            for s in self.scan_progress[scan_id]["steps"]:
                s["completed"] = True

    def get_scan_progress(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Return real live discovery activity progress."""
        sid = scan_id or self.latest_scan_id
        if sid and sid in self.scan_progress:
            return self.scan_progress[sid]

        recent = self.list_scans(limit=1)
        if recent:
            last = recent[0]
            is_comp = (last.get("status") or "").upper() == "COMPLETED"
            return {
                "scan_id": last.get("id"),
                "target": last.get("target"),
                "scan_type": last.get("scan_type"),
                "status": "COMPLETED" if is_comp else last.get("status"),
                "status_text": "Assessment completed" if is_comp else (last.get("status") or "IDLE"),
                "findings_count": last.get("findings_count", 0),
                "steps": [
                    {"label": "Target validated", "completed": is_comp},
                    {"label": "Authorization verified", "completed": is_comp},
                    {"label": "Asset identified", "completed": is_comp},
                    {"label": "Ports/services discovered", "completed": is_comp},
                    {"label": "Web endpoints discovered", "completed": is_comp},
                    {"label": "Security checks executed", "completed": is_comp},
                    {"label": "Findings normalized", "completed": is_comp},
                    {"label": "Evidence captured", "completed": is_comp},
                    {"label": "Findings correlated", "completed": is_comp},
                    {"label": "Risk calculated", "completed": is_comp}
                ]
            }

        return {
            "scan_id": None,
            "target": None,
            "status": "IDLE",
            "status_text": "Awaiting target submission",
            "findings_count": 0,
            "steps": [
                {"label": "Target validated", "completed": False},
                {"label": "Authorization verified", "completed": False},
                {"label": "Asset identified", "completed": False},
                {"label": "Ports/services discovered", "completed": False},
                {"label": "Web endpoints discovered", "completed": False},
                {"label": "Security checks executed", "completed": False},
                {"label": "Findings normalized", "completed": False},
                {"label": "Evidence captured", "completed": False},
                {"label": "Findings correlated", "completed": False},
                {"label": "Risk calculated", "completed": False}
            ]
        }

    def start_scan(self, target: str, scan_type: str = "network",
                   options: Optional[Dict[str, Any]] = None,
                   interactive_auth: bool = False,
                   scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute the complete deterministic scan pipeline."""
        opts = options or {}
        start_time_ts = time.time()

        # 1. Target Validation
        parsed_target = parse_and_validate_target(target)
        clean_target = parsed_target.normalized
        target_host = parsed_target.host

        # 2. Authorization Check
        is_auth, auth_msg, scope = self.auth_engine.check_target_scope(clean_target, scan_type)
        if not is_auth:
            if interactive_auth:
                if not self.auth_engine.require_authorization_interactive(clean_target, scan_type):
                    raise AuthorizationError(
                        f"Target rejected. Reason: Target '{clean_target}' is outside authorized scope and consent was not granted.",
                        remediation="Add target using 'cyberwolf target add' or obtain explicit written permission."
                    )
            else:
                raise AuthorizationError(
                    f"Target rejected. Reason: Target '{clean_target}' is outside authorized scope.",
                    remediation=auth_msg
                )

        # 3. Policy Validation
        action_cat = "port_scan" if scan_type == "network" else "general_assessment"
        is_policy_allowed, policy_msg = self.policy_engine.validate_action(action_cat)
        if not is_policy_allowed:
            raise PolicyViolationError(
                f"Policy Denied: {policy_msg}",
                remediation="Adjust active safety mode in config or switch to an allowed assessment mode."
            )

        active_policy = self.policy_engine.get_active_policy()

        # 4. Create Scan Session in Database
        actual_scan_id = create_scan(
            scan_type=scan_type,
            target=clean_target,
            mode=active_policy.name,
            authorization_status="AUTHORIZED",
            policy=active_policy.name,
            scan_id=scan_id
        )
        scan_id = actual_scan_id

        self._init_progress(scan_id, clean_target, scan_type)
        self._mark_progress_step(scan_id, "Target validated")
        self._mark_progress_step(scan_id, "Authorization verified")

        logger.info(f"Initialized assessment session {scan_id} for target {clean_target} [{scan_type}]")
        audit_log("SCAN_SESSION", "STARTED", target=clean_target, decision="APPROVED",
                  details=f"Scan ID: {scan_id}, Mode: {active_policy.name}")

        # 5. Discover / Upsert Asset
        asset_id = upsert_asset(
            target_identifier=clean_target,
            hostname=target_host if parsed_target.target_type == "hostname" else None,
            ip_address=target_host if parsed_target.target_type in ["ipv4", "ipv6"] else None,
            asset_type=parsed_target.target_type
        )
        self._mark_progress_step(scan_id, "Asset identified")

        all_findings: List[Finding] = []
        tools_executed: List[str] = []
        discovered_hosts: List[Dict[str, Any]] = []

        try:
            # 6. Execute Selected Tools and Collect Raw Results
            if scan_type in ["network", "full"]:
                ports_arg = opts.get("ports")
                if self.nmap.is_available():
                    tools_executed.append("Nmap")
                    code, out, err = self.nmap.execute(
                        clean_target,
                        options={"ports": ports_arg, "scan_type": opts.get("profile", "fast")},
                        timeout=active_policy.max_scan_duration,
                        scan_id=scan_id
                    )
                    # Evidence vault storage
                    self.vault.store_evidence(
                        target=clean_target,
                        tool_name="Nmap",
                        output_text=out,
                        command_used=f"nmap -T4 {clean_target}",
                        scan_id=scan_id
                    )
                    parsed_nmap = self.nmap.parse_output(out, code)
                    discovered_hosts.extend(parsed_nmap.get("hosts", []))
                    all_findings.extend(self.nmap.normalize_results(parsed_nmap, clean_target))
                else:
                    # Native high-concurrency socket fallback
                    tools_executed.append("Native Network Engine")
                    net_scanner = NetworkScanner()
                    res = net_scanner.scan(clean_target, port_spec=ports_arg)
                    discovered_hosts.extend(res.get("hosts", []))
                    for f in res.get("findings", []):
                        all_findings.append(self.normalizer.normalize(f, clean_target, "Native Network Engine"))

                self._mark_progress_step(scan_id, "Ports/services discovered")

            if scan_type in ["vulnerability", "vuln", "full"]:
                # Nuclei
                if self.nuclei.is_available():
                    tools_executed.append("Nuclei")
                    code, out, err = self.nuclei.execute(
                        clean_target,
                        options={"severity": opts.get("severity")},
                        timeout=active_policy.max_scan_duration,
                        scan_id=scan_id
                    )
                    self.vault.store_evidence(
                        target=clean_target,
                        tool_name="Nuclei",
                        output_text=out,
                        command_used=f"nuclei -u {clean_target}",
                        scan_id=scan_id
                    )
                    parsed_nuclei = self.nuclei.parse_output(out, code)
                    all_findings.extend(self.nuclei.normalize_results(parsed_nuclei, clean_target))

                # Nikto if web target
                if self.nikto.is_available() and (clean_target.startswith("http://") or clean_target.startswith("https://")):
                    tools_executed.append("Nikto")
                    code, out, err = self.nikto.execute(
                        clean_target,
                        options={},
                        timeout=active_policy.max_scan_duration,
                        scan_id=scan_id
                    )
                    self.vault.store_evidence(
                        target=clean_target,
                        tool_name="Nikto",
                        output_text=out,
                        command_used=f"nikto -h {clean_target}",
                        scan_id=scan_id
                    )
                    parsed_nikto = self.nikto.parse_output(out, code)
                    all_findings.extend(self.nikto.normalize_results(parsed_nikto, clean_target))

            if scan_type in ["web", "full"]:
                # Native web security header & cookie audit
                tools_executed.append("Native Web Engine")
                web_scanner = WebScanner()
                web_res = web_scanner.assess_url(clean_target)
                self._mark_progress_step(scan_id, "Web endpoints discovered")

                # Sensitive endpoint bug analyzer
                bug_analyzer = BugAnalyzer()
                bug_res = bug_analyzer.analyze(clean_target)
                for f in bug_res.get("findings", []):
                    all_findings.append(self.normalizer.normalize(f, clean_target, "CYBERWOLF Bug Engine"))

            self._mark_progress_step(scan_id, "Ports/services discovered")
            self._mark_progress_step(scan_id, "Web endpoints discovered")
            self._mark_progress_step(scan_id, "Security checks executed")
            self._mark_progress_step(scan_id, "Findings normalized")
            self._mark_progress_step(scan_id, "Evidence captured")

            # 7. Finding Deduplication
            deduped_findings = self.deduplicator.deduplicate(all_findings)

            # 8. Finding Correlation
            correlated_findings = self.correlator.correlate(deduped_findings, discovered_hosts)
            self._mark_progress_step(scan_id, "Findings correlated")

            # 9. Risk Scoring
            scored_findings = self.risk_engine.score_findings_batch(correlated_findings)
            self._mark_progress_step(scan_id, "Risk calculated")

            # Calculate asset risk
            asset_risk, risk_level = self.risk_engine.calculate_asset_risk(scored_findings)
            upsert_asset(target_identifier=clean_target, risk_score=asset_risk)

            # 10. Persist Findings & Discovered Hosts to Database
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in scored_findings:
                f.asset_id = asset_id
                f.target = clean_target
                create_finding(f)
                sev = f.severity.upper() if f.severity else "INFO"
                if sev in severity_counts:
                    severity_counts[sev] += 1

            for host in discovered_hosts:
                h_id = upsert_host(
                    ip=host.get("ip", clean_target),
                    hostname=host.get("hostname"),
                    os_name=host.get("os_name"),
                    asset_id=asset_id
                )
                for p in host.get("ports", []):
                    upsert_port(
                        host_id=h_id,
                        port_number=p.get("port"),
                        protocol=p.get("protocol", "tcp"),
                        state=p.get("state", "open"),
                        service_name=p.get("service"),
                        service_product=p.get("product"),
                        service_version=p.get("version"),
                        banner=p.get("banner")
                    )

            # 11. Generate Deliverable Reports (HTML, PDF, JSON, CSV)
            reports = self.report_gen.generate_all_formats(
                target=clean_target,
                title=f"CYBERWOLF Security Assessment - {clean_target}",
                scan_id=scan_id
            )

            # 12. Complete Scan Session
            duration = round(time.time() - start_time_ts, 2)
            summary_dict = {
                "scan_id": scan_id,
                "target": clean_target,
                "status": ScanStatus.COMPLETED,
                "duration_seconds": duration,
                "tools_executed": tools_executed,
                "hosts_discovered": len(discovered_hosts),
                "findings_count": len(scored_findings),
                "severity_counts": severity_counts,
                "asset_risk_score": asset_risk,
                "reports": reports
            }

            complete_scan(
                scan_id=scan_id,
                status=ScanStatus.COMPLETED,
                summary=summary_dict,
                findings_count=len(scored_findings),
                severity_counts=severity_counts,
                tools_executed=tools_executed
            )

            self._complete_progress(scan_id, len(scored_findings))

            audit_log("SCAN_SESSION", "COMPLETED", target=clean_target, decision="COMPLETED",
                      details=f"Duration: {duration}s, Findings: {len(scored_findings)}")

            return summary_dict

        except Exception as e:
            if scan_id in self.scan_progress:
                self.scan_progress[scan_id]["status"] = "FAILED"
                self.scan_progress[scan_id]["status_text"] = f"Assessment failed: {str(e)}"
            logger.error(f"Scan session {scan_id} failed: {e}")
            complete_scan(scan_id=scan_id, status=ScanStatus.FAILED, summary={"error": str(e)})
            audit_log("SCAN_SESSION", "FAILED", target=clean_target, decision="FAILED", details=str(e))
            raise

    def cancel_scan(self, scan_id: str, reason: str = "Operator cancellation") -> bool:
        """Cancel a running scan."""
        return cancel_scan(scan_id, reason=reason)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan record by ID."""
        return get_scan(scan_id)

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent scans."""
        return get_all_scans(limit=limit)

    def get_status(self) -> Dict[str, Any]:
        """Retrieve operational engine status."""
        from app.database.operations import get_database_status
        from app.ai.ollama_client import get_ollama_client
        ollama = get_ollama_client()
        return {
            "status": "READY",
            "active_mode": self.policy_engine.get_active_policy().name,
            "database": get_database_status(),
            "ai_online": ollama.is_online(),
            "active_model": ollama.get_active_model() if ollama.is_online() else None
        }


_SCAN_SERVICE: Optional[ScanService] = None

def get_scan_service() -> ScanService:
    global _SCAN_SERVICE
    if _SCAN_SERVICE is None:
        _SCAN_SERVICE = ScanService()
    return _SCAN_SERVICE
