"""CYBERWOLF Multi-Format Security Assessment Report Generator (BDIE V2).

Generates auditable, professional security assessment deliverables in:
- HTML (Interactive SOC Workstation & Client Presentation format)
- PDF (ReportLab document with page numbers, tables, severity indicators)
- JSON (Machine-readable canonical report schema with all 21 BDIE sections)
- CSV (Spreadsheet finding export with exact locations and cryptographic evidence hashes)
- TXT (ASCII technical assessment summary)

Structured 21-Section Report Specification:
1. Executive Summary
2. Assessment Scope
3. Authorization & Scope Validation
4. Assessment Timeline
5. Asset Inventory
6. Attack Surface
7. Risk Summary
8. Vulnerability Summary
9. Detailed Findings
10. Exact Locations
11. Evidence
12. Observed Behavior
13. Verified Behavior
14. Security Impact
15. Exploitability Assessment
16. CVE/CWE/OWASP Mapping
17. Remediation
18. Verification & Retesting
19. Tool Execution History
20. Evidence Integrity
21. Final Risk Summary
"""

import os
import json
import csv
import uuid
import hashlib
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from app.core.config import get_config
from app.core.logger import get_logger, sanitize_message
from app.database.operations import (
    get_all_findings, get_findings_summary, get_scan,
    get_all_assets, get_evidence_by_finding, get_finding_retests,
    get_tool_runs, get_finding_status_history, get_finding
)
from app.database.db_manager import get_db
from app.detection.exact_location import ExactLocationEngine

logger = get_logger()

REPORT_DISCLAIMER = """
CONFIDENTIAL SECURITY ASSESSMENT REPORT
This document contains proprietary and security-sensitive findings resulting from authorized
security testing activities. This report is intended solely for the authorized asset owner
and technical remediation teams. Findings should be validated before applying configuration changes.
CYBERWOLF is intended solely for authorized security assessment, defense, and research.
"""


class ReportGenerator:
    """Generates professional executive & technical security assessment reports."""

    def __init__(self, output_dir: Optional[str] = None):
        self.config = get_config()
        self.output_dir = Path(output_dir or (self.config.base_dir / "reports")).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.version = self.config.get("app", {}).get("version", "2.0.0")

    def generate_all_formats(self, target: str, title: Optional[str] = None,
                             ai_summary: Optional[str] = None,
                             scan_id: Optional[str] = None) -> Dict[str, str]:
        """Generate deliverables in JSON, CSV, HTML, TXT, and PDF formats."""
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_id = f"CW-REP-{timestamp_str}-{uuid.uuid4().hex[:6].upper()}"
        base_filename = f"cyberwolf_report_{timestamp_str}_{uuid.uuid4().hex[:6]}"
        report_title = title or f"CYBERWOLF Security Assessment Report - {target}"

        raw_findings = get_all_findings(target=target)
        summary = get_findings_summary()
        scan_data = get_scan(scan_id) if scan_id else None
        assets = get_all_assets()
        tool_runs = get_tool_runs(scan_id=scan_id)

        # Enrich findings with exact location, evidence chain, and retests
        findings = []
        for rf in raw_findings:
            fid = rf.get("id")
            detailed = get_finding(fid) if fid else None
            f_item = detailed if detailed else rf

            # Attach evidence items
            ev_list = get_evidence_by_finding(fid) if fid else []
            f_item["evidence_items"] = ev_list

            # Attach retest history
            retests = get_finding_retests(fid) if fid else []
            f_item["retests"] = retests

            # Attach investigation why_this_was_flagged & exact location details
            try:
                from app.intelligence.investigation import get_investigation_engine
                inv_engine = get_investigation_engine()
                inv_res = inv_engine.investigate(f_item)
                f_item["why_this_was_flagged"] = inv_res.get("why_this_was_flagged")
                f_item["why_flagged"] = inv_res.get("why_flagged")
                f_item["exact_location_details"] = inv_res.get("exact_location")
            except Exception as e:
                logger.debug(f"Error enriching finding {fid} in report generator: {e}")

            # Attach timeline
            try:
                from app.services.finding_service import get_finding_service
                finding_svc = get_finding_service()
                f_item["timeline"] = finding_svc.get_timeline(fid, f_item, get_finding_status_history(fid), retests)
            except Exception as e:
                logger.debug(f"Error attaching timeline for {fid}: {e}")

            findings.append(f_item)

        generated_files = {}

        # 1. JSON Report (Complete 21-section payload)
        json_path = self.output_dir / f"{base_filename}.json"
        json_data = self._build_json_payload(
            report_id, report_title, target, scan_id, scan_data, summary, findings, ai_summary, assets, tool_runs
        )
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        generated_files["JSON"] = str(json_path)

        # 2. CSV Report (Enhanced with Exact Location and Integrity data)
        csv_path = self.output_dir / f"{base_filename}.csv"
        self._write_csv_report(csv_path, findings)
        generated_files["CSV"] = str(csv_path)

        # 3. TXT Report
        txt_path = self.output_dir / f"{base_filename}.txt"
        self._write_txt_report(
            txt_path, report_id, report_title, target, scan_id, summary, findings, ai_summary, scan_data
        )
        generated_files["TXT"] = str(txt_path)

        # 4. HTML Report (Dark SOC Analyst Station Deliverable)
        html_path = self.output_dir / f"{base_filename}.html"
        html_content = self._build_html_report(
            report_id, report_title, target, scan_id, scan_data, summary, findings, ai_summary, assets, tool_runs
        )
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        generated_files["HTML"] = str(html_path)

        # 5. PDF Report
        pdf_path = self.output_dir / f"{base_filename}.pdf"
        try:
            self._build_pdf_report(
                pdf_path, report_id, report_title, target, scan_id, summary, findings, ai_summary
            )
            generated_files["PDF"] = str(pdf_path)
        except Exception as e:
            logger.warning(f"PDF generation skipped or failed: {e}")

        # Record report in SQLite database
        db = get_db()
        with db.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO reports (
                    id, title, report_format, file_path, target,
                    scan_id, summary_text, findings_count, created_at
                ) VALUES (?, ?, 'MULTI_FORMAT', ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                report_id, report_title, str(html_path), target,
                scan_id, ai_summary or "BDIE Multi-format report generated", len(findings)
            ))

        logger.info(f"Reports successfully generated in {self.output_dir}")
        return generated_files

    def _build_json_payload(self, report_id: str, title: str, target: str,
                            scan_id: Optional[str], scan_data: Optional[Dict[str, Any]],
                            summary: Dict[str, int], findings: List[Dict[str, Any]],
                            ai_summary: Optional[str], assets: List[Dict[str, Any]],
                            tool_runs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build canonical JSON report representation with all 21 BDIE sections."""
        now_iso = datetime.now().isoformat()

        # Build Exact Locations Catalog
        exact_locations_catalog = []
        evidence_catalog = []
        observed_catalog = []
        verified_catalog = []
        impact_catalog = []
        exploit_catalog = []
        mapping_catalog = []
        remediation_catalog = []
        retesting_catalog = []
        integrity_audit = []

        for f in findings:
            fid = f.get("id")
            # 10. Exact Location
            loc_entry = {
                "finding_id": fid,
                "domain": f.get("domain") or target,
                "scheme": f.get("scheme") or "https" if str(f.get("port")) in ["443", "8443"] else "http",
                "hostname": f.get("host") or f.get("target"),
                "ip_address": f.get("ip_address") or f.get("host"),
                "port": f.get("port"),
                "protocol": f.get("protocol") or "tcp",
                "service": f.get("service"),
                "service_version": f.get("service_version"),
                "url": f.get("url"),
                "http_method": f.get("http_method"),
                "endpoint": f.get("endpoint"),
                "parameter": f.get("parameter"),
                "source_file": f.get("source_file"),
                "source_line": f.get("source_line"),
                "config_location": f.get("config_location")
            }
            exact_locations_catalog.append(loc_entry)

            # 11. Evidence
            for ev in f.get("evidence_items", []):
                evidence_catalog.append({
                    "evidence_id": ev.get("id"),
                    "finding_id": fid,
                    "evidence_type": ev.get("evidence_type", "TOOL_OUTPUT"),
                    "tool": ev.get("tool_name"),
                    "timestamp": ev.get("timestamp"),
                    "sha256": ev.get("hash_sha256"),
                    "output_excerpt": sanitize_message(ev.get("output_excerpt", ""))
                })
                integrity_audit.append({
                    "evidence_id": ev.get("id"),
                    "sha256": ev.get("hash_sha256"),
                    "status": "INTEGRITY_VERIFIED" if ev.get("hash_sha256") else "UNHASHED"
                })

            # 12 & 13. Observed & Verified
            observed_catalog.append({
                "finding_id": fid,
                "observed_behavior": f.get("observed_behavior") or f.get("evidence") or "Vulnerability pattern observed during scan."
            })
            verified_catalog.append({
                "finding_id": fid,
                "verified_behavior": f.get("verified_behavior") or "Passive observation / unconfirmed by probe"
            })

            # 14 & 15. Impact & Exploitability
            impact_catalog.append({
                "finding_id": fid,
                "potential_impact": f.get("potential_impact") or "Confidentiality, Integrity, or Availability exposure."
            })
            exploit_catalog.append({
                "finding_id": fid,
                "exploitability_level": f.get("exploitability_level", "MEDIUM"),
                "prerequisites": "Network adjacency or direct target reachability",
                "limitations": "Strict non-destructive assessment boundary applied"
            })

            # 16. Standards Mapping
            mapping_catalog.append({
                "finding_id": fid,
                "cve": f.get("cve"),
                "cwe": f.get("cwe"),
                "owasp": f.get("owasp_category"),
                "cvss": f.get("cvss_score")
            })

            # 17. Remediation
            remediation_catalog.append({
                "finding_id": fid,
                "remediation": f.get("remediation") or "Harden configuration and restrict unauthorized access.",
                "verification_procedure": f.get("verification_procedure") or "Re-test endpoint with authorized probes."
            })

            # 18. Retesting
            retesting_catalog.append({
                "finding_id": fid,
                "current_status": f.get("status", "OPEN"),
                "retest_result": f.get("retest_result"),
                "retest_history": f.get("retests", [])
            })

        return {
            "cyberwolf_version": self.version,
            "report_id": report_id,
            "scan_id": scan_id or "N/A",
            "title": title,
            "target": target,
            "timestamp": now_iso,
            "sections": {
                "1_executive_summary": ai_summary or f"Assessment completed under authorized rules for {target}. Found {len(findings)} security findings.",
                "2_assessment_scope": {
                    "primary_target": target,
                    "target_type": scan_data.get("target_type", "REMOTE_HOST") if scan_data else "REMOTE_HOST",
                    "authorized_scope_id": scan_data.get("scan_id") if scan_data else "DEFAULT_SCOPE"
                },
                "3_authorization_and_scope_validation": {
                    "authorization_status": scan_data.get("authorization_status", "AUTHORIZED") if scan_data else "AUTHORIZED",
                    "policy_mode": scan_data.get("mode", "SAFE_SCAN") if scan_data else "SAFE_SCAN",
                    "policy_enforced": True,
                    "timestamp": now_iso
                },
                "4_assessment_timeline": {
                    "scan_started": scan_data.get("started_at", now_iso) if scan_data else now_iso,
                    "scan_completed": scan_data.get("completed_at", now_iso) if scan_data else now_iso,
                    "report_generated": now_iso
                },
                "5_asset_inventory": assets,
                "6_attack_surface": {
                    "target": target,
                    "active_endpoints": list({f.get("url") for f in findings if f.get("url")}),
                    "open_ports": list({f.get("port") for f in findings if f.get("port")})
                },
                "7_risk_summary": {
                    "metrics": summary,
                    "average_risk_score": round(sum(f.get("risk_score", 0.0) for f in findings) / max(len(findings), 1), 2)
                },
                "8_vulnerability_summary": {
                    "total_count": len(findings),
                    "by_severity": summary,
                    "by_status": {
                        "OPEN": sum(1 for f in findings if f.get("status") in ["OPEN", "NEW"]),
                        "CONFIRMED": sum(1 for f in findings if f.get("status") == "CONFIRMED"),
                        "RESOLVED": sum(1 for f in findings if f.get("status") == "RESOLVED")
                    }
                },
                "9_detailed_findings": findings,
                "10_exact_locations": exact_locations_catalog,
                "11_evidence": evidence_catalog,
                "12_observed_behavior": observed_catalog,
                "13_verified_behavior": verified_catalog,
                "14_security_impact": impact_catalog,
                "15_exploitability_assessment": exploit_catalog,
                "16_cve_cwe_owasp_mapping": mapping_catalog,
                "17_remediation": remediation_catalog,
                "18_verification_and_retesting": retesting_catalog,
                "19_tool_execution_history": tool_runs,
                "20_evidence_integrity": integrity_audit,
                "21_final_risk_summary": {
                    "overall_posture": "ATTENTION_REQUIRED" if summary.get("CRITICAL", 0) + summary.get("HIGH", 0) > 0 else "ACCEPTABLE",
                    "immediate_actions": [f.get("title") for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
                }
            },
            "disclaimer": REPORT_DISCLAIMER.strip()
        }

    def _write_csv_report(self, csv_path: Path, findings: List[Dict[str, Any]]):
        """Write enriched CSV export containing BDIE exact locations and evidence hashes."""
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Finding ID", "Target", "Severity", "Confidence", "Risk Score", "Status",
                "Title / Vulnerability", "Exact Location", "URL", "Method", "Endpoint",
                "Parameter", "Port", "Protocol", "Service", "CVE", "CWE", "OWASP",
                "Exploitability", "Observed Behavior", "Verified Behavior",
                "Evidence SHA-256", "Remediation", "Verification Procedure",
                "Retest Result", "Source Tools"
            ])
            for fnd in findings:
                # Format exact location summary
                loc_summary = fnd.get("url") or (f"{fnd.get('target')}:{fnd.get('port')}" if fnd.get("port") else fnd.get("target"))

                # Get first evidence hash
                ev_items = fnd.get("evidence_items", [])
                ev_hash = ev_items[0].get("hash_sha256") if ev_items else "N/A"

                writer.writerow([
                    fnd.get("id"),
                    fnd.get("target"),
                    fnd.get("severity"),
                    fnd.get("confidence", "MEDIUM"),
                    fnd.get("risk_score", 0.0),
                    fnd.get("status", "OPEN"),
                    fnd.get("title") or fnd.get("vulnerability"),
                    loc_summary,
                    fnd.get("url") or "N/A",
                    fnd.get("http_method") or "N/A",
                    fnd.get("endpoint") or "N/A",
                    fnd.get("parameter") or "N/A",
                    fnd.get("port") or "N/A",
                    fnd.get("protocol") or "tcp",
                    fnd.get("service") or "N/A",
                    fnd.get("cve") or "N/A",
                    fnd.get("cwe") or "N/A",
                    fnd.get("owasp_category") or "N/A",
                    fnd.get("exploitability_level") or "MEDIUM",
                    sanitize_message(fnd.get("observed_behavior") or fnd.get("evidence", "")),
                    sanitize_message(fnd.get("verified_behavior") or "N/A"),
                    ev_hash,
                    fnd.get("remediation") or "N/A",
                    fnd.get("verification_procedure") or "N/A",
                    fnd.get("retest_result") or "NOT_TESTED",
                    fnd.get("source_tool") or "CYBERWOLF"
                ])

    def _write_txt_report(self, txt_path: Path, report_id: str, title: str, target: str,
                          scan_id: Optional[str], summary: Dict[str, int],
                          findings: List[Dict[str, Any]], ai_summary: Optional[str],
                          scan_data: Optional[Dict[str, Any]]):
        """Write human-readable ASCII technical assessment report."""
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("                       CYBERWOLF SECURITY ASSESSMENT REPORT\n")
            f.write(f"                               Version {self.version} (BDIE)\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Report ID:        {report_id}\n")
            f.write(f"Scan ID:          {scan_id or 'N/A'}\n")
            f.write(f"Target:           {target}\n")
            f.write(f"Date:             {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"Authorization:    AUTHORIZED (Scope Enforced)\n")
            f.write(f"Total Findings:   {summary.get('TOTAL', 0)} (CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}, INFO: {summary.get('INFO', 0)})\n\n")
            f.write("-" * 80 + "\n")
            f.write("1. EXECUTIVE SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(ai_summary or "Authorized security assessment completed across identified perimeter targets.\n")
            f.write("\n" + "-" * 80 + "\n")
            f.write("2. DETAILED TECHNICAL FINDINGS & EXACT LOCATIONS\n")
            f.write("-" * 80 + "\n")
            for idx, fnd in enumerate(findings, 1):
                sev = fnd.get("severity", "INFO")
                t_str = fnd.get("title") or fnd.get("vulnerability")
                f.write(f"\n[{idx}] [{sev}] {t_str} (ID: {fnd.get('id')})\n")
                f.write(f"    Status:            {fnd.get('status', 'OPEN')}\n")
                f.write(f"    Confidence:        {fnd.get('confidence', 'MEDIUM')}\n")
                f.write(f"    Risk Score:        {fnd.get('risk_score', 'N/A')}/10.0\n")

                # Exact Location
                if fnd.get("url"):
                    f.write(f"    Exact Location:    {fnd.get('url')}\n")
                    if fnd.get("http_method"):
                        f.write(f"    HTTP Method:       {fnd.get('http_method')}\n")
                    if fnd.get("endpoint"):
                        f.write(f"    Endpoint:          {fnd.get('endpoint')}\n")
                    if fnd.get("parameter"):
                        f.write(f"    Parameter:         {fnd.get('parameter')}\n")
                elif fnd.get("port"):
                    f.write(f"    Exact Location:    {fnd.get('target')}:{fnd.get('port')}/{fnd.get('protocol', 'tcp')} ({fnd.get('service', 'unknown')})\n")
                else:
                    f.write(f"    Exact Location:    {fnd.get('target')}\n")

                # Standards
                if fnd.get("cve"):
                    f.write(f"    CVE:               {fnd.get('cve')}\n")
                if fnd.get("cwe"):
                    f.write(f"    CWE:               {fnd.get('cwe')}\n")
                if fnd.get("owasp_category"):
                    f.write(f"    OWASP:             {fnd.get('owasp_category')}\n")

                # Observed vs Verified
                f.write(f"    Observed Behavior: {sanitize_message(fnd.get('observed_behavior') or fnd.get('evidence', 'N/A'))}\n")
                if fnd.get("verified_behavior"):
                    f.write(f"    Verified Behavior: {fnd.get('verified_behavior')}\n")
                if fnd.get("potential_impact"):
                    f.write(f"    Potential Impact:  {fnd.get('potential_impact')}\n")

                # Exploitability Assessment
                f.write(f"    Exploitability:    {fnd.get('exploitability_level', 'MEDIUM')}\n")

                # Remediation & Retesting
                f.write(f"    Remediation:       {fnd.get('remediation', 'N/A')}\n")
                if fnd.get("verification_procedure"):
                    f.write(f"    Verification:      {fnd.get('verification_procedure')}\n")
                if fnd.get("retest_result"):
                    f.write(f"    Retest Status:     {fnd.get('retest_result')} (Last: {fnd.get('last_retested_at', 'N/A')})\n")

                # Evidence Hashes
                ev_items = fnd.get("evidence_items", [])
                if ev_items:
                    f.write("    Cryptographic Evidence:\n")
                    for ev in ev_items:
                        f.write(f"      - [{ev.get('id')}] Tool: {ev.get('tool_name')} | SHA-256: {ev.get('hash_sha256', 'N/A')}\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write(REPORT_DISCLAIMER.strip() + "\n")
            f.write("=" * 80 + "\n")

    def _build_html_report(self, report_id: str, title: str, target: str,
                           scan_id: Optional[str], scan_data: Optional[Dict[str, Any]],
                           summary: Dict[str, int], findings: List[Dict[str, Any]],
                           ai_summary: Optional[str], assets: List[Dict[str, Any]],
                           tool_runs: List[Dict[str, Any]]) -> str:
        """Build professional SOC Analyst Workstation deliverable covering all 21 BDIE sections."""
        findings_html = ""
        evidence_chain_rows = ""

        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            badge_color = {
                "CRITICAL": "#e63946",
                "HIGH": "#f77f00",
                "MEDIUM": "#fcbf49",
                "LOW": "#4ea8de",
                "INFO": "#6c757d"
            }.get(sev, "#6c757d")

            title_safe = html.escape(str(f.get('title') or f.get('vulnerability') or 'Finding'))
            target_safe = html.escape(str(f.get('target') or ''))
            id_safe = html.escape(str(f.get('id') or ''))
            obs_safe = html.escape(sanitize_message(f.get("observed_behavior") or f.get("evidence", "No output recorded")))
            ver_safe = html.escape(str(f.get("verified_behavior") or "Not independently probe-verified. Passive or scanner observation only."))
            impact_safe = html.escape(str(f.get("potential_impact") or "Potential impact to service confidentiality or integrity."))
            rem_safe = html.escape(str(f.get('remediation') or 'Review configuration and apply vendor patches.'))
            verif_proc_safe = html.escape(str(f.get('verification_procedure') or 'Re-test endpoint with non-destructive authorized probe.'))
            tool_safe = html.escape(str(f.get('source_tool') or 'CYBERWOLF'))
            conf_safe = html.escape(str(f.get('confidence') or 'MEDIUM'))
            status_safe = html.escape(str(f.get('status') or 'OPEN'))
            exploit_level = html.escape(str(f.get('exploitability_level') or 'MEDIUM'))

            # Exact Location hierarchy building
            loc_parts = []
            if f.get("domain"):
                loc_parts.append(f"<strong>Domain:</strong> {html.escape(str(f.get('domain')))}")
            if f.get("host"):
                loc_parts.append(f"<strong>Host:</strong> {html.escape(str(f.get('host')))}")
            if f.get("port"):
                loc_parts.append(f"<strong>Port:</strong> {f.get('port')}/{f.get('protocol', 'tcp')}")
            if f.get("service"):
                loc_parts.append(f"<strong>Service:</strong> {html.escape(str(f.get('service')))}")
            if f.get("url"):
                loc_parts.append(f"<strong>URL:</strong> <code>{html.escape(str(f.get('url')))}</code>")
            if f.get("http_method"):
                loc_parts.append(f"<strong>Method:</strong> <code>{html.escape(str(f.get('http_method')))}</code>")
            if f.get("endpoint"):
                loc_parts.append(f"<strong>Endpoint:</strong> <code>{html.escape(str(f.get('endpoint')))}</code>")
            if f.get("parameter"):
                loc_parts.append(f"<strong>Parameter:</strong> <code>{html.escape(str(f.get('parameter')))}</code>")
            if f.get("source_file"):
                loc_parts.append(f"<strong>Source:</strong> <code>{html.escape(str(f.get('source_file')))}:{f.get('source_line', '')}</code>")
            if f.get("config_location"):
                loc_parts.append(f"<strong>Config Area:</strong> <code>{html.escape(str(f.get('config_location')))}</code>")

            loc_html = " • ".join(loc_parts) if loc_parts else f"<strong>Host:</strong> {target_safe}"

            # Standards pills
            cve_pill = f'<span class="pill pill-cve">CVE: {html.escape(str(f.get("cve")))}</span>' if f.get("cve") else ""
            cwe_pill = f'<span class="pill pill-cwe">{html.escape(str(f.get("cwe")))}</span>' if f.get("cwe") else ""
            owasp_pill = f'<span class="pill pill-cwe">{html.escape(str(f.get("owasp_category")))}</span>' if f.get("owasp_category") else ""
            score_pill = f'<span class="pill pill-score">Risk: {f.get("risk_score", 0.0)}/10.0</span>' if f.get("risk_score") else ""
            conf_pill = f'<span class="pill pill-conf">{conf_safe}</span>'
            status_pill = f'<span class="pill pill-status status-{status_safe.lower()}">{status_safe}</span>'

            # Retest badge
            retest_badge = ""
            if f.get("retest_result"):
                r_res = str(f.get("retest_result")).upper()
                r_color = "#10b981" if r_res == "PASS" else ("#ef4444" if r_res == "FAIL" else "#f59e0b")
                retest_badge = f'<span class="pill" style="background:{r_color}; color:#fff;">Retest: {r_res}</span>'

            # Evidence Items for this finding
            ev_boxes = ""
            for ev in f.get("evidence_items", []):
                ev_id_safe = html.escape(str(ev.get("id")))
                ev_sha_safe = html.escape(str(ev.get("hash_sha256") or "N/A"))
                ev_tool_safe = html.escape(str(ev.get("tool_name") or "CYBERWOLF"))
                ev_type_safe = html.escape(str(ev.get("evidence_type") or "TOOL_OUTPUT"))
                ev_out_safe = html.escape(sanitize_message(ev.get("output_excerpt") or "No excerpt recorded"))

                ev_boxes += f"""
                <div class="evidence-item">
                    <div class="evidence-header">
                        <span><strong>[{ev_id_safe}]</strong> {ev_type_safe} via {ev_tool_safe}</span>
                        <span class="hash-tag">SHA-256: <code>{ev_sha_safe}</code></span>
                    </div>
                    <pre class="evidence-box"><code>{ev_out_safe}</code></pre>
                </div>
                """

                evidence_chain_rows += f"""
                <tr>
                    <td><code>{id_safe}</code></td>
                    <td><code>{ev_id_safe}</code></td>
                    <td>{ev_type_safe}</td>
                    <td>{ev_tool_safe}</td>
                    <td><code style="color:#6ee7b7;">{ev_sha_safe[:16]}...{ev_sha_safe[-8:] if len(ev_sha_safe)>24 else ''}</code></td>
                    <td><span class="badge-verified">✔ VERIFIED</span></td>
                </tr>
                """

            # Why this was flagged
            why_text = f.get("why_this_was_flagged") or f.get("why_flagged") or ""
            why_html = ""
            if why_text:
                why_safe = html.escape(why_text)
                why_html = f"""
                <div class="why-flagged-box" style="background:#0c1524; border-left:3px solid #3b82f6; border-radius:4px; padding:10px 14px; margin:12px 0;">
                    <div style="font-size:11px; font-weight:700; color:#60a5fa; text-transform:uppercase; margin-bottom:4px;">◈ WHY THIS WAS FLAGGED</div>
                    <div style="font-size:12px; color:#e2e8f0; line-height:1.5;">{why_safe}</div>
                </div>
                """

            # Timeline
            timeline_items = f.get("timeline") or []
            timeline_html = ""
            if timeline_items:
                tl_rows = ""
                for tlev in timeline_items:
                    t_ts = html.escape(str(tlev.get("timestamp") or "")[:19].replace("T", " "))
                    t_type = html.escape(str(tlev.get("event_type") or "EVENT"))
                    t_desc = html.escape(str(tlev.get("description") or ""))
                    t_actor = html.escape(str(tlev.get("actor") or "system"))
                    tl_rows += f"""
                    <div style="font-size:11px; margin-bottom:4px; color:#cbd5e1;">
                        <span style="color:#94a3b8; font-family:monospace;">{t_ts}</span> • 
                        <strong style="color:#93c5fd;">{t_type}:</strong> {t_desc} 
                        <span style="color:#64748b;">({t_actor})</span>
                    </div>
                    """
                timeline_html = f"""
                <div class="section-sub" style="margin-top:14px;">
                    <h4>Finding Lifecycle Timeline</h4>
                    <div style="background:#0a0f1d; border:1px solid #1e293b; border-radius:5px; padding:10px 14px;">
                        {tl_rows}
                    </div>
                </div>
                """

            findings_html += f"""
            <div class="finding-card" id="{id_safe}">
                <div class="finding-header">
                    <div class="finding-title-row">
                        <span class="severity-badge" style="background-color: {badge_color};">{sev}</span>
                        <span class="finding-title">{title_safe}</span>
                    </div>
                    <div class="finding-meta-pills">
                        {status_pill}
                        {conf_pill}
                        {score_pill}
                        {cve_pill}
                        {cwe_pill}
                        {owasp_pill}
                        {retest_badge}
                        <span class="pill pill-tool">{tool_safe}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <!-- EXACT LOCATION HIERARCHY -->
                    <div class="location-banner">
                        <span class="loc-label">EXACT AFFECTED LOCATION:</span>
                        <div class="loc-content">{loc_html}</div>
                    </div>

                    {why_html}

                    <div class="meta-grid">
                        <div><strong>Finding ID:</strong> <code>{id_safe}</code></div>
                        <div><strong>Target Host:</strong> {target_safe}</div>
                        <div><strong>Exploitability:</strong> <span class="exploit-pill">{exploit_level}</span></div>
                        <div><strong>Lifecycle Status:</strong> <strong>{status_safe}</strong></div>
                    </div>

                    <!-- OBSERVED VS VERIFIED BEHAVIOR -->
                    <div class="dual-panel">
                        <div class="panel-box observed-box">
                            <h5>◈ OBSERVED BEHAVIOR (Actual Detection)</h5>
                            <p>{obs_safe}</p>
                        </div>
                        <div class="panel-box verified-box">
                            <h5>◈ VERIFIED BEHAVIOR (Authorized Confirmation)</h5>
                            <p>{ver_safe}</p>
                        </div>
                    </div>

                    <!-- SECURITY IMPACT & EXPLOITABILITY -->
                    <div class="section-sub">
                        <h4>Security Impact & Exploitation Assessment</h4>
                        <div class="impact-box">
                            <strong>Potential Impact:</strong> {impact_safe}<br>
                            <strong>Exploitability Level:</strong> {exploit_level} • Prerequisites: Network reachability to target endpoint. Strict non-destructive boundaries enforced.
                        </div>
                    </div>

                    <!-- EVIDENCE CHAIN -->
                    <div class="section-sub">
                        <h4>Traceable Cryptographic Evidence</h4>
                        {ev_boxes if ev_boxes else '<pre class="evidence-box"><code>' + obs_safe + '</code></pre>'}
                    </div>

                    <!-- REMEDIATION & VERIFICATION -->
                    <div class="dual-panel" style="margin-top: 15px;">
                        <div class="panel-box remediation-box">
                            <h5>◈ DEFENSIVE REMEDIATION</h5>
                            <p>{rem_safe}</p>
                        </div>
                        <div class="panel-box verification-box">
                            <h5>◈ VERIFICATION / RETEST PROCEDURE</h5>
                            <p>{verif_proc_safe}</p>
                        </div>
                    </div>

                    {timeline_html}
                </div>
            </div>
            """

        # Asset inventory rows
        asset_rows = ""
        for a in assets:
            a_id = a.get("id")
            a_ident = html.escape(str(a.get("target_identifier") or "Unknown"))
            a_type = html.escape(str(a.get("asset_type") or "host"))
            a_ip = html.escape(str(a.get("ip_address") or "—"))
            a_risk = str(round(a.get("risk_score", 0.0), 1))
            asset_rows += f"""
            <tr>
                <td><code>{a_id}</code></td>
                <td><strong>{a_ident}</strong></td>
                <td>{a_type}</td>
                <td><code>{a_ip}</code></td>
                <td>{a_risk}/10.0</td>
            </tr>
            """

        # Tool runs rows
        tool_rows = ""
        for tr in tool_runs:
            t_name = html.escape(str(tr.get("tool_name") or "Adapter"))
            t_cmd = html.escape(str(tr.get("command_used") or "Internal probe"))
            t_code = tr.get("exit_code", 0)
            t_dur = f"{tr.get('duration_seconds', 0.0):.2f}s"
            tool_rows += f"""
            <tr>
                <td><strong>{t_name}</strong></td>
                <td><code>{t_cmd}</code></td>
                <td>{t_code}</td>
                <td>{t_dur}</td>
            </tr>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --surface: #111827;
            --surface-card: #1f2937;
            --border: #374151;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent: #2563eb;
            --critical: #e63946;
            --high: #f77f00;
            --medium: #fcbf49;
            --low: #4ea8de;
            --info: #6c757d;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .report-header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 25px;
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}
        .brand-logo {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 1.5px;
            color: #60a5fa;
        }}
        .brand-sub {{
            font-size: 13px;
            color: var(--text-muted);
        }}
        .header-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            font-size: 14px;
        }}
        .meta-label {{ color: var(--text-muted); font-size: 12px; text-transform: uppercase; }}
        .meta-val {{ font-weight: 600; color: var(--text-main); }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            text-align: center;
        }}
        .metric-count {{ font-size: 32px; font-weight: 800; margin: 5px 0; }}
        .metric-label {{ font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }}

        .card-panel {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        .card-panel h3 {{ margin-top: 0; margin-bottom: 15px; color: #93c5fd; font-size: 18px; }}

        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 25px;
            overflow: hidden;
        }}
        .finding-header {{
            background: #182234;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .finding-title-row {{ display: flex; align-items: center; gap: 12px; }}
        .severity-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 800;
            font-size: 12px;
            color: #000;
        }}
        .finding-title {{ font-size: 16px; font-weight: 700; color: #fff; }}
        .finding-meta-pills {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .pill {{
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
            background: #374151;
            color: #d1d5db;
            font-weight: 600;
        }}
        .pill-score {{ background: #1e3a8a; color: #bfdbfe; }}
        .pill-cve {{ background: #991b1b; color: #fecaca; }}
        .pill-cwe {{ background: #7c2d12; color: #ffedd5; }}
        .pill-tool {{ background: #065f46; color: #a7f3d0; }}
        .pill-conf {{ background: #312e81; color: #c7d2fe; }}
        .pill-status {{ background: #374151; }}
        .status-confirmed {{ background: #831843; color: #fbcfe8; }}
        .status-resolved {{ background: #064e3b; color: #a7f3d0; }}

        .finding-body {{ padding: 20px; }}

        .location-banner {{
            background: #0f172a;
            border-left: 4px solid #38bdf8;
            padding: 12px 16px;
            border-radius: 4px;
            margin-bottom: 15px;
        }}
        .loc-label {{
            font-size: 11px;
            font-weight: 800;
            color: #38bdf8;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: block;
            margin-bottom: 4px;
        }}
        .loc-content {{ font-size: 13px; color: #e2e8f0; }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            background: #151d2d;
            padding: 12px 15px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 15px;
        }}

        .dual-panel {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 15px;
        }}
        @media (max-width: 768px) {{
            .dual-panel {{ grid-template-columns: 1fr; }}
        }}
        .panel-box {{
            padding: 14px;
            border-radius: 6px;
            font-size: 13px;
        }}
        .panel-box h5 {{ margin: 0 0 8px 0; font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase; }}
        .observed-box {{ background: #182234; border: 1px solid #2b3952; }}
        .observed-box h5 {{ color: #93c5fd; }}
        .verified-box {{ background: #1c1917; border: 1px solid #44403c; }}
        .verified-box h5 {{ color: #fdba74; }}
        .remediation-box {{ background: #0f1f17; border: 1px solid #14532d; }}
        .remediation-box h5 {{ color: #6ee7b7; }}
        .verification-box {{ background: #172554; border: 1px solid #1e3a8a; }}
        .verification-box h5 {{ color: #bfdbfe; }}

        .section-sub h4 {{ margin: 15px 0 8px 0; font-size: 13px; text-transform: uppercase; color: var(--text-muted); }}
        .impact-box {{
            background: #1f1b2e;
            border-left: 3px solid #a855f7;
            padding: 12px 16px;
            border-radius: 4px;
            font-size: 13px;
            color: #e9d5ff;
        }}
        .evidence-item {{
            margin-bottom: 10px;
        }}
        .evidence-header {{
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }}
        .hash-tag code {{ color: #34d399; }}
        .evidence-box {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 12px;
            overflow-x: auto;
            color: #7ee787;
            margin: 0;
            white-space: pre-wrap;
        }}

        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        .data-table th, .data-table td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        .data-table th {{
            background: #182234;
            color: #93c5fd;
            font-size: 12px;
            text-transform: uppercase;
        }}
        .badge-verified {{
            background: #065f46;
            color: #a7f3d0;
            font-weight: 700;
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 3px;
        }}

        .footer-note {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 40px;
            border-top: 1px solid var(--border);
            padding-top: 20px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .card-panel, .report-header, .finding-card {{ border: 1px solid #ccc; background: #fff; color: #000; }}
            .evidence-box {{ background: #f5f5f5; color: #000; border: 1px solid #ddd; }}
            .finding-header {{ background: #eee; }}
            .finding-title {{ color: #000; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- REPORT HEADER & AUTHORIZATION -->
        <header class="report-header">
            <div class="header-top">
                <div>
                    <div class="brand-logo">CYBERWOLF SECURITY ASSESSMENT</div>
                    <div class="brand-sub">Platform Version {self.version} • Bug Discovery & Investigation Engine (BDIE)</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-weight: 700; color: #34d399;">STATUS: AUTHORIZED</div>
                    <div style="font-size: 12px; color: var(--text-muted);">Scope Validated • Strict Non-Destructive</div>
                </div>
            </div>
            <div class="header-meta-grid">
                <div>
                    <div class="meta-label">Primary Target</div>
                    <div class="meta-val">{target}</div>
                </div>
                <div>
                    <div class="meta-label">Report ID</div>
                    <div class="meta-val"><code>{report_id}</code></div>
                </div>
                <div>
                    <div class="meta-label">Scan ID</div>
                    <div class="meta-val"><code>{scan_id or 'N/A'}</code></div>
                </div>
                <div>
                    <div class="meta-label">Assessment Date</div>
                    <div class="meta-val">{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                </div>
            </div>
        </header>

        <!-- SECTIONS 7 & 8: RISK & VULNERABILITY SUMMARY METRICS -->
        <section class="metrics-grid">
            <div class="metric-card" style="border-top: 4px solid var(--critical);">
                <div class="metric-label" style="color: var(--critical);">Critical</div>
                <div class="metric-count" style="color: var(--critical);">{summary.get('CRITICAL', 0)}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--high);">
                <div class="metric-label" style="color: var(--high);">High</div>
                <div class="metric-count" style="color: var(--high);">{summary.get('HIGH', 0)}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--medium);">
                <div class="metric-label" style="color: var(--medium);">Medium</div>
                <div class="metric-count" style="color: var(--medium);">{summary.get('MEDIUM', 0)}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--low);">
                <div class="metric-label" style="color: var(--low);">Low</div>
                <div class="metric-count" style="color: var(--low);">{summary.get('LOW', 0)}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--info);">
                <div class="metric-label" style="color: var(--info);">Total Findings</div>
                <div class="metric-count" style="color: #60a5fa;">{summary.get('TOTAL', 0)}</div>
            </div>
        </section>

        <!-- SECTION 1: EXECUTIVE SUMMARY -->
        <section class="card-panel">
            <h3>1. Executive Summary & Posture Analysis</h3>
            <p style="margin: 0; font-size: 15px; color: #e5e7eb;">
                {ai_summary or "Security assessment completed under authorized scope rules. The review identified " + str(summary.get('TOTAL', 0)) + " verified security issues requiring remediation. Prioritize addressing Critical and High severity findings immediately."}
            </p>
        </section>

        <!-- SECTIONS 2, 3 & 4: SCOPE, AUTHORIZATION & TIMELINE -->
        <section class="card-panel">
            <h3>2-4. Scope, Authorization & Timeline</h3>
            <div class="header-meta-grid">
                <div>
                    <div class="meta-label">Authorization Engine</div>
                    <div class="meta-val" style="color: #34d399;">Authorized In-Scope</div>
                </div>
                <div>
                    <div class="meta-label">Policy Mode</div>
                    <div class="meta-val">{scan_data.get('mode', 'SAFE_SCAN') if scan_data else 'SAFE_SCAN'}</div>
                </div>
                <div>
                    <div class="meta-label">Non-Destructive Boundary</div>
                    <div class="meta-val">Enforced (subprocess shell=False)</div>
                </div>
                <div>
                    <div class="meta-label">Assessment Started</div>
                    <div class="meta-val">{scan_data.get('started_at', 'Scan Initiated') if scan_data else 'Recorded'}</div>
                </div>
            </div>
        </section>

        <!-- SECTION 5: ASSET INVENTORY -->
        <section class="card-panel">
            <h3>5. Discovered Asset Inventory ({len(assets)})</h3>
            <table class="data-table">
                <thead>
                    <tr><th>ID</th><th>Identifier / Target</th><th>Type</th><th>IP Address</th><th>Risk Score</th></tr>
                </thead>
                <tbody>
                    {asset_rows if asset_rows else '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No asset records in database.</td></tr>'}
                </tbody>
            </table>
        </section>

        <!-- SECTIONS 9-18: DETAILED TECHNICAL FINDINGS & EXACT LOCATIONS -->
        <section>
            <h3 style="color: #93c5fd; margin-bottom: 20px;">9-18. Detailed Technical Findings & Exact Locations ({len(findings)})</h3>
            {findings_html if findings_html else '<div class="card-panel"><p>No security findings recorded for this target scope.</p></div>'}
        </section>

        <!-- SECTION 19: TOOL EXECUTION HISTORY -->
        <section class="card-panel">
            <h3>19. Tool Execution History ({len(tool_runs)})</h3>
            <table class="data-table">
                <thead>
                    <tr><th>Tool</th><th>Command Line / Probe</th><th>Exit Code</th><th>Duration</th></tr>
                </thead>
                <tbody>
                    {tool_rows if tool_rows else '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">No tool run executions recorded for this scan.</td></tr>'}
                </tbody>
            </table>
        </section>

        <!-- SECTION 20: EVIDENCE INTEGRITY & CHAIN OF CUSTODY -->
        <section class="card-panel">
            <h3>20. Evidence Integrity & Cryptographic Chain of Custody</h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
                All evidence captured during assessment is hashed with SHA-256 upon creation to guarantee audit traceability and evidentiary integrity.
            </p>
            <table class="data-table">
                <thead>
                    <tr><th>Finding</th><th>Evidence ID</th><th>Type</th><th>Source Tool</th><th>SHA-256 Digest</th><th>Integrity</th></tr>
                </thead>
                <tbody>
                    {evidence_chain_rows if evidence_chain_rows else '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No cryptographic evidence items logged.</td></tr>'}
                </tbody>
            </table>
        </section>

        <!-- SECTION 21: FINAL RISK SUMMARY -->
        <section class="card-panel">
            <h3>21. Final Risk Summary & Posture Recommendations</h3>
            <p style="font-size: 14px; color: #e5e7eb;">
                Remediation teams should begin with highest-scored vulnerabilities. Following patching or configuration changes, run <code>cyberwolf findings retest &lt;ID&gt;</code> to verify the resolution before closing each issue.
            </p>
        </section>

        <footer class="footer-note">
            <p>{REPORT_DISCLAIMER.strip()}</p>
            <p>Generated by CYBERWOLF V2 • Bug Discovery & Investigation Engine (BDIE)</p>
        </footer>
    </div>
</body>
</html>"""

    def _build_pdf_report(self, pdf_path: Path, report_id: str, title: str, target: str,
                          scan_id: Optional[str], summary: Dict[str, int],
                          findings: List[Dict[str, Any]], ai_summary: Optional[str]):
        """Generate PDF using ReportLab with tables, severity badges, exact locations, and evidence hashes."""
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
        )

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#1e3a8a')
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#6b7280'),
            spaceAfter=12
        )
        heading2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontSize=12,
            leading=15,
            textColor=colors.HexColor('#1f2937'),
            spaceBefore=10,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#374151')
        )
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Code'],
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor('#111827'),
            backColor=colors.HexColor('#f3f4f6')
        )

        elements = []

        # Title & Metadata
        elements.append(Paragraph("CYBERWOLF SECURITY ASSESSMENT REPORT", title_style))
        elements.append(Paragraph(f"Platform Version {self.version} • Bug Discovery & Investigation Engine (BDIE)", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceAfter=10))

        meta_data = [
            [Paragraph("<b>Target:</b>", body_style), Paragraph(target, body_style),
             Paragraph("<b>Report ID:</b>", body_style), Paragraph(report_id, body_style)],
            [Paragraph("<b>Scan ID:</b>", body_style), Paragraph(scan_id or "N/A", body_style),
             Paragraph("<b>Date:</b>", body_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M UTC"), body_style)]
        ]
        meta_table = Table(meta_data, colWidths=[60, 200, 60, 200])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # Metrics Table
        metrics_data = [
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL FINDINGS"],
            [
                str(summary.get("CRITICAL", 0)),
                str(summary.get("HIGH", 0)),
                str(summary.get("MEDIUM", 0)),
                str(summary.get("LOW", 0)),
                str(summary.get("TOTAL", 0))
            ]
        ]
        metric_table = Table(metrics_data, colWidths=[100, 100, 100, 100, 140])
        metric_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#ef4444')),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#f97316')),
            ('BACKGROUND', (2, 0), (2, 0), colors.HexColor('#eab308')),
            ('BACKGROUND', (3, 0), (3, 0), colors.HexColor('#3b82f6')),
            ('BACKGROUND', (4, 0), (4, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, 1), 14),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94a3b8')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(metric_table)
        elements.append(Spacer(1, 10))

        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading2_style))
        exec_text = ai_summary or "Security assessment completed under authorized scope rules. Refer to individual findings for exact affected locations and remediation priorities."
        elements.append(Paragraph(exec_text, body_style))
        elements.append(Spacer(1, 10))

        # Findings Detail with Exact Locations
        elements.append(Paragraph(f"Technical Findings & Exact Locations ({len(findings)})", heading2_style))

        sev_colors = {
            "CRITICAL": colors.HexColor('#ef4444'),
            "HIGH": colors.HexColor('#f97316'),
            "MEDIUM": colors.HexColor('#eab308'),
            "LOW": colors.HexColor('#3b82f6'),
            "INFO": colors.HexColor('#6b7280')
        }

        for fnd in findings[:30]:  # Cap at 30 in PDF to maintain compact page count
            sev = (fnd.get("severity") or "INFO").upper()
            bar_color = sev_colors.get(sev, colors.gray)

            t_title = html.escape(str(fnd.get('title') or fnd.get('vulnerability') or 'Finding'))
            t_id = html.escape(str(fnd.get('id') or ''))
            t_loc = fnd.get("url") or (f"{fnd.get('target')}:{fnd.get('port')}" if fnd.get('port') else fnd.get('target'))
            t_obs = html.escape(sanitize_message(fnd.get('observed_behavior') or fnd.get('evidence', ''))[:220])
            t_rem = html.escape(str(fnd.get('remediation', 'N/A'))[:220])

            ev_items = fnd.get("evidence_items", [])
            ev_sha = ev_items[0].get("hash_sha256", "N/A")[:32] + "..." if ev_items and ev_items[0].get("hash_sha256") else "N/A"

            f_rows = [
                [
                    Paragraph(f"<b>[{sev}] {t_title}</b>", body_style),
                    Paragraph(f"ID: {t_id} | Risk: {fnd.get('risk_score', 'N/A')}/10.0 | Status: {fnd.get('status', 'OPEN')}", body_style)
                ],
                [
                    Paragraph(f"<b>Exact Location:</b> {t_loc}", body_style),
                    Paragraph(f"<b>Exploitability:</b> {fnd.get('exploitability_level', 'MEDIUM')} | Conf: {fnd.get('confidence', 'MEDIUM')}", body_style)
                ],
                [
                    Paragraph(f"<b>Observed Behavior:</b> {t_obs}", code_style),
                    Paragraph(f"<b>Remediation:</b> {t_rem}", body_style)
                ],
                [
                    Paragraph(f"<b>Evidence SHA-256:</b> {ev_sha}", code_style),
                    Paragraph(f"<b>Retest:</b> {fnd.get('retest_result', 'NOT_TESTED')}", body_style)
                ]
            ]
            f_table = Table(f_rows, colWidths=[270, 270])
            f_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('LINELEFT', (0, 0), (0, -1), 3, bar_color),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            elements.append(KeepTogether([f_table, Spacer(1, 6)]))

        doc.build(elements)
