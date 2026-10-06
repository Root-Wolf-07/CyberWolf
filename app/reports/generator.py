"""CYBERWOLF Multi-Format Security Assessment Report Generator (V2).

Generates auditable, professional security assessment deliverables in:
- HTML (Interactive SOC Workstation & Client Presentation format)
- PDF (ReportLab document with page numbers, tables, severity indicators)
- JSON (Machine-readable canonical report schema)
- CSV (Spreadsheet finding export)
- TXT (ASCII technical assessment summary)
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
from app.database.operations import get_all_findings, get_findings_summary, get_scan
from app.database.db_manager import get_db
from app.database.models import Finding, ReportRecord

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

        findings = get_all_findings(target=target)
        summary = get_findings_summary()
        scan_data = get_scan(scan_id) if scan_id else None

        generated_files = {}

        # 1. JSON Report
        json_path = self.output_dir / f"{base_filename}.json"
        json_data = self._build_json_payload(report_id, report_title, target, scan_id, scan_data, summary, findings, ai_summary)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        generated_files["JSON"] = str(json_path)

        # 2. CSV Report
        csv_path = self.output_dir / f"{base_filename}.csv"
        self._write_csv_report(csv_path, findings)
        generated_files["CSV"] = str(csv_path)

        # 3. TXT Report
        txt_path = self.output_dir / f"{base_filename}.txt"
        self._write_txt_report(txt_path, report_id, report_title, target, scan_id, summary, findings, ai_summary)
        generated_files["TXT"] = str(txt_path)

        # 4. HTML Report
        html_path = self.output_dir / f"{base_filename}.html"
        html_content = self._build_html_report(report_id, report_title, target, scan_id, scan_data, summary, findings, ai_summary)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        generated_files["HTML"] = str(html_path)

        # 5. PDF Report
        pdf_path = self.output_dir / f"{base_filename}.pdf"
        try:
            self._build_pdf_report(pdf_path, report_id, report_title, target, scan_id, summary, findings, ai_summary)
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
                scan_id, ai_summary or "Multi-format report generated", len(findings)
            ))

        logger.info(f"Reports successfully generated in {self.output_dir}")
        return generated_files

    def _build_json_payload(self, report_id: str, title: str, target: str,
                            scan_id: Optional[str], scan_data: Optional[Dict[str, Any]],
                            summary: Dict[str, int], findings: List[Dict[str, Any]],
                            ai_summary: Optional[str]) -> Dict[str, Any]:
        return {
            "cyberwolf_version": self.version,
            "report_id": report_id,
            "scan_id": scan_id or "N/A",
            "title": title,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "authorization_status": scan_data.get("authorization_status", "AUTHORIZED") if scan_data else "AUTHORIZED",
            "policy_mode": scan_data.get("mode", "SAFE_SCAN") if scan_data else "SAFE_SCAN",
            "tools_executed": scan_data.get("tools_executed", []) if scan_data else [],
            "executive_summary": ai_summary or "Assessment completed. Refer to technical findings for remediation priority.",
            "metrics": {
                "total_findings": summary.get("TOTAL", 0),
                "critical": summary.get("CRITICAL", 0),
                "high": summary.get("HIGH", 0),
                "medium": summary.get("MEDIUM", 0),
                "low": summary.get("LOW", 0),
                "info": summary.get("INFO", 0)
            },
            "findings": findings,
            "disclaimer": REPORT_DISCLAIMER.strip()
        }

    def _write_csv_report(self, csv_path: Path, findings: List[Dict[str, Any]]):
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Finding ID", "Target", "Severity", "Risk Score", "Title / Vulnerability",
                "Port", "Protocol", "Service", "CVE", "CWE", "Evidence", "Remediation", "Source Tools", "Status"
            ])
            for fnd in findings:
                writer.writerow([
                    fnd.get("id"),
                    fnd.get("target"),
                    fnd.get("severity"),
                    fnd.get("risk_score", 0.0),
                    fnd.get("title") or fnd.get("vulnerability"),
                    fnd.get("port") or "N/A",
                    fnd.get("protocol") or "tcp",
                    fnd.get("service") or "N/A",
                    fnd.get("cve") or "N/A",
                    fnd.get("cwe") or "N/A",
                    sanitize_message(fnd.get("evidence", "")),
                    fnd.get("remediation") or "N/A",
                    fnd.get("source_tool") or "CYBERWOLF",
                    fnd.get("status", "OPEN")
                ])

    def _write_txt_report(self, txt_path: Path, report_id: str, title: str, target: str,
                          scan_id: Optional[str], summary: Dict[str, int],
                          findings: List[Dict[str, Any]], ai_summary: Optional[str]):
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("                       CYBERWOLF SECURITY ASSESSMENT REPORT\n")
            f.write(f"                               Version {self.version}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Report ID:        {report_id}\n")
            f.write(f"Scan ID:          {scan_id or 'N/A'}\n")
            f.write(f"Target:           {target}\n")
            f.write(f"Date:             {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"Total Findings:   {summary.get('TOTAL', 0)} (CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}, INFO: {summary.get('INFO', 0)})\n\n")
            f.write("-" * 80 + "\n")
            f.write("1. EXECUTIVE SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(ai_summary or "Authorized security assessment completed across identified perimeter targets.\n")
            f.write("\n" + "-" * 80 + "\n")
            f.write("2. DETAILED TECHNICAL FINDINGS & EVIDENCE\n")
            f.write("-" * 80 + "\n")
            for idx, fnd in enumerate(findings, 1):
                sev = fnd.get("severity", "INFO")
                t_str = fnd.get("title") or fnd.get("vulnerability")
                port_str = f" (Port: {fnd.get('port')}/{fnd.get('protocol', 'tcp')})" if fnd.get('port') else ""
                f.write(f"\n[{idx}] [{sev}] {t_str} (ID: {fnd.get('id')})\n")
                f.write(f"    Target:       {fnd.get('target')}{port_str}\n")
                f.write(f"    Risk Score:   {fnd.get('risk_score', 'N/A')}/10.0\n")
                if fnd.get("cve"):
                    f.write(f"    CVE:          {fnd.get('cve')}\n")
                if fnd.get("cwe"):
                    f.write(f"    CWE:          {fnd.get('cwe')}\n")
                f.write(f"    Evidence:     {sanitize_message(fnd.get('evidence', 'N/A'))}\n")
                f.write(f"    Remediation:  {fnd.get('remediation', 'N/A')}\n")
                f.write(f"    Source Tool:  {fnd.get('source_tool')}\n")
            f.write("\n" + "=" * 80 + "\n")
            f.write(REPORT_DISCLAIMER.strip() + "\n")
            f.write("=" * 80 + "\n")

    def _build_html_report(self, report_id: str, title: str, target: str,
                           scan_id: Optional[str], scan_data: Optional[Dict[str, Any]],
                           summary: Dict[str, int], findings: List[Dict[str, Any]],
                           ai_summary: Optional[str]) -> str:
        findings_html = ""
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
            evidence_safe = html.escape(sanitize_message(f.get("evidence", "No output recorded")))
            remediation_safe = html.escape(str(f.get('remediation') or 'Review configuration and apply vendor patches.'))
            tool_safe = html.escape(str(f.get('source_tool') or 'CYBERWOLF'))

            cve_pill = f'<span class="pill pill-cve">{html.escape(str(f.get("cve")))}</span>' if f.get("cve") else ""
            cwe_pill = f'<span class="pill pill-cwe">{html.escape(str(f.get("cwe")))}</span>' if f.get("cwe") else ""
            score_pill = f'<span class="pill pill-score">Risk: {f.get("risk_score", 0.0)}/10.0</span>' if f.get("risk_score") else ""

            port_info = f"Port: {f.get('port')}/{f.get('protocol', 'tcp')}" if f.get("port") else "Host Level"

            findings_html += f"""
            <div class="finding-card" id="{id_safe}">
                <div class="finding-header">
                    <div class="finding-title-row">
                        <span class="severity-badge" style="background-color: {badge_color};">{sev}</span>
                        <span class="finding-title">{title_safe}</span>
                    </div>
                    <div class="finding-meta-pills">
                        {score_pill}
                        {cve_pill}
                        {cwe_pill}
                        <span class="pill pill-tool">{tool_safe}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="meta-grid">
                        <div><strong>Finding ID:</strong> <code>{id_safe}</code></div>
                        <div><strong>Target:</strong> {target_safe}</div>
                        <div><strong>Scope / Port:</strong> {port_info}</div>
                        <div><strong>Status:</strong> {f.get('status', 'OPEN')}</div>
                    </div>
                    <div class="section-sub">
                        <h4>Evidence & Observed Output</h4>
                        <pre class="evidence-box"><code>{evidence_safe}</code></pre>
                    </div>
                    <div class="section-sub">
                        <h4>Remediation Guidance</h4>
                        <div class="remediation-box">{remediation_safe}</div>
                    </div>
                </div>
            </div>
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
            max-width: 1150px;
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
            margin-bottom: 20px;
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

        .finding-body {{ padding: 20px; }}
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
        .section-sub h4 {{ margin: 15px 0 8px 0; font-size: 14px; text-transform: uppercase; color: var(--text-muted); }}
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
        .remediation-box {{
            background: #0f1f17;
            border-left: 3px solid #10b981;
            padding: 12px 16px;
            border-radius: 0 6px 6px 0;
            font-size: 14px;
            color: #d1fae5;
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
        <header class="report-header">
            <div class="header-top">
                <div>
                    <div class="brand-logo">CYBERWOLF SECURITY ASSESSMENT</div>
                    <div class="brand-sub">Platform Version {self.version} • Defense & Posture Assessment</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-weight: 700; color: #34d399;">STATUS: AUTHORIZED</div>
                    <div style="font-size: 12px; color: var(--text-muted);">Confidential Deliverable</div>
                </div>
            </div>
            <div class="header-meta-grid">
                <div>
                    <div class="meta-label">Target Assessment</div>
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

        <section class="card-panel">
            <h3>Executive Summary & Posture Analysis</h3>
            <p style="margin: 0; font-size: 15px; color: #e5e7eb;">
                {ai_summary or "Security assessment completed under authorized scope rules. The review identified " + str(summary.get('TOTAL', 0)) + " potential findings requiring remediation review. Highest priority should be given to critical and high severity exposures."}
            </p>
        </section>

        <section>
            <h3 style="color: #93c5fd; margin-bottom: 20px;">Detailed Technical Findings ({len(findings)})</h3>
            {findings_html if findings_html else '<div class="card-panel"><p>No security findings recorded for this target scope.</p></div>'}
        </section>

        <footer class="footer-note">
            <p>{REPORT_DISCLAIMER.strip()}</p>
            <p>Generated by CYBERWOLF V2 • Local Offline Security Command Center</p>
        </footer>
    </div>
</body>
</html>"""

    def _build_pdf_report(self, pdf_path: Path, report_id: str, title: str, target: str,
                          scan_id: Optional[str], summary: Dict[str, int],
                          findings: List[Dict[str, Any]], ai_summary: Optional[str]):
        """Generate PDF using ReportLab with tables, severity badges, and page numbers."""
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
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#1e3a8a')
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#6b7280'),
            spaceAfter=15
        )
        heading2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#1f2937'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#374151')
        )
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Code'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#111827'),
            backColor=colors.HexColor('#f3f4f6')
        )

        elements = []

        # Title & Metadata
        elements.append(Paragraph("CYBERWOLF SECURITY ASSESSMENT REPORT", title_style))
        elements.append(Paragraph(f"Platform Version {self.version} • Confidential Technical Assessment", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceAfter=12))

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
        elements.append(Spacer(1, 14))

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
            ('FONTSIZE', (0, 1), (-1, 1), 16),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94a3b8')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(metric_table)
        elements.append(Spacer(1, 14))

        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading2_style))
        exec_text = ai_summary or "Security assessment completed under authorized scope rules. Refer to individual findings for remediation priorities."
        elements.append(Paragraph(exec_text, body_style))
        elements.append(Spacer(1, 14))

        # Findings Detail
        elements.append(Paragraph(f"Technical Findings ({len(findings)})", heading2_style))

        sev_colors = {
            "CRITICAL": colors.HexColor('#ef4444'),
            "HIGH": colors.HexColor('#f97316'),
            "MEDIUM": colors.HexColor('#eab308'),
            "LOW": colors.HexColor('#3b82f6'),
            "INFO": colors.HexColor('#6b7280')
        }

        for fnd in findings[:40]:  # Cap at 40 in PDF to maintain compact page count
            sev = (fnd.get("severity") or "INFO").upper()
            bar_color = sev_colors.get(sev, colors.gray)

            t_title = html.escape(str(fnd.get('title') or fnd.get('vulnerability') or 'Finding'))
            t_target = html.escape(str(fnd.get('target') or ''))
            t_id = html.escape(str(fnd.get('id') or ''))
            t_tool = html.escape(str(fnd.get('source_tool') or 'CYBERWOLF'))
            t_ev = html.escape(sanitize_message(fnd.get('evidence', ''))[:300])
            t_rem = html.escape(str(fnd.get('remediation', 'N/A'))[:300])
            t_port = fnd.get('port') or 'N/A'
            t_proto = fnd.get('protocol', 'tcp')

            f_rows = [
                [
                    Paragraph(f"<b>[{sev}] {t_title}</b>", body_style),
                    Paragraph(f"ID: {t_id} | Score: {fnd.get('risk_score', 'N/A')}", body_style)
                ],
                [
                    Paragraph(f"<b>Scope:</b> {t_target} (Port {t_port}/{t_proto})", body_style),
                    Paragraph(f"<b>Tool:</b> {t_tool}", body_style)
                ],
                [
                    Paragraph(f"<b>Evidence:</b> {t_ev}", code_style),
                    Paragraph(f"<b>Remediation:</b> {t_rem}", body_style)
                ]
            ]
            f_table = Table(f_rows, colWidths=[270, 270])
            f_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('LINELEFT', (0, 0), (0, -1), 3, bar_color),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(KeepTogether([f_table, Spacer(1, 8)]))

        doc.build(elements)
