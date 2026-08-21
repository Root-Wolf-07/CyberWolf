"""CYBERWOLF Multi-Format Security Assessment Report Generator."""

import os
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from app.core.config import get_config
from app.database.operations import get_all_findings, get_findings_summary
from app.database.db_manager import get_db
from app.core.logger import get_logger

logger = get_logger()

REPORT_DISCLAIMER = """
DISCLAIMER:
This report was generated from authorized security assessment activity.
Findings should be manually validated before remediation or disclosure.
CYBERWOLF is intended solely for authorized security assessment, defense, and research.
"""

class ReportGenerator:
    """Generates professional executive & technical security assessment reports."""
    
    def __init__(self, output_dir: Optional[str] = None):
        self.config = get_config()
        self.output_dir = Path(output_dir or (self.config.base_dir / "reports")).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all_formats(self, target: str, title: Optional[str] = None,
                             ai_summary: Optional[str] = None) -> Dict[str, str]:
        """Generate reports in TXT, JSON, HTML, and CSV formats."""
        import uuid
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_title = title or f"CYBERWOLF Security Assessment Report - {target}"
        base_filename = f"cyberwolf_report_{timestamp_str}_{uuid.uuid4().hex[:6]}"
        
        findings = get_all_findings(target=target)
        summary = get_findings_summary()

        generated_files = {}

        # 1. JSON Report
        json_path = self.output_dir / f"{base_filename}.json"
        json_data = {
            "title": report_title,
            "generated_at": datetime.now().isoformat(),
            "target": target,
            "disclaimer": REPORT_DISCLAIMER.strip(),
            "summary": summary,
            "ai_executive_summary": ai_summary or "Assessment completed. Refer to individual findings for remediation priorities.",
            "findings": findings
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        generated_files["JSON"] = str(json_path)

        # 2. TXT Report
        txt_path = self.output_dir / f"{base_filename}.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write(f"           CYBERWOLF SECURITY ASSESSMENT REPORT\n")
            f.write(f"           {self.config.get('app', {}).get('tagline', '')}\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Title:         {report_title}\n")
            f.write(f"Target:        {target}\n")
            f.write(f"Date:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Findings:{summary.get('TOTAL', 0)} (CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)})\n\n")
            f.write("-" * 70 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(ai_summary or "No critical anomalies detected beyond reported findings.\n")
            f.write("\n" + "-" * 70 + "\n")
            f.write("FINDINGS & EVIDENCE\n")
            f.write("-" * 70 + "\n")
            for idx, fnd in enumerate(findings, 1):
                f.write(f"\n[{idx}] [{fnd.get('severity')}] {fnd.get('vulnerability')}\n")
                f.write(f"    Target:      {fnd.get('target')}\n")
                f.write(f"    Port/Proto:  {fnd.get('port')}/{fnd.get('protocol')}\n")
                f.write(f"    Evidence:    {fnd.get('evidence')}\n")
                f.write(f"    Remediation: {fnd.get('remediation')}\n")
                f.write(f"    Tool:        {fnd.get('source_tool')}\n")
            f.write("\n" + "=" * 70 + "\n")
            f.write(REPORT_DISCLAIMER + "\n")
            f.write("=" * 70 + "\n")
        generated_files["TXT"] = str(txt_path)

        # 3. CSV Report
        csv_path = self.output_dir / f"{base_filename}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Finding ID", "Target", "Severity", "Vulnerability", "Port", "Protocol", "Evidence", "Remediation", "Source Tool", "Status"])
            for fnd in findings:
                writer.writerow([
                    fnd.get("id"), fnd.get("target"), fnd.get("severity"), fnd.get("vulnerability"),
                    fnd.get("port"), fnd.get("protocol"), fnd.get("evidence"), fnd.get("remediation"),
                    fnd.get("source_tool"), fnd.get("status")
                ])
        generated_files["CSV"] = str(csv_path)

        # 4. HTML Report (Dark SOC Theme)
        html_path = self.output_dir / f"{base_filename}.html"
        html_content = self._build_html_report(report_title, target, summary, findings, ai_summary)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        generated_files["HTML"] = str(html_path)

        # Record in database
        db = get_db()
        with db.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO reports (id, title, report_format, file_path, target, summary_text, findings_count)
                VALUES (?, ?, 'MULTI_FORMAT', ?, ?, ?, ?)
            """, (base_filename, report_title, str(html_path), target, ai_summary or "Multi-format report generated", len(findings)))

        logger.info(f"Reports successfully generated in {self.output_dir}")
        return generated_files

    def _build_html_report(self, title: str, target: str, summary: Dict[str, int],
                           findings: List[Dict[str, Any]], ai_summary: Optional[str]) -> str:
        """Render self-contained dark cyber SOC HTML report."""
        findings_rows = ""
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            badge_color = {
                "CRITICAL": "#ff3366",
                "HIGH": "#ff6600",
                "MEDIUM": "#ffcc00",
                "LOW": "#00ccff",
                "INFO": "#888888"
            }.get(sev, "#888888")

            findings_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge" style="background-color: {badge_color}; color: #000;">{sev}</span>
                    <span class="finding-title">{f.get('vulnerability')}</span>
                    <span class="finding-tool">{f.get('source_tool')}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Target:</strong> {f.get('target')} {f" (Port: {f.get('port')})" if f.get('port') else ""}</p>
                    <p><strong>Evidence:</strong> <code>{f.get('evidence')}</code></p>
                    <p><strong>Remediation:</strong> {f.get('remediation') or 'N/A'}</p>
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
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --accent-cyan: #00f0ff;
            --accent-green: #00ff88;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--accent-cyan);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .brand {{
            font-size: 26px;
            font-weight: 800;
            color: var(--accent-cyan);
            letter-spacing: 2px;
        }}
        .tagline {{
            color: #8b949e;
            font-size: 14px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-box {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            color: #fff;
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 18px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
        }}
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            color: #fff;
            flex-grow: 1;
        }}
        .finding-tool {{
            font-size: 12px;
            color: #8b949e;
        }}
        code {{
            background: #090d13;
            padding: 4px 8px;
            border-radius: 4px;
            color: #79c0ff;
            word-break: break-all;
        }}
        .disclaimer {{
            margin-top: 40px;
            padding: 15px;
            background: #1f1f28;
            border-left: 4px solid #e3b341;
            font-size: 12px;
            color: #8b949e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="brand">CYBERWOLF SECURITY COMMAND CENTER</div>
            <div class="tagline">HUNT THREATS • FIND WEAKNESSES • DEFEND EVERYTHING</div>
            <p style="margin-top: 10px; color: #8b949e;">Target: <strong>{target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-box"><div class="stat-value" style="color: #ff3366;">{summary.get('CRITICAL', 0)}</div><div>CRITICAL</div></div>
            <div class="stat-box"><div class="stat-value" style="color: #ff6600;">{summary.get('HIGH', 0)}</div><div>HIGH</div></div>
            <div class="stat-box"><div class="stat-value" style="color: #ffcc00;">{summary.get('MEDIUM', 0)}</div><div>MEDIUM</div></div>
            <div class="stat-box"><div class="stat-value" style="color: #00ccff;">{summary.get('LOW', 0)}</div><div>LOW</div></div>
            <div class="stat-box"><div class="stat-value" style="color: #00ff88;">{summary.get('TOTAL', 0)}</div><div>TOTAL</div></div>
        </div>

        <div class="finding-card">
            <h3>Executive & AI Assessment Summary</h3>
            <p>{ai_summary or "The assessment completed successfully. Prioritize remediation based on findings severity above."}</p>
        </div>

        <h3>Assessment Findings & Evidence</h3>
        {findings_rows if findings_rows else "<p>No active security vulnerabilities found.</p>"}

        <div class="disclaimer">
            <strong>AUTHORIZED ASSESSMENT DISCLAIMER:</strong><br>
            This report was generated from authorized security assessment activity. Findings should be manually validated before remediation or disclosure.
        </div>
    </div>
</body>
</html>
"""
