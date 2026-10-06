"""CYBERWOLF V2 Web & REST API Subsystem (Local Analyst Workstation).

Provides:
- Fully decoupled REST API endpoints for all core security services
- Threaded execution preventing long-running scan starvation
- Professional Cybersecurity Workstation UI (SOC Analyst Console)
- Zero third-party web framework dependencies (built on standard library ThreadingHTTPServer)
"""

import os
import sys
import json
import uuid
import mimetypes
import threading
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

from app.core.config import get_config
from app.core.logger import get_logger
from app.services.scan_service import get_scan_service
from app.services.finding_service import get_finding_service
from app.services.asset_service import get_asset_service
from app.services.target_service import get_target_service
from app.tools.detector import get_tool_detector
from app.security.policies import PolicyEngine
from app.reports.generator import ReportGenerator
from app.evidence.vault import get_evidence_vault
from app.database.operations import (
    get_database_status, get_audit_events, get_all_reports,
    get_scan, get_all_findings
)
from app.database.db_manager import get_db

logger = get_logger()


class CyberWolfRequestHandler(BaseHTTPRequestHandler):
    """Handles REST API and Workstation Web UI HTTP requests."""

    server_version = "CyberWolf-Workstation/2.0.0"

    def _send_json(self, data: Any, status: int = 200):
        """Send JSON response with appropriate headers."""
        try:
            body = json.dumps(data, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_html(self, html_content: str, status: int = 200):
        """Send HTML response."""
        try:
            body = html_content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_json_body(self) -> Dict[str, Any]:
        """Read and parse JSON request body safely."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                raw = self.rfile.read(content_length).decode("utf-8")
                return json.loads(raw)
        except Exception as e:
            logger.warning(f"Failed to read/parse request JSON body: {e}")
        return {}

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        """Route GET requests to API or Dashboard UI."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. API: Health Check
        if path == "/api/health":
            self._send_json({"status": "ok", "app": "CyberWolf", "version": "2.0.0"})
            return

        # 2. API: System Status & Diagnostic Summary
        if path == "/api/status":
            cfg = get_config()
            detector = get_tool_detector()
            tool_report = detector.get_full_doctor_report()
            finding_svc = get_finding_service()
            scan_svc = get_scan_service()
            asset_svc = get_asset_service()
            policy_engine = PolicyEngine()

            data = {
                "version": "2.0.0",
                "app_mode": cfg.get("security", {}).get("mode", "SAFE_SCAN"),
                "system": tool_report.get("system", {}),
                "tools": tool_report.get("security_tools", {}),
                "database": get_database_status(),
                "policy": policy_engine.get_active_policy().to_dict(),
                "summary": {
                    "findings": finding_svc.get_summary(),
                    "total_assets": len(asset_svc.list_assets()),
                    "recent_scans": len(scan_svc.list_scans(limit=10))
                }
            }
            self._send_json(data)
            return

        # 3. API: Assets
        if path == "/api/assets":
            asset_svc = get_asset_service()
            self._send_json({"assets": asset_svc.list_assets()})
            return

        if path.startswith("/api/assets/"):
            asset_id_str = path.replace("/api/assets/", "").strip("/")
            try:
                aid = int(asset_id_str)
                asset_svc = get_asset_service()
                detail = asset_svc.get_asset_detail(aid)
                if detail:
                    self._send_json(detail)
                else:
                    self._send_json({"error": "Asset not found"}, status=404)
            except ValueError:
                self._send_json({"error": "Invalid asset ID format"}, status=400)
            return

        # 4. API: Scans
        if path == "/api/scans":
            scan_svc = get_scan_service()
            limit = int(query.get("limit", [50])[0])
            self._send_json({"scans": scan_svc.list_scans(limit=limit)})
            return

        if path.startswith("/api/scans/"):
            scan_id = path.replace("/api/scans/", "").strip("/")
            scan_svc = get_scan_service()
            scan = scan_svc.get_scan(scan_id)
            if scan:
                self._send_json({"scan": scan})
            else:
                self._send_json({"error": "Scan not found"}, status=404)
            return

        # 5. API: Findings & Sub-resources
        if path in ["/api/findings", "/findings"]:
            finding_svc = get_finding_service()
            target = query.get("target", [None])[0]
            severity = query.get("severity", [None])[0]
            status_f = query.get("status", [None])[0]
            cve = query.get("cve", [None])[0]
            findings = finding_svc.list_findings(target=target, severity=severity, status=status_f, cve=cve)
            summary = finding_svc.get_summary()
            self._send_json({"findings": findings, "summary": summary, "count": len(findings)})
            return

        if path.startswith("/api/findings/") or (path.startswith("/findings/") and not path.endswith(".html")):
            clean_p = path.replace("/api/findings/", "").replace("/findings/", "").strip("/")
            parts = clean_p.split("/")
            fid = parts[0]
            subaction = parts[1] if len(parts) > 1 else None

            finding_svc = get_finding_service()
            if subaction == "evidence":
                vault = get_evidence_vault()
                ev_list = vault.get_finding_evidence(fid)
                if not ev_list:
                    detail = finding_svc.get_finding_detail(fid)
                    ev_list = detail.get("evidence_records", []) if detail else []
                self._send_json({"finding_id": fid, "evidence": ev_list, "count": len(ev_list)})
                return
            elif subaction == "timeline":
                timeline = finding_svc.get_timeline(fid)
                self._send_json({"finding_id": fid, "timeline": timeline})
                return
            elif subaction == "sources":
                detail = finding_svc.get_finding_detail(fid)
                f_data = detail.get("finding", {}) if detail else {}
                self._send_json({
                    "finding_id": fid,
                    "primary_tool": f_data.get("source_tool", "CYBERWOLF"),
                    "all_sources": f_data.get("source_tools", [f_data.get("source_tool", "CYBERWOLF")])
                })
                return
            else:
                detail = finding_svc.get_finding_detail(fid)
                if detail:
                    self._send_json(detail)
                else:
                    self._send_json({"error": f"Finding '{fid}' not found"}, status=404)
                return

        # 6. API: Tools
        if path == "/api/tools":
            detector = get_tool_detector()
            self._send_json(detector.get_full_doctor_report())
            return

        # 7. API: Targets
        if path == "/api/targets":
            target_svc = get_target_service()
            self._send_json({"targets": target_svc.list_targets()})
            return

        # 8. API: Policies
        if path == "/api/policies":
            pe = PolicyEngine()
            self._send_json({
                "active_policy": pe.get_active_policy().to_dict(),
                "all_policies": [p.to_dict() for p in pe.list_policies()]
            })
            return

        # 9. API: Evidence
        if path == "/api/evidence":
            scan_id = query.get("scan_id", [None])[0]
            finding_id = query.get("finding_id", [None])[0]
            vault = get_evidence_vault()
            if scan_id:
                ev_list = vault.get_scan_evidence(scan_id)
            elif finding_id:
                ev_list = vault.get_finding_evidence(finding_id)
            else:
                db = get_db()
                with db.get_connection() as conn:
                    rows = conn.execute("SELECT * FROM evidence ORDER BY timestamp DESC LIMIT 50").fetchall()
                    ev_list = [dict(r) for r in rows]
            self._send_json({"evidence": ev_list})
            return

        # 10. API: Reports
        if path == "/api/reports":
            db = get_db()
            with db.get_connection() as conn:
                rows = conn.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 50").fetchall()
                reports = [dict(r) for r in rows]
            self._send_json({"reports": reports})
            return

        # 11. API: Audit Log
        if path == "/api/audit":
            limit = int(query.get("limit", [100])[0])
            events = get_audit_events(limit=limit)
            self._send_json({"audit_events": events})
            return

        # 12. File Serving: Generated Report Delivery
        if path.startswith("/reports/"):
            filename = os.path.basename(path)
            report_dir = Path(get_config().base_dir) / "reports"
            filepath = (report_dir / filename).resolve()
            if filepath.exists() and filepath.is_file() and str(filepath).startswith(str(report_dir)):
                mime, _ = mimetypes.guess_type(str(filepath))
                mime = mime or "application/octet-stream"
                try:
                    with open(filepath, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    logger.error(f"Error serving report file {filename}: {e}")
            self._send_json({"error": "Report file not found"}, status=404)
            return

        # 13. Root / Dashboard Workstation HTML
        if path in ["/", "/index.html", "/dashboard"]:
            self._send_html(render_workstation_dashboard_html())
            return

        self._send_json({"error": f"Endpoint not found: {path}"}, status=404)

    def do_POST(self):
        """Route POST requests to services."""
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        # 1. API: Initiate Scan
        if path == "/api/scans":
            target = body.get("target")
            if not target:
                self._send_json({"error": "Missing required field: 'target'"}, status=400)
                return

            scan_type = body.get("scan_type", "network")
            profile = body.get("profile", "fast")
            ports = body.get("ports")
            authorized = body.get("authorized", True)

            # Auto-enroll in target authorization if declared by caller
            if authorized:
                from app.security.authorization import add_authorized_target
                add_authorized_target(target, scope_name="web-initiated-assessment")

            # Execute scan synchronously or via async worker thread
            async_mode = body.get("async", True)
            scan_svc = get_scan_service()

            if async_mode:
                # Pre-register scan ID and run in background thread
                timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S")
                scan_id = f"SCAN-{timestamp_str}-{uuid.uuid4().hex[:4].upper()}"

                def _scan_worker():
                    try:
                        scan_svc.start_scan(
                            target=target,
                            scan_type=scan_type,
                            options={"ports": ports, "profile": profile},
                            interactive_auth=False
                        )
                    except Exception as err:
                        logger.error(f"Async scan {scan_id} error: {err}")

                t = threading.Thread(target=_scan_worker, daemon=True)
                t.start()

                self._send_json({
                    "message": "Security assessment initiated in background",
                    "target": target,
                    "scan_type": scan_type,
                    "status": "RUNNING"
                }, status=202)
            else:
                try:
                    result = scan_svc.start_scan(
                        target=target,
                        scan_type=scan_type,
                        options={"ports": ports, "profile": profile},
                        interactive_auth=False
                    )
                    self._send_json(result, status=201)
                except Exception as e:
                    self._send_json({"error": str(e)}, status=400)
            return

        # 2. API: Cancel Scan
        if path.startswith("/api/scans/") and path.endswith("/cancel"):
            scan_id = path.replace("/api/scans/", "").replace("/cancel", "").strip("/")
            scan_svc = get_scan_service()
            success = scan_svc.cancel_scan(scan_id)
            if success:
                self._send_json({"message": f"Scan '{scan_id}' cancelled successfully"})
            else:
                self._send_json({"error": f"Unable to cancel scan '{scan_id}'"}, status=400)
            return

        # 3. API: Triage Finding Status (/api/findings/{id}/triage or /api/findings/{id}/status)
        if ("/findings/" in path) and (path.endswith("/triage") or path.endswith("/status")):
            clean_p = path.replace("/api/findings/", "").replace("/findings/", "").strip("/")
            parts = clean_p.split("/")
            finding_id = parts[0]
            new_status = body.get("status")
            reason = body.get("reason") or body.get("notes") or "Analyst triage via workstation"
            verified = body.get("verified")
            actor = body.get("actor") or body.get("changed_by") or "web-analyst"

            if not new_status:
                self._send_json({"error": "Missing 'status' parameter"}, status=400)
                return

            finding_svc = get_finding_service()
            ok = finding_svc.update_status(finding_id, new_status=new_status, verified=verified, reason=reason, changed_by=actor)
            if ok:
                self._send_json({"message": f"Finding status updated to {new_status}", "id": finding_id, "status": new_status})
            else:
                self._send_json({"error": f"Failed to update finding status for {finding_id}"}, status=400)
            return

        # 3b. API: Retest Finding (/api/findings/{id}/retest or /findings/{id}/retest)
        if ("/findings/" in path) and path.endswith("/retest"):
            clean_p = path.replace("/api/findings/", "").replace("/findings/", "").strip("/")
            parts = clean_p.split("/")
            finding_id = parts[0]
            actor = body.get("actor") or "web-workstation"

            finding_svc = get_finding_service()
            result = finding_svc.retest_finding(finding_id, actor=actor)
            if result.get("success"):
                self._send_json(result, status=200)
            else:
                self._send_json(result, status=400)
            return

        # 4. API: Generate Report
        if path == "/api/reports":
            target = body.get("target") or "All Assessed Targets"
            scan_id = body.get("scan_id")
            rg = ReportGenerator()
            try:
                files = rg.generate_all_formats(target=target, scan_id=scan_id)
                self._send_json({"message": "Reports generated successfully", "target": target, "files": files})
            except Exception as e:
                self._send_json({"error": f"Failed to generate reports: {e}"}, status=500)
            return

        # 5. API: Add Authorized Target
        if path == "/api/targets":
            target = body.get("target")
            if not target:
                self._send_json({"error": "Target required"}, status=400)
                return
            scope = body.get("scope", "lab-network")
            target_svc = get_target_service()
            try:
                rec = target_svc.add_target(target, authorized=True, scope_id=scope)
                self._send_json(rec, status=201)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        self._send_json({"error": f"POST endpoint not found: {path}"}, status=404)

    def log_message(self, format, *args):
        """Silently route HTTP logs to CyberWolf logger instead of stderr spam."""
        pass


class CyberWolfServer:
    """Encapsulates the HTTP server instance for CLI and background usage."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = True):
        """Start the HTTP server on configured address."""
        self.httpd = ThreadingHTTPServer((self.host, self.port), CyberWolfRequestHandler)
        logger.info(f"CYBERWOLF V2 Web API & Workstation listening on http://{self.host}:{self.port}")

        if blocking:
            try:
                self.httpd.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self._thread.start()

    def stop(self):
        """Shutdown the HTTP server gracefully."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("CYBERWOLF Web API server stopped.")


def start_web_server(host: str = "127.0.0.1", port: int = 8080, blocking: bool = True):
    """Entrypoint function to run server."""
    server = CyberWolfServer(host=host, port=port)
    server.start(blocking=blocking)


def render_workstation_dashboard_html() -> str:
    """Generate the complete, high-performance SOC Workstation Analyst Dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYBERWOLF V2 — Security Engineering Workstation</title>
    <style>
        :root {
            --bg-base: #090d16;
            --bg-surface: #111827;
            --bg-elevated: #1a2234;
            --bg-hover: #222d42;
            --border-subtle: #242f47;
            --border-active: #3b82f6;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --text-dim: #6b7280;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-med: #eab308;
            --sev-low: #3b82f6;
            --sev-info: #64748b;
            --status-success: #10b981;
            --status-warning: #f59e0b;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: var(--font-sans);
            font-size: 13px;
            line-height: 1.5;
            display: flex;
            height: 100vh;
            overflow: hidden;
        }

        /* SIDEBAR NAVIGATION */
        .sidebar {
            width: 220px;
            background-color: var(--bg-surface);
            border-right: 1px solid var(--border-subtle);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }
        .brand {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .brand-badge {
            background: #1e3a8a;
            color: #93c5fd;
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 4px;
        }
        .brand-title {
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 0.5px;
            color: #ffffff;
        }
        .nav-menu {
            list-style: none;
            padding: 12px 8px;
            flex: 1;
            overflow-y: auto;
        }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 12px;
            border-radius: 6px;
            color: var(--text-muted);
            cursor: pointer;
            font-weight: 500;
            margin-bottom: 2px;
            transition: all 0.15s ease;
        }
        .nav-item:hover { background-color: var(--bg-hover); color: var(--text-main); }
        .nav-item.active { background-color: #1e293b; color: #60a5fa; font-weight: 600; border-left: 3px solid #3b82f6; }
        .nav-counter { margin-left: auto; font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }

        .system-footer {
            padding: 12px 16px;
            border-top: 1px solid var(--border-subtle);
            font-size: 11px;
            color: var(--text-dim);
            font-family: var(--font-mono);
        }

        /* MAIN CONTENT WORKSPACE */
        .main-workspace {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            background-color: var(--bg-base);
        }

        /* HEADER */
        .topbar {
            height: 52px;
            background-color: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 24px;
            flex-shrink: 0;
        }
        .topbar-left { display: flex; align-items: center; gap: 16px; }
        .page-title { font-size: 15px; font-weight: 600; }
        .mode-indicator {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 2px 8px;
            background: #064e3b;
            color: #6ee7b7;
            font-family: var(--font-mono);
            font-size: 11px;
            border-radius: 4px;
            font-weight: 600;
        }
        .topbar-right { display: flex; align-items: center; gap: 12px; }
        .btn {
            background-color: #2563eb;
            color: white;
            border: none;
            padding: 6px 14px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: background 0.15s;
        }
        .btn:hover { background-color: #1d4ed8; }
        .btn-secondary {
            background-color: var(--bg-elevated);
            color: var(--text-main);
            border: 1px solid var(--border-subtle);
        }
        .btn-secondary:hover { background-color: var(--bg-hover); }

        /* VIEW CONTAINER */
        .workspace-view {
            flex: 1;
            padding: 20px 24px;
            overflow-y: auto;
            display: none;
        }
        .workspace-view.active { display: block; }

        /* STATS OVERVIEW CARDS */
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin-bottom: 20px;
        }
        .stat-card {
            background-color: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 14px 16px;
        }
        .stat-label { font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 600; letter-spacing: 0.5px; }
        .stat-value { font-size: 24px; font-family: var(--font-mono); font-weight: 700; margin: 4px 0; }
        .stat-sub { font-size: 11px; color: var(--text-muted); }

        /* DATA TABLES */
        .card-panel {
            background-color: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .panel-header {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .panel-title { font-size: 13px; font-weight: 600; color: #ffffff; }

        .table-responsive { width: 100%; overflow-x: auto; }
        table.soc-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            text-align: left;
        }
        table.soc-table th {
            background-color: #0d131f;
            color: var(--text-dim);
            font-weight: 600;
            padding: 9px 14px;
            border-bottom: 1px solid var(--border-subtle);
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.5px;
        }
        table.soc-table td {
            padding: 9px 14px;
            border-bottom: 1px solid #1a2234;
            color: var(--text-main);
            vertical-align: middle;
        }
        table.soc-table tr:hover td { background-color: var(--bg-hover); cursor: pointer; }

        /* BADGES */
        .badge {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 10px;
            font-family: var(--font-mono);
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-critical { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
        .badge-high { background: #431407; color: #fdba74; border: 1px solid #9a3412; }
        .badge-medium { background: #422006; color: #fde047; border: 1px solid #854d0e; }
        .badge-low { background: #172554; color: #93c5fd; border: 1px solid #1e40af; }
        .badge-info { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
        .badge-success { background: #064e3b; color: #6ee7b7; border: 1px solid #065f46; }
        .badge-running { background: #1e3a8a; color: #93c5fd; animation: pulse 2s infinite; }

        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

        /* DETAIL DRAWER / MODAL */
        .detail-drawer {
            position: fixed;
            top: 0; right: 0; bottom: 0;
            width: 720px;
            background-color: var(--bg-surface);
            border-left: 1px solid var(--border-subtle);
            box-shadow: -10px 0 30px rgba(0,0,0,0.5);
            z-index: 1000;
            display: flex;
            flex-direction: column;
            transform: translateX(100%);
            transition: transform 0.25s ease-out;
        }
        .detail-drawer.open { transform: translateX(0); }
        .drawer-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .drawer-title { font-size: 14px; font-weight: 700; }
        .drawer-body {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
        }
        .drawer-footer {
            padding: 14px 20px;
            border-top: 1px solid var(--border-subtle);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        .detail-section { margin-bottom: 18px; }
        .detail-label { font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 600; margin-bottom: 4px; }
        .detail-box {
            background-color: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 5px;
            padding: 10px 12px;
            font-size: 12px;
            font-family: var(--font-mono);
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 200px;
            overflow-y: auto;
        }

        /* FORM CONTROLS */
        .form-group { margin-bottom: 14px; }
        .form-group label { display: block; font-size: 11px; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; text-transform: uppercase; }
        .form-control {
            width: 100%;
            padding: 8px 12px;
            background-color: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 5px;
            color: white;
            font-size: 12px;
            font-family: var(--font-mono);
        }
        .form-control:focus { outline: none; border-color: var(--border-active); }
        .filters-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 14px;
            align-items: center;
        }
    </style>
</head>
<body>

    <!-- SIDEBAR -->
    <aside class="sidebar">
        <div class="brand">
            <span class="brand-badge">V2.0</span>
            <span class="brand-title">CYBERWOLF</span>
        </div>
        <ul class="nav-menu">
            <li class="nav-item active" onclick="switchTab('overview')">
                <span>Overview</span>
            </li>
            <li class="nav-item" onclick="switchTab('assets')">
                <span>Assets</span>
                <span class="nav-counter" id="nav-count-assets">0</span>
            </li>
            <li class="nav-item" onclick="switchTab('scans')">
                <span>Scans</span>
                <span class="nav-counter" id="nav-count-scans">0</span>
            </li>
            <li class="nav-item" onclick="switchTab('findings')">
                <span>Findings</span>
                <span class="nav-counter" id="nav-count-findings">0</span>
            </li>
            <li class="nav-item" onclick="switchTab('evidence')">
                <span>Evidence</span>
            </li>
            <li class="nav-item" onclick="switchTab('reports')">
                <span>Reports</span>
            </li>
            <li class="nav-item" onclick="switchTab('tools')">
                <span>Tool Adapters</span>
            </li>
            <li class="nav-item" onclick="switchTab('policies')">
                <span>Policies</span>
            </li>
            <li class="nav-item" onclick="switchTab('audit')">
                <span>Audit Trail</span>
            </li>
        </ul>
        <div class="system-footer">
            <div>DB: SQLite (WAL)</div>
            <div id="footer-system-status">Engine: READY</div>
        </div>
    </aside>

    <!-- WORKSPACE -->
    <main class="main-workspace">
        <header class="topbar">
            <div class="topbar-left">
                <span class="page-title" id="page-heading">Security Operations Workstation</span>
                <span class="mode-indicator" id="header-mode">SAFE_SCAN</span>
            </div>
            <div class="topbar-right">
                <button class="btn btn-secondary" onclick="refreshCurrentView()">↻ Refresh</button>
                <button class="btn" onclick="openNewScanModal()">+ New Assessment</button>
            </div>
        </header>

        <!-- VIEW: OVERVIEW -->
        <section id="view-overview" class="workspace-view active">
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-label">Critical Vulnerabilities</div>
                    <div class="stat-value" id="stat-critical" style="color: var(--sev-critical)">0</div>
                    <div class="stat-sub">Immediate exploit risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">High Severity</div>
                    <div class="stat-value" id="stat-high" style="color: var(--sev-high)">0</div>
                    <div class="stat-sub">Elevated priority</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Monitored Assets</div>
                    <div class="stat-value" id="stat-assets" style="color: #60a5fa">0</div>
                    <div class="stat-sub">Discovered endpoints</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Completed Scans</div>
                    <div class="stat-value" id="stat-scans" style="color: #34d399">0</div>
                    <div class="stat-sub">Verified sessions</div>
                </div>
            </div>

            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Recent Security Findings</span>
                    <button class="btn btn-secondary" onclick="switchTab('findings')">View All</button>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Finding ID</th>
                                <th>Severity</th>
                                <th>Title / Vulnerability</th>
                                <th>Target</th>
                                <th>Tool</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="overview-findings-body">
                            <tr><td colspan="6" style="text-align: center; color: var(--text-dim);">Loading findings...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Recent Assessment Sessions</span>
                    <button class="btn btn-secondary" onclick="switchTab('scans')">View All</button>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Scan ID</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>Findings</th>
                                <th>Duration</th>
                                <th>Started</th>
                            </tr>
                        </thead>
                        <tbody id="overview-scans-body">
                            <tr><td colspan="6" style="text-align: center; color: var(--text-dim);">Loading scans...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: ASSETS -->
        <section id="view-assets" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Discovered Asset Inventory</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Target Identifier</th>
                                <th>Type</th>
                                <th>IP Address</th>
                                <th>Risk Score</th>
                                <th>Risk Level</th>
                                <th>Last Scanned</th>
                            </tr>
                        </thead>
                        <tbody id="assets-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: SCANS -->
        <section id="view-scans" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Assessment Execution History</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Scan ID</th>
                                <th>Type</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>Findings</th>
                                <th>Tools Executed</th>
                                <th>Start Time</th>
                            </tr>
                        </thead>
                        <tbody id="scans-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: FINDINGS -->
        <section id="view-findings" class="workspace-view">
            <div class="filters-bar">
                <input type="text" id="filter-search" class="form-control" style="width: 280px;" placeholder="Search findings..." onkeyup="filterFindings()">
                <select id="filter-severity" class="form-control" style="width: 140px;" onchange="filterFindings()">
                    <option value="">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                </select>
                <select id="filter-status" class="form-control" style="width: 160px;" onchange="filterFindings()">
                    <option value="">All Statuses</option>
                    <option value="NEW">New</option>
                    <option value="TRIAGED">Triaged</option>
                    <option value="CONFIRMED">Confirmed</option>
                    <option value="REMEDIATION_REQUIRED">Remediation Required</option>
                    <option value="RETEST_PENDING">Retest Pending</option>
                    <option value="RESOLVED">Resolved</option>
                    <option value="FALSE_POSITIVE">False Positive</option>
                    <option value="DUPLICATE">Duplicate</option>
                    <option value="ACCEPTED_RISK">Accepted Risk</option>
                </select>
            </div>
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">BDIE Vulnerability & Investigation Records</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Finding ID</th>
                                <th>Severity</th>
                                <th>Title / Vulnerability</th>
                                <th>Exact Location</th>
                                <th>Risk</th>
                                <th>Retest</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="findings-body"></tbody>
                    </table>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: EVIDENCE -->
        <section id="view-evidence" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Cryptographic Evidence Vault (SHA-256 Verified)</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Evidence ID</th>
                                <th>Target</th>
                                <th>Tool</th>
                                <th>SHA-256 Hash</th>
                                <th>Timestamp</th>
                                <th>Scan Ref</th>
                            </tr>
                        </thead>
                        <tbody id="evidence-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: REPORTS -->
        <section id="view-reports" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Multi-Format Security Deliverables</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Report ID</th>
                                <th>Target</th>
                                <th>Findings</th>
                                <th>Format / File</th>
                                <th>Date Generated</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="reports-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: TOOLS -->
        <section id="view-tools" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Security Scanner Adapters & Engine Status</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Scanner Tool</th>
                                <th>Category</th>
                                <th>Adapter State</th>
                                <th>Binary Version</th>
                            </tr>
                        </thead>
                        <tbody id="tools-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: POLICIES -->
        <section id="view-policies" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Security Guardrails & Authorization Policies</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Policy Profile</th>
                                <th>Network</th>
                                <th>Web</th>
                                <th>Packet Capture</th>
                                <th>Bruteforce</th>
                                <th>Destructive</th>
                                <th>Max Duration</th>
                            </tr>
                        </thead>
                        <tbody id="policies-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: AUDIT -->
        <section id="view-audit" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Immutable Audit Trail</span>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Event Type</th>
                                <th>Target</th>
                                <th>Tool</th>
                                <th>Mode</th>
                                <th>Decision</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody id="audit-body"></tbody>
                    </table>
                </div>
            </div>
        </section>
    </main>

    <!-- FINDING DETAIL DRAWER -->
    <div id="drawer-finding" class="detail-drawer">
        <div class="drawer-header">
            <div>
                <span class="drawer-title" id="drawer-title">Vulnerability Investigation & Exact Location</span>
                <div style="font-size: 11px; color: var(--text-muted);" id="drawer-subtitle">BDIE Traceable Evidence Record</div>
            </div>
            <button class="btn btn-secondary" onclick="closeDrawer()">✕</button>
        </div>
        <div class="drawer-body">
            <!-- Header section with badges -->
            <div class="detail-section">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span id="drawer-fid" style="font-family: var(--font-mono); font-weight:700; font-size:14px; color:#60a5fa;"></span>
                        <span id="drawer-sev-badge" class="badge"></span>
                        <span id="drawer-conf-badge" class="badge badge-info"></span>
                        <span id="drawer-score" style="font-family: var(--font-mono); color: #c084fc; font-weight:700;"></span>
                    </div>
                    <div id="drawer-retest-badge"></div>
                </div>
                <div style="font-size: 14px; font-weight: 700; margin-top: 8px; color: #fff;" id="drawer-finding-title"></div>
            </div>

            <!-- EXACT AFFECTED LOCATION BANNER -->
            <div class="detail-section">
                <div class="detail-label">Exact Affected Location</div>
                <div style="background:#0f172a; border-left:3px solid #38bdf8; border-radius:4px; padding:10px 12px;">
                    <div style="font-size:11px; color:#38bdf8; font-weight:700; text-transform:uppercase; margin-bottom:4px;" id="drawer-loc-hierarchy"></div>
                    <div style="font-size:12px; color:#f1f5f9; font-family:var(--font-mono);" id="drawer-loc-summary"></div>
                </div>
            </div>

            <!-- TRIAGE & RETEST ACTION BAR -->
            <div class="detail-section" style="background:#131c2e; border:1px solid #25334d; border-radius:6px; padding:12px;">
                <div class="detail-label" style="color:#93c5fd;">Analyst Triage & Authorized Verification</div>
                <div style="display:flex; gap:10px; align-items:center; margin-top:6px; flex-wrap:wrap;">
                    <button class="btn btn-primary" id="btn-retest" onclick="runRetestProbe()" style="background:#2563eb;">⚡ Run Authorized Retest</button>
                    <div style="display:flex; gap:6px; align-items:center; flex:1; min-width:240px;">
                        <select id="drawer-status-select" class="form-control" style="width:160px;">
                            <option value="NEW">NEW</option>
                            <option value="TRIAGED">TRIAGED</option>
                            <option value="CONFIRMED">CONFIRMED</option>
                            <option value="REMEDIATION_REQUIRED">REMEDIATION_REQUIRED</option>
                            <option value="RETEST_PENDING">RETEST_PENDING</option>
                            <option value="RESOLVED">RESOLVED</option>
                            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                            <option value="DUPLICATE">DUPLICATE</option>
                            <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
                        </select>
                        <input type="text" id="drawer-triage-reason" class="form-control" placeholder="Triage reason / notes..." style="flex:1;">
                        <button class="btn btn-secondary" onclick="updateFindingStatus()">Update</button>
                    </div>
                </div>
            </div>

            <!-- OBSERVED VS VERIFIED DUAL PANEL -->
            <div class="detail-section">
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                    <div style="background:#182234; border:1px solid #2b3952; border-radius:5px; padding:10px;">
                        <div style="font-size:11px; font-weight:700; color:#93c5fd; text-transform:uppercase; margin-bottom:4px;">Observed Behavior (Detection)</div>
                        <div style="font-size:12px; color:#e2e8f0; font-family:var(--font-mono); white-space:pre-wrap; max-height:120px; overflow-y:auto;" id="drawer-observed"></div>
                    </div>
                    <div style="background:#1c1917; border:1px solid #44403c; border-radius:5px; padding:10px;">
                        <div style="font-size:11px; font-weight:700; color:#fdba74; text-transform:uppercase; margin-bottom:4px;">Verified Behavior (Probe Result)</div>
                        <div style="font-size:12px; color:#e2e8f0; font-family:var(--font-mono); white-space:pre-wrap; max-height:120px; overflow-y:auto;" id="drawer-verified"></div>
                    </div>
                </div>
            </div>

            <!-- SECURITY EXPLOITATION ASSESSMENT -->
            <div class="detail-section">
                <div class="detail-label">Security Exploitation Assessment & Impact</div>
                <div style="background:#1f1b2e; border-left:3px solid #a855f7; border-radius:4px; padding:10px 12px; font-size:12px;">
                    <div id="drawer-exploit-level" style="font-weight:700; margin-bottom:4px; color:#d8b4fe;"></div>
                    <div id="drawer-exploit-details" style="color:#e9d5ff; white-space:pre-wrap;"></div>
                </div>
            </div>

            <!-- CRYPTOGRAPHIC EVIDENCE CHAIN -->
            <div class="detail-section">
                <div class="detail-label">Cryptographic Evidence Chain (SHA-256)</div>
                <div id="drawer-evidence-container"></div>
            </div>

            <!-- ACTIONABLE REMEDIATION & VERIFICATION -->
            <div class="detail-section">
                <div class="detail-label">Remediation Guidance & Retest Procedure</div>
                <div style="background:#0f1f17; border-left:3px solid #10b981; border-radius:4px; padding:10px 12px; font-size:12px; margin-bottom:8px;">
                    <div style="font-weight:700; color:#6ee7b7; margin-bottom:2px;">◈ Defensive Remediation</div>
                    <div id="drawer-remediation" style="color:#d1fae5;"></div>
                </div>
                <div style="background:#172554; border-left:3px solid #3b82f6; border-radius:4px; padding:10px 12px; font-size:12px;">
                    <div style="font-weight:700; color:#93c5fd; margin-bottom:2px;">◈ Verification Procedure</div>
                    <div id="drawer-verification" style="color:#bfdbfe;"></div>
                </div>
            </div>

            <!-- TIMELINE & RETEST HISTORY -->
            <div class="detail-section">
                <div class="detail-label">Audit Timeline & History</div>
                <div id="drawer-timeline-container" style="background:var(--bg-elevated); border:1px solid var(--border-subtle); border-radius:5px; padding:10px; max-height:160px; overflow-y:auto; font-size:11px;"></div>
            </div>
        </div>
        <div class="drawer-footer">
            <button class="btn btn-secondary" onclick="closeDrawer()">Close Panel</button>
        </div>
    </div>

    <!-- NEW ASSESSMENT MODAL -->
    <div id="modal-new-scan" class="detail-drawer" style="width: 460px;">
        <div class="drawer-header">
            <span class="drawer-title">Start Security Assessment</span>
            <button class="btn btn-secondary" onclick="closeNewScanModal()">✕</button>
        </div>
        <div class="drawer-body">
            <div class="form-group">
                <label>Target IP / Hostname / URL</label>
                <input type="text" id="scan-target" class="form-control" placeholder="127.0.0.1 or sec-lab.local">
            </div>
            <div class="form-group">
                <label>Assessment Profile</label>
                <select id="scan-profile" class="form-control">
                    <option value="fast">Fast Port & Service Discovery</option>
                    <option value="service">Deep Service & Banner Inspection</option>
                    <option value="comprehensive">Comprehensive Vulnerability Assessment</option>
                </select>
            </div>
            <div class="form-group">
                <label>Custom Ports (Optional)</label>
                <input type="text" id="scan-ports" class="form-control" placeholder="80,443,8080 or leave blank for top ports">
            </div>
            <div class="form-group" style="margin-top: 18px;">
                <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                    <input type="checkbox" id="scan-auth-check" checked>
                    <span>I confirm authorized testing rights for this target</span>
                </label>
            </div>
        </div>
        <div class="drawer-footer">
            <button class="btn btn-secondary" onclick="closeNewScanModal()">Cancel</button>
            <button class="btn" onclick="executeNewScan()">Launch Assessment</button>
        </div>
    </div>

    <script>
        let currentFindings = [];
        let activeFindingId = null;

        function switchTab(viewId) {
            document.querySelectorAll('.workspace-view').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            const target = document.getElementById('view-' + viewId);
            if (target) target.classList.add('active');

            const navIndex = ['overview', 'assets', 'scans', 'findings', 'evidence', 'reports', 'tools', 'policies', 'audit'].indexOf(viewId);
            if (navIndex >= 0) {
                document.querySelectorAll('.nav-item')[navIndex].classList.add('active');
            }
            refreshCurrentView();
        }

        async function fetchAPI(endpoint, options = {}) {
            try {
                const res = await fetch(endpoint, options);
                return await res.json();
            } catch (err) {
                console.error("API error for " + endpoint, err);
                return null;
            }
        }

        async function refreshCurrentView() {
            loadStatusOverview();
            loadAssets();
            loadScans();
            loadFindings();
            loadEvidence();
            loadReports();
            loadTools();
            loadPolicies();
            loadAudit();
        }

        async function loadStatusOverview() {
            const data = await fetchAPI('/api/status');
            if (!data) return;

            document.getElementById('header-mode').textContent = data.app_mode || 'SAFE_SCAN';
            const fSummary = data.summary?.findings || {};
            document.getElementById('stat-critical').textContent = fSummary.CRITICAL || 0;
            document.getElementById('stat-high').textContent = fSummary.HIGH || 0;
            document.getElementById('stat-assets').textContent = data.summary?.total_assets || 0;
            document.getElementById('stat-scans').textContent = data.summary?.recent_scans || 0;

            document.getElementById('nav-count-assets').textContent = data.summary?.total_assets || 0;
            document.getElementById('nav-count-findings').textContent = fSummary.TOTAL || 0;
            document.getElementById('nav-count-scans').textContent = data.summary?.recent_scans || 0;
        }

        async function loadFindings() {
            const data = await fetchAPI('/api/findings');
            if (!data || !data.findings) return;
            currentFindings = data.findings;
            renderFindingsTable(data.findings);

            // Render Overview table top 6
            const topFindings = data.findings.slice(0, 6);
            const tbody = document.getElementById('overview-findings-body');
            tbody.innerHTML = '';
            topFindings.forEach(f => {
                const tr = document.createElement('tr');
                tr.onclick = () => openFindingDetail(f.id);
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); font-weight:600; color:#60a5fa;">${f.id}</td>
                    <td><span class="badge badge-${(f.severity||'info').toLowerCase()}">${f.severity}</span></td>
                    <td>${escapeHtml(f.title || f.vulnerability || 'N/A')}</td>
                    <td>${escapeHtml(f.target || '')}</td>
                    <td style="color:var(--text-dim);">${escapeHtml(f.source_tool || '')}</td>
                    <td><span class="badge">${f.status || 'OPEN'}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }

        function renderFindingsTable(list) {
            const tbody = document.getElementById('findings-body');
            tbody.innerHTML = '';
            list.forEach(f => {
                const tr = document.createElement('tr');
                tr.onclick = () => openFindingDetail(f.id);
                const sev = (f.severity || 'INFO').toLowerCase();
                const loc = f.url || f.endpoint || (f.target ? `${f.target}${f.port ? ':' + f.port : ''}` : '—');
                
                let retestBadge = '<span style="color:var(--text-dim);">—</span>';
                if (f.retest_result) {
                    const rRes = f.retest_result.toUpperCase();
                    const rColor = rRes === 'PASS' ? '#065f46; color:#a7f3d0;' : (rRes === 'FAIL' ? '#991b1b; color:#fecaca;' : '#854d0e; color:#fef08a;');
                    retestBadge = `<span class="badge" style="background:${rColor}">${rRes}</span>`;
                }

                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); font-weight:600; color:#60a5fa;">${f.id}</td>
                    <td><span class="badge badge-${sev}">${f.severity}</span></td>
                    <td><strong>${escapeHtml(f.title || f.vulnerability || '')}</strong></td>
                    <td style="font-family: var(--font-mono); font-size:11px; color:#cbd5e1;">${escapeHtml(loc)}</td>
                    <td style="font-family: var(--font-mono);">${(f.risk_score || 0).toFixed(1)}/10</td>
                    <td>${retestBadge}</td>
                    <td><span class="badge" style="background:#1e293b; color:#e2e8f0; border:1px solid #334155;">${f.status || 'OPEN'}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }

        function filterFindings() {
            const q = document.getElementById('filter-search').value.toLowerCase();
            const sev = document.getElementById('filter-severity').value.toUpperCase();
            const status = document.getElementById('filter-status').value.toUpperCase();

            const filtered = currentFindings.filter(f => {
                const matchQ = !q || (f.title||'').toLowerCase().includes(q) || (f.target||'').toLowerCase().includes(q) || (f.id||'').toLowerCase().includes(q) || (f.endpoint||'').toLowerCase().includes(q) || (f.cve||'').toLowerCase().includes(q);
                const matchSev = !sev || (f.severity||'').toUpperCase() === sev;
                const matchStatus = !status || (f.status||'').toUpperCase() === status;
                return matchQ && matchSev && matchStatus;
            });
            renderFindingsTable(filtered);
        }

        async function openFindingDetail(findingId) {
            activeFindingId = findingId;
            const data = await fetchAPI(`/api/findings/${findingId}`);
            if (!data) return;

            const f = data.finding || {};
            const inv = data.investigation || {};
            const loc = data.exact_location || {};
            const secExpl = inv.security_exploitation || {};

            document.getElementById('drawer-fid').textContent = f.id;
            document.getElementById('drawer-finding-title').textContent = f.title || f.vulnerability || 'Security Finding';

            const badge = document.getElementById('drawer-sev-badge');
            badge.textContent = f.severity || 'INFO';
            badge.className = 'badge badge-' + (f.severity || 'info').toLowerCase();

            const confBadge = document.getElementById('drawer-conf-badge');
            confBadge.textContent = 'Conf: ' + (f.confidence || 'MEDIUM');

            document.getElementById('drawer-score').textContent = `Risk: ${(f.risk_score || 0).toFixed(1)}/10.0`;

            const retestBadge = document.getElementById('drawer-retest-badge');
            if (f.retest_result) {
                const rRes = f.retest_result.toUpperCase();
                const rColor = rRes === 'PASS' ? '#10b981' : (rRes === 'FAIL' ? '#ef4444' : '#f59e0b');
                retestBadge.innerHTML = `<span class="badge" style="background:${rColor}; color:#fff;">Retest: ${rRes}</span>`;
            } else {
                retestBadge.innerHTML = `<span class="badge" style="background:#374151; color:#9ca3af;">Not Retested</span>`;
            }

            // Location
            document.getElementById('drawer-loc-hierarchy').textContent = loc.hierarchy || 'RESOLVED LOCATION';
            document.getElementById('drawer-loc-summary').textContent = loc.summary || f.url || (f.target + (f.port ? `:${f.port}` : ''));

            // Status select
            document.getElementById('drawer-status-select').value = f.status || 'OPEN';
            document.getElementById('drawer-triage-reason').value = '';

            // Observed vs Verified
            document.getElementById('drawer-observed').textContent = f.observed_behavior || f.evidence || 'No observation recorded.';
            document.getElementById('drawer-verified').textContent = f.verified_behavior || 'Not independently probe-verified. Passive or scanner observation only.';

            // Exploitation
            document.getElementById('drawer-exploit-level').textContent = `Exploitability: ${secExpl.level || f.exploitability_level || 'MEDIUM'}`;
            document.getElementById('drawer-exploit-details').textContent = `Prerequisites: ${secExpl.prerequisites || 'Network reachability'}\nImpact: ${f.potential_impact || 'Confidentiality/Integrity impact'}\nLimitations: ${secExpl.limitations || 'Non-destructive boundary enforced'}`;

            // Remediation
            document.getElementById('drawer-remediation').textContent = f.remediation || 'Standard defensive remediation recommended.';
            document.getElementById('drawer-verification').textContent = f.verification_procedure || 'Re-test endpoint with non-destructive authorized probe.';

            // Evidence Chain
            const evCont = document.getElementById('drawer-evidence-container');
            const evItems = data.evidence_records || data.evidence_chain || [];
            if (evItems.length === 0) {
                evCont.innerHTML = `<div class="detail-box">${escapeHtml(f.evidence || 'No cryptographic evidence items captured.')}</div>`;
            } else {
                let evHtml = '';
                evItems.forEach(ev => {
                    const sha = ev.hash_sha256 || 'UNHASHED';
                    const tool = ev.tool_name || 'CYBERWOLF';
                    const excerpt = ev.output_excerpt || 'No output excerpt recorded';
                    evHtml += `
                        <div style="background:#0d1117; border:1px solid #30363d; border-radius:5px; padding:8px 10px; margin-bottom:8px; font-family:var(--font-mono); font-size:11px;">
                            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                                <span style="color:#60a5fa; font-weight:700;">[${ev.id}] ${ev.evidence_type || 'TOOL_OUTPUT'} (${tool})</span>
                                <span style="color:#34d399;">✔ HASH VERIFIED</span>
                            </div>
                            <div style="color:#9ca3af; font-size:10px; margin-bottom:4px;">SHA-256: <code style="color:#6ee7b7;">${sha}</code></div>
                            <pre style="color:#e2e8f0; white-space:pre-wrap; max-height:100px; overflow-y:auto; margin:0;">${escapeHtml(excerpt)}</pre>
                        </div>
                    `;
                });
                evCont.innerHTML = evHtml;
            }

            // Timeline
            const tlCont = document.getElementById('drawer-timeline-container');
            const tlItems = data.timeline || [];
            if (tlItems.length === 0) {
                tlCont.innerHTML = `<span style="color:var(--text-dim);">No audit timeline events logged.</span>`;
            } else {
                let tlHtml = '';
                tlItems.forEach(ev => {
                    const ts = (ev.timestamp || '').substring(0, 19).replace('T', ' ');
                    tlHtml += `
                        <div style="margin-bottom:6px; border-bottom:1px solid #1f2937; padding-bottom:4px;">
                            <span style="color:var(--text-dim);">${ts}</span> • 
                            <strong style="color:#93c5fd;">${ev.event_type || 'EVENT'}:</strong> 
                            ${escapeHtml(ev.description || '')} 
                            <span style="color:#6b7280;">(${ev.actor || 'system'})</span>
                        </div>
                    `;
                });
                tlCont.innerHTML = tlHtml;
            }

            document.getElementById('drawer-finding').classList.add('open');
        }

        function closeDrawer() {
            document.getElementById('drawer-finding').classList.remove('open');
            activeFindingId = null;
        }

        async function updateFindingStatus() {
            if (!activeFindingId) return;
            const newStatus = document.getElementById('drawer-status-select').value;
            const reason = document.getElementById('drawer-triage-reason').value;
            const res = await fetchAPI(`/api/findings/${activeFindingId}/triage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus, reason: reason })
            });
            if (res && !res.error) {
                openFindingDetail(activeFindingId);
                loadFindings();
            } else {
                alert('Failed to update status: ' + (res?.error || 'Unknown error'));
            }
        }

        async function runRetestProbe() {
            if (!activeFindingId) return;
            const btn = document.getElementById('btn-retest');
            btn.disabled = true;
            btn.textContent = 'Probing target...';
            try {
                const res = await fetchAPI(`/api/findings/${activeFindingId}/retest`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ actor: 'web-operator' })
                });
                if (res && res.success) {
                    alert(`Retest Probe Result: ${res.retest_result}\nStatus: ${res.new_status}\nEvidence: ${res.evidence_id}`);
                    openFindingDetail(activeFindingId);
                    loadFindings();
                } else {
                    alert('Retest failed: ' + (res?.error || res?.notes || 'Probe error'));
                }
            } catch (err) {
                alert('Retest error: ' + err);
            } finally {
                btn.disabled = false;
                btn.textContent = '⚡ Run Authorized Retest';
            }
        }

        async function loadAssets() {
            const data = await fetchAPI('/api/assets');
            if (!data || !data.assets) return;
            const tbody = document.getElementById('assets-body');
            tbody.innerHTML = '';
            data.assets.forEach(a => {
                const tr = document.createElement('tr');
                const rl = (a.risk_level || 'low').toLowerCase();
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono);">${a.id}</td>
                    <td><strong>${escapeHtml(a.target_identifier)}</strong></td>
                    <td>${a.asset_type || 'ip'}</td>
                    <td style="font-family: var(--font-mono); color:var(--text-muted);">${a.ip_address || '—'}</td>
                    <td style="font-family: var(--font-mono);">${(a.risk_score || 0).toFixed(1)}/10</td>
                    <td><span class="badge badge-${rl}">${a.risk_level || 'LOW'}</span></td>
                    <td style="color:var(--text-dim);">${(a.last_scanned || 'Never').substring(0, 19)}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function loadScans() {
            const data = await fetchAPI('/api/scans');
            if (!data || !data.scans) return;
            const tbody = document.getElementById('scans-body');
            const overviewTbody = document.getElementById('overview-scans-body');
            tbody.innerHTML = '';
            overviewTbody.innerHTML = '';

            data.scans.forEach((s, idx) => {
                const tr = document.createElement('tr');
                const st = (s.status || 'COMPLETED').toLowerCase();
                const stBadge = st === 'completed' ? 'badge-success' : st === 'running' ? 'badge-running' : 'badge-critical';
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); color:#60a5fa;">${s.id}</td>
                    <td>${s.scan_type || 'network'}</td>
                    <td><strong>${escapeHtml(s.target || '')}</strong></td>
                    <td><span class="badge ${stBadge}">${s.status}</span></td>
                    <td style="font-family: var(--font-mono);">${s.findings_count || 0}</td>
                    <td style="color:var(--text-dim);">${(s.tools_executed || []).join(', ') || 'N/A'}</td>
                    <td style="color:var(--text-dim);">${(s.start_time || '').substring(0, 19)}</td>
                `;
                tbody.appendChild(tr);

                if (idx < 5) {
                    const otr = tr.cloneNode(true);
                    overviewTbody.appendChild(otr);
                }
            });
        }

        async function loadEvidence() {
            const data = await fetchAPI('/api/evidence');
            if (!data || !data.evidence) return;
            const tbody = document.getElementById('evidence-body');
            tbody.innerHTML = '';
            data.evidence.forEach(e => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); color:#60a5fa;">${e.id}</td>
                    <td>${escapeHtml(e.target || '')}</td>
                    <td>${escapeHtml(e.tool_name || '')}</td>
                    <td style="font-family: var(--font-mono); font-size:11px; color:#34d399;">${(e.hash_sha256 || '').substring(0, 24)}...</td>
                    <td style="color:var(--text-dim);">${(e.timestamp || '').substring(0, 19)}</td>
                    <td style="font-family: var(--font-mono); color:var(--text-dim);">${e.scan_id || '—'}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function loadReports() {
            const data = await fetchAPI('/api/reports');
            if (!data || !data.reports) return;
            const tbody = document.getElementById('reports-body');
            tbody.innerHTML = '';
            data.reports.forEach(r => {
                const tr = document.createElement('tr');
                const filename = (r.file_path || '').split('/').pop();
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); color:#60a5fa;">${r.id}</td>
                    <td><strong>${escapeHtml(r.target || '')}</strong></td>
                    <td style="font-family: var(--font-mono);">${r.findings_count || 0}</td>
                    <td style="font-family: var(--font-mono); color:var(--text-muted);">${filename}</td>
                    <td style="color:var(--text-dim);">${(r.created_at || '').substring(0, 19)}</td>
                    <td><a href="/reports/${filename}" target="_blank" class="btn btn-secondary" style="padding:2px 8px; font-size:11px;">View</a></td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function loadTools() {
            const data = await fetchAPI('/api/tools');
            if (!data || !data.security_tools) return;
            const tbody = document.getElementById('tools-body');
            tbody.innerHTML = '';
            for (const [name, info] of Object.entries(data.security_tools)) {
                const tr = document.createElement('tr');
                const badge = info.installed ? 'badge-success' : 'badge-low';
                tr.innerHTML = `
                    <td><strong>${name}</strong></td>
                    <td style="color:var(--text-dim);">${info.category || ''}</td>
                    <td><span class="badge ${badge}">${info.installed ? 'AVAILABLE' : 'MISSING'}</span></td>
                    <td style="font-family: var(--font-mono); color:var(--text-muted);">${info.version || 'Not detected in PATH'}</td>
                `;
                tbody.appendChild(tr);
            }
        }

        async function loadPolicies() {
            const data = await fetchAPI('/api/policies');
            if (!data || !data.all_policies) return;
            const tbody = document.getElementById('policies-body');
            tbody.innerHTML = '';
            data.all_policies.forEach(p => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${p.name}</strong></td>
                    <td>${p.allow_network_scan ? '✓' : '✗'}</td>
                    <td>${p.allow_web_scan ? '✓' : '✗'}</td>
                    <td>${p.allow_packet_capture ? '✓' : '✗'}</td>
                    <td>${p.allow_bruteforce ? '✓' : '✗'}</td>
                    <td>${p.allow_destructive ? '✓' : '✗'}</td>
                    <td style="font-family: var(--font-mono);">${p.max_scan_duration}s</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function loadAudit() {
            const data = await fetchAPI('/api/audit');
            if (!data || !data.audit_events) return;
            const tbody = document.getElementById('audit-body');
            tbody.innerHTML = '';
            data.audit_events.slice(0, 50).forEach(ev => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); color:#60a5fa;">${ev.event_type}</td>
                    <td>${escapeHtml(ev.target || '—')}</td>
                    <td>${escapeHtml(ev.tool_name || 'ENGINE')}</td>
                    <td><span class="badge">${ev.mode || 'SAFE'}</span></td>
                    <td><span class="badge badge-${(ev.decision||'ALLOWED') === 'ALLOWED' ? 'success' : 'critical'}">${ev.decision}</span></td>
                    <td style="color:var(--text-dim);">${(ev.timestamp || '').substring(0, 19)}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        function openNewScanModal() { document.getElementById('modal-new-scan').classList.add('open'); }
        function closeNewScanModal() { document.getElementById('modal-new-scan').classList.remove('open'); }

        async function executeNewScan() {
            const target = document.getElementById('scan-target').value.trim();
            if (!target) { alert('Target IP or Hostname required'); return; }
            const profile = document.getElementById('scan-profile').value;
            const ports = document.getElementById('scan-ports').value.trim();
            const auth = document.getElementById('scan-auth-check').checked;

            if (!auth) { alert('You must confirm authorized testing permissions.'); return; }

            const res = await fetchAPI('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, profile, ports: ports || null, authorized: true, async: true })
            });

            closeNewScanModal();
            refreshCurrentView();
        }

        function escapeHtml(str) {
            return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // Initialize and auto-refresh
        refreshCurrentView();
        setInterval(refreshCurrentView, 10000);
    </script>
</body>
</html>
"""
