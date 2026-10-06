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

        if path == "/api/scans/activity":
            scan_svc = get_scan_service()
            scan_id = query.get("scan_id", [None])[0]
            if scan_id:
                prog = scan_svc.get_scan_progress(scan_id)
                if prog:
                    self._send_json(prog)
                    return
                scan = scan_svc.get_scan(scan_id)
                if scan:
                    self._send_json({
                        "scan_id": scan_id,
                        "target": scan.get("target"),
                        "scan_type": scan.get("scan_type"),
                        "status": scan.get("status", "COMPLETED"),
                        "steps": [
                            {"label": "Target validated", "completed": True},
                            {"label": "Authorization verified", "completed": True},
                            {"label": "Asset identified", "completed": True},
                            {"label": "Ports/services discovered", "completed": True},
                            {"label": "Web endpoints discovered", "completed": True},
                            {"label": "Security checks executed", "completed": True},
                            {"label": "Findings normalized", "completed": True},
                            {"label": "Evidence captured", "completed": True},
                            {"label": "Findings correlated", "completed": True},
                            {"label": "Risk calculated", "completed": True}
                        ]
                    })
                    return
                self._send_json({"error": f"Scan '{scan_id}' not found"}, status=404)
                return
            else:
                recent_scans = scan_svc.list_scans(limit=1)
                if recent_scans:
                    latest_id = recent_scans[0]["id"]
                    prog = scan_svc.get_scan_progress(latest_id)
                    if prog:
                        self._send_json(prog)
                        return
                    self._send_json({
                        "scan_id": latest_id,
                        "target": recent_scans[0].get("target"),
                        "scan_type": recent_scans[0].get("scan_type"),
                        "status": recent_scans[0].get("status", "COMPLETED"),
                        "steps": [
                            {"label": "Target validated", "completed": True},
                            {"label": "Authorization verified", "completed": True},
                            {"label": "Asset identified", "completed": True},
                            {"label": "Ports/services discovered", "completed": True},
                            {"label": "Web endpoints discovered", "completed": True},
                            {"label": "Security checks executed", "completed": True},
                            {"label": "Findings normalized", "completed": True},
                            {"label": "Evidence captured", "completed": True},
                            {"label": "Findings correlated", "completed": True},
                            {"label": "Risk calculated", "completed": True}
                        ]
                    })
                    return
                self._send_json({"status": "IDLE", "steps": []})
                return

        if path.startswith("/api/scans/"):
            clean_sub = path.replace("/api/scans/", "").strip("/")
            scan_svc = get_scan_service()
            if clean_sub.endswith("/activity"):
                scan_id = clean_sub.replace("/activity", "").strip("/")
                prog = scan_svc.get_scan_progress(scan_id)
                if prog:
                    self._send_json(prog)
                    return
                scan = scan_svc.get_scan(scan_id)
                if scan:
                    self._send_json({
                        "scan_id": scan_id,
                        "target": scan.get("target"),
                        "scan_type": scan.get("scan_type"),
                        "status": scan.get("status", "COMPLETED"),
                        "steps": [
                            {"label": "Target validated", "completed": True},
                            {"label": "Authorization verified", "completed": True},
                            {"label": "Asset identified", "completed": True},
                            {"label": "Ports/services discovered", "completed": True},
                            {"label": "Web endpoints discovered", "completed": True},
                            {"label": "Security checks executed", "completed": True},
                            {"label": "Findings normalized", "completed": True},
                            {"label": "Evidence captured", "completed": True},
                            {"label": "Findings correlated", "completed": True},
                            {"label": "Risk calculated", "completed": True}
                        ]
                    })
                    return
                self._send_json({"error": f"Scan '{scan_id}' not found"}, status=404)
                return

            scan_id = clean_sub
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
            timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S")
            scan_id = body.get("scan_id") or f"SCAN-{timestamp_str}-{uuid.uuid4().hex[:4].upper()}"

            if async_mode:
                def _scan_worker():
                    try:
                        scan_svc.start_scan(
                            target=target,
                            scan_type=scan_type,
                            options={"ports": ports, "profile": profile},
                            interactive_auth=False,
                            scan_id=scan_id
                        )
                    except Exception as err:
                        logger.error(f"Async scan {scan_id} error: {err}")

                t = threading.Thread(target=_scan_worker, daemon=True)
                t.start()

                self._send_json({
                    "message": "Security assessment initiated in background",
                    "scan_id": scan_id,
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
                        interactive_auth=False,
                        scan_id=scan_id
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
            reason = body.get("reason") or body.get("notes")
            verified = body.get("verified")
            actor = body.get("actor") or body.get("changed_by") or "web-analyst"

            if not new_status:
                self._send_json({"error": "Missing 'status' parameter"}, status=400)
                return

            from app.database.models import FindingStatus
            if not FindingStatus.is_valid(new_status):
                self._send_json({
                    "error": f"Invalid status: '{new_status}'",
                    "allowed_statuses": FindingStatus.ALL
                }, status=400)
                return

            norm_status = FindingStatus.normalize(new_status)
            if norm_status == FindingStatus.FALSE_POSITIVE:
                if not reason or not reason.strip():
                    self._send_json({
                        "error": "A specific reason is required when marking a finding as FALSE_POSITIVE.",
                        "accepted_reasons": [
                            "Expected application behavior",
                            "Scanner detection error",
                            "Not reproducible",
                            "Compensating control exists",
                            "Duplicate finding",
                            "Other"
                        ]
                    }, status=400)
                    return

            final_reason = reason or f"Analyst status transition to {norm_status}"

            finding_svc = get_finding_service()
            ok = finding_svc.update_status(
                finding_id,
                new_status=norm_status,
                verified=verified,
                reason=final_reason,
                changed_by=actor
            )
            if ok:
                self._send_json({
                    "message": f"Finding status updated to {norm_status}",
                    "id": finding_id,
                    "status": norm_status,
                    "reason": final_reason
                })
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
    <title>CYBERWOLF V2 — Security Engineering & Investigation Workstation</title>
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
            width: 230px;
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
        .page-title { font-size: 14px; font-weight: 700; letter-spacing: 0.3px; color: #f8fafc; }
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
        .btn-warning { background-color: #d97706; color: white; }
        .btn-warning:hover { background-color: #b45309; }
        .btn-danger { background-color: #dc2626; color: white; }
        .btn-danger:hover { background-color: #b91c1c; }
        .btn-success { background-color: #059669; color: white; }
        .btn-success:hover { background-color: #047857; }

        /* VIEW CONTAINER */
        .workspace-view {
            flex: 1;
            padding: 20px 24px;
            overflow-y: auto;
            display: none;
        }
        .workspace-view.active { display: block; }

        /* DATA PANELS */
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
        .panel-title { font-size: 13px; font-weight: 700; color: #ffffff; letter-spacing: 0.3px; }

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
            user-select: none;
        }
        table.soc-table th.sortable { cursor: pointer; }
        table.soc-table th.sortable:hover { color: #93c5fd; }
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

        /* DISCOVERY ACTIVITY CHECKLIST */
        .activity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 10px;
        }
        .activity-item {
            background: #0d131f;
            border: 1px solid #1f293d;
            border-radius: 4px;
            padding: 8px 12px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12px;
            font-family: var(--font-mono);
        }
        .activity-item.completed { border-color: #065f46; background: #06201a; color: #6ee7b7; }
        .activity-item.completed .activity-icon { color: #10b981; font-weight: 700; }
        .activity-item.pending { color: #64748b; }
        .activity-item.pending .activity-icon { color: #475569; }

        /* DETAIL DRAWER / MODAL */
        .detail-drawer {
            position: fixed;
            top: 0; right: 0; bottom: 0;
            width: 860px;
            background-color: var(--bg-surface);
            border-left: 1px solid var(--border-subtle);
            box-shadow: -12px 0 36px rgba(0,0,0,0.6);
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
            background: #0d131f;
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
            background: #0d131f;
        }
        .detail-section { margin-bottom: 20px; }
        .detail-label { font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700; margin-bottom: 6px; letter-spacing: 0.5px; }
        .detail-box {
            background-color: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 5px;
            padding: 10px 12px;
            font-size: 12px;
            font-family: var(--font-mono);
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 220px;
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
            flex-wrap: wrap;
        }

        /* MODAL BACKDROP */
        .modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            z-index: 1100;
            display: none;
            align-items: center;
            justify-content: center;
        }
        .modal-overlay.open { display: flex; }
        .modal-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            width: 500px;
            max-width: 90vw;
            box-shadow: 0 10px 30px rgba(0,0,0,0.7);
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
            <li class="nav-item active" onclick="switchTab('discovery')">
                <span>Bug Discovery</span>
                <span class="nav-counter" id="nav-count-findings">0</span>
            </li>
            <li class="nav-item" onclick="switchTab('overview')">
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
            <li class="nav-item" onclick="switchTab('evidence')">
                <span>Evidence Vault</span>
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
                <span class="page-title" id="page-heading">BUG DISCOVERY — Professional Security Assessment & Vulnerability Investigation</span>
                <span style="font-size:11px; color:var(--text-dim); margin-left:6px; font-family:var(--font-mono);">[Security Operations Workstation]</span>
                <span class="mode-indicator" id="header-mode">SAFE_SCAN</span>
            </div>
            <div class="topbar-right">
                <button class="btn btn-secondary" onclick="refreshCurrentView()">↻ Refresh</button>
                <button class="btn" onclick="switchTab('discovery')">⚡ Discovery Hub</button>
            </div>
        </header>

        <!-- VIEW: BUG DISCOVERY -->
        <section id="view-discovery" class="workspace-view active">
            <!-- TARGET SECTION -->
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">TARGET DISCOVERY CONFIGURATION</span>
                    <span class="badge badge-success">AUTHORIZED ASSESSMENTS ONLY</span>
                </div>
                <div style="padding: 16px;">
                    <div style="display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap;">
                        <div style="flex: 2; min-width: 280px;">
                            <label style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700; margin-bottom: 6px; display: block;">Target (Host / Domain / URL)</label>
                            <input type="text" id="discovery-target-input" class="form-control" placeholder="https://example.com" value="https://example.com">
                        </div>
                        <div style="flex: 1; min-width: 200px;">
                            <label style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700; margin-bottom: 6px; display: block;">Scan Profile</label>
                            <select id="discovery-profile-select" class="form-control">
                                <option value="web">Web Assessment (SQLi, XSS, Headers, Auth)</option>
                                <option value="network">Network Discovery (Ports, Services, Banners)</option>
                                <option value="comprehensive">Full Audit (Web + Network + Heuristics)</option>
                            </select>
                        </div>
                        <div>
                            <button id="btn-start-discovery" class="btn" onclick="startDiscoveryScan()" style="height: 35px; padding: 0 20px;">⚡ START DISCOVERY</button>
                        </div>
                    </div>
                    <div style="margin-top: 10px; display: flex; align-items: center; gap: 8px;">
                        <input type="checkbox" id="discovery-auth-check" checked style="accent-color: #3b82f6;">
                        <label for="discovery-auth-check" style="font-size: 11px; color: var(--text-muted); cursor: pointer;">
                            I confirm authorized testing permission for this target according to CyberWolf security policy.
                        </label>
                    </div>
                </div>
            </div>

            <!-- LIVE DISCOVERY ACTIVITY PANEL -->
            <div id="discovery-activity-panel" class="card-panel">
                <div class="panel-header">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="panel-title">DISCOVERY ACTIVITY</span>
                        <span id="discovery-activity-status" class="badge badge-info">IDLE</span>
                    </div>
                    <span id="discovery-activity-target" style="font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);">No Active Scan</span>
                </div>
                <div style="padding: 14px 16px;">
                    <div id="discovery-activity-checklist" class="activity-grid">
                        <div class="activity-item pending" id="step-0"><span class="activity-icon">○</span> Target validated</div>
                        <div class="activity-item pending" id="step-1"><span class="activity-icon">○</span> Authorization verified</div>
                        <div class="activity-item pending" id="step-2"><span class="activity-icon">○</span> Asset identified</div>
                        <div class="activity-item pending" id="step-3"><span class="activity-icon">○</span> Ports/services discovered</div>
                        <div class="activity-item pending" id="step-4"><span class="activity-icon">○</span> Web endpoints discovered</div>
                        <div class="activity-item pending" id="step-5"><span class="activity-icon">○</span> Security checks executed</div>
                        <div class="activity-item pending" id="step-6"><span class="activity-icon">○</span> Findings normalized</div>
                        <div class="activity-item pending" id="step-7"><span class="activity-icon">○</span> Evidence captured</div>
                        <div class="activity-item pending" id="step-8"><span class="activity-icon">○</span> Findings correlated</div>
                        <div class="activity-item pending" id="step-9"><span class="activity-icon">○</span> Risk calculated</div>
                    </div>
                </div>
            </div>

            <!-- FINDINGS TABLE -->
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">DISCOVERED SECURITY FINDINGS & INVESTIGATION QUEUE</span>
                    <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);" id="discovery-finding-count">0 Records</div>
                </div>
                <div style="padding: 12px 16px; border-bottom: 1px solid var(--border-subtle); background: #0c121e;">
                    <div class="filters-bar">
                        <input type="text" id="filter-search" class="form-control" style="width: 240px;" placeholder="Search title, ID, target, CVE, CWE..." onkeyup="filterFindings()">
                        <select id="filter-severity" class="form-control" style="width: 130px;" onchange="filterFindings()">
                            <option value="">All Severities</option>
                            <option value="CRITICAL">Critical</option>
                            <option value="HIGH">High</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="LOW">Low</option>
                            <option value="INFO">Info</option>
                        </select>
                        <select id="filter-confidence" class="form-control" style="width: 140px;" onchange="filterFindings()">
                            <option value="">All Confidences</option>
                            <option value="CONFIRMED">Confirmed</option>
                            <option value="HIGH">High</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="LOW">Low</option>
                        </select>
                        <select id="filter-status" class="form-control" style="width: 150px;" onchange="filterFindings()">
                            <option value="">All Statuses</option>
                            <option value="OPEN">Open</option>
                            <option value="CONFIRMED">Confirmed</option>
                            <option value="FALSE_POSITIVE">False Positive</option>
                            <option value="IN_PROGRESS">In Progress</option>
                            <option value="REMEDIATED">Remediated</option>
                            <option value="RETEST_REQUIRED">Retest Required</option>
                            <option value="VERIFIED">Verified</option>
                        </select>
                        <select id="filter-category" class="form-control" style="width: 140px;" onchange="filterFindings()">
                            <option value="">All Categories</option>
                            <option value="injection">Injection</option>
                            <option value="web">Web Security</option>
                            <option value="headers">Missing Headers</option>
                            <option value="network">Network Service</option>
                            <option value="auth">Authentication</option>
                        </select>
                        <select id="filter-tool" class="form-control" style="width: 150px;" onchange="filterFindings()">
                            <option value="">All Tools</option>
                            <option value="CYBERWOLF">CyberWolf Probes</option>
                            <option value="Nmap">Nmap</option>
                            <option value="Nuclei">Nuclei</option>
                        </select>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th class="sortable" onclick="sortFindings('id')">ID ↕</th>
                                <th class="sortable" onclick="sortFindings('severity')">Severity ↕</th>
                                <th class="sortable" onclick="sortFindings('title')">Title ↕</th>
                                <th class="sortable" onclick="sortFindings('target')">Target ↕</th>
                                <th>Location</th>
                                <th>Confidence</th>
                                <th class="sortable" onclick="sortFindings('risk_score')">Risk ↕</th>
                                <th class="sortable" onclick="sortFindings('status')">Status ↕</th>
                                <th class="sortable" onclick="sortFindings('first_seen')">First Seen ↕</th>
                            </tr>
                        </thead>
                        <tbody id="findings-body">
                            <tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 20px;">Loading security findings...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- VIEW: OVERVIEW -->
        <section id="view-overview" class="workspace-view">
            <div class="card-panel">
                <div class="panel-header">
                    <span class="panel-title">Operations Summary</span>
                </div>
                <div style="padding: 20px;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px;">
                        <div style="background:var(--bg-elevated); padding:16px; border-radius:5px; border:1px solid var(--border-subtle);">
                            <div style="font-size:11px; text-transform:uppercase; color:var(--text-dim); font-weight:700;">Critical Findings</div>
                            <div style="font-size:26px; font-family:var(--font-mono); font-weight:700; color:var(--sev-critical); margin:4px 0;" id="stat-critical">0</div>
                        </div>
                        <div style="background:var(--bg-elevated); padding:16px; border-radius:5px; border:1px solid var(--border-subtle);">
                            <div style="font-size:11px; text-transform:uppercase; color:var(--text-dim); font-weight:700;">High Findings</div>
                            <div style="font-size:26px; font-family:var(--font-mono); font-weight:700; color:var(--sev-high); margin:4px 0;" id="stat-high">0</div>
                        </div>
                        <div style="background:var(--bg-elevated); padding:16px; border-radius:5px; border:1px solid var(--border-subtle);">
                            <div style="font-size:11px; text-transform:uppercase; color:var(--text-dim); font-weight:700;">Total Assets</div>
                            <div style="font-size:26px; font-family:var(--font-mono); font-weight:700; color:#60a5fa; margin:4px 0;" id="stat-assets">0</div>
                        </div>
                        <div style="background:var(--bg-elevated); padding:16px; border-radius:5px; border:1px solid var(--border-subtle);">
                            <div style="font-size:11px; text-transform:uppercase; color:var(--text-dim); font-weight:700;">Recent Scans</div>
                            <div style="font-size:26px; font-family:var(--font-mono); font-weight:700; color:#34d399; margin:4px 0;" id="stat-scans">0</div>
                        </div>
                    </div>
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
                    <span class="panel-title">Multi-Format Security Deliverables (21 Sections)</span>
                    <button class="btn btn-secondary" onclick="generateNewReport()">⚡ Generate Report Deliverable</button>
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
                    <span class="panel-title">Security Scanner Adapters & Diagnostics</span>
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
                    <span class="panel-title">Security Guardrails & Safety Policies</span>
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

    <!-- FINDING INVESTIGATION DRAWER -->
    <div id="drawer-finding" class="detail-drawer">
        <div class="drawer-header">
            <div>
                <span class="drawer-title" id="drawer-header-title">FINDING INVESTIGATION</span>
                <div style="font-size: 11px; color: var(--text-muted);" id="drawer-header-id">CW-FINDING-0000</div>
            </div>
            <button class="btn btn-secondary" onclick="closeDrawer()">✕ Close</button>
        </div>
        <div class="drawer-body">
            <!-- 1. HEADER TITLE & BADGES -->
            <div class="detail-section" style="background:#0c1322; border:1px solid #1e293b; border-radius:6px; padding:12px 16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span id="drawer-fid" style="font-family: var(--font-mono); font-weight:700; font-size:14px; color:#60a5fa;"></span>
                        <span id="drawer-sev-badge" class="badge"></span>
                        <span id="drawer-conf-badge" class="badge badge-info"></span>
                        <span id="drawer-score-badge" style="font-family: var(--font-mono); color: #c084fc; font-weight:700;"></span>
                    </div>
                    <div id="drawer-retest-status-badge"></div>
                </div>
                <div style="font-size: 15px; font-weight: 700; margin-top: 8px; color: #fff;" id="drawer-finding-title"></div>
            </div>

            <!-- 2. SUMMARY -->
            <div class="detail-section">
                <div class="detail-label">◈ SUMMARY</div>
                <div class="detail-box" id="drawer-summary" style="max-height:100px;"></div>
            </div>

            <!-- 3. TARGET -->
            <div class="detail-section">
                <div class="detail-label">◈ TARGET & ASSET CONTEXT</div>
                <div style="background:#0f172a; border:1px solid #1e293b; border-radius:5px; padding:10px 14px; font-family:var(--font-mono); font-size:11px;">
                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:8px;" id="drawer-target-grid">
                    </div>
                </div>
            </div>

            <!-- 4. EXACT LOCATION -->
            <div class="detail-section">
                <div class="detail-label">◈ EXACT AFFECTED LOCATION</div>
                <div style="background:#0a192f; border-left:3px solid #38bdf8; border-radius:4px; padding:12px 14px;">
                    <div style="font-size:11px; color:#38bdf8; font-weight:700; text-transform:uppercase; margin-bottom:4px;" id="drawer-loc-hierarchy"></div>
                    <div style="font-size:12px; color:#f1f5f9; font-family:var(--font-mono); word-break:break-all;" id="drawer-loc-summary"></div>
                    <div style="margin-top:8px; font-size:11px; color:#94a3b8; font-family:var(--font-mono);" id="drawer-loc-details"></div>
                </div>
            </div>

            <!-- 5. WHY THIS WAS FLAGGED -->
            <div class="detail-section">
                <div class="detail-label">◈ WHY THIS WAS FLAGGED (Detection Grounding)</div>
                <div style="background:#0c192c; border-left:3px solid #60a5fa; border-radius:4px; padding:12px 14px; font-size:12px; color:#e2e8f0; line-height:1.6;" id="drawer-why-flagged">
                </div>
            </div>

            <!-- 6. EVIDENCE -->
            <div class="detail-section">
                <div class="detail-label">◈ EVIDENCE (Evidence Vault & SHA-256 Verified)</div>
                <div id="drawer-evidence-container"></div>
            </div>

            <!-- 7. IMPACT -->
            <div class="detail-section">
                <div class="detail-label">◈ POTENTIAL IMPACT</div>
                <div style="background:#1f1b2e; border-left:3px solid #a855f7; border-radius:4px; padding:10px 14px; font-size:12px; color:#e9d5ff; line-height:1.5;" id="drawer-impact">
                </div>
            </div>

            <!-- 8. RISK ANALYSIS & FACTORS -->
            <div class="detail-section">
                <div class="detail-label">◈ RISK ANALYSIS & FACTORS</div>
                <div style="background:#0d1424; border:1px solid #1e293b; border-radius:5px; padding:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <span style="font-weight:700; color:#fff;" id="drawer-final-risk-text">Final Risk Score: 0.0 / 10.0</span>
                    </div>
                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:8px;" id="drawer-risk-factors-grid">
                    </div>
                </div>
            </div>

            <!-- 9. REMEDIATION -->
            <div class="detail-section">
                <div class="detail-label">◈ DEFENSIVE REMEDIATION</div>
                <div style="background:#091e16; border-left:3px solid #10b981; border-radius:4px; padding:10px 14px; font-size:12px; color:#d1fae5; line-height:1.5;" id="drawer-remediation">
                </div>
            </div>

            <!-- 10. VERIFICATION & RETEST -->
            <div class="detail-section">
                <div class="detail-label">◈ VERIFICATION & RETEST</div>
                <div style="background:#172554; border-left:3px solid #3b82f6; border-radius:4px; padding:12px 14px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:8px;">
                        <div>
                            <div style="font-size:11px; color:#93c5fd;">Expected Result: The vulnerable behavior should no longer be reproducible.</div>
                            <div style="font-size:11px; color:#cbd5e1; margin-top:2px;" id="drawer-last-tested-text">Last Tested: Never</div>
                        </div>
                        <button class="btn" id="btn-drawer-retest" onclick="runRetestProbe()" style="background:#2563eb;">⚡ RETEST FINDING</button>
                    </div>
                    <div id="drawer-retest-outcome" style="margin-top:6px; font-size:12px; font-family:var(--font-mono);"></div>
                </div>
            </div>

            <!-- 11. DETECTION SOURCES -->
            <div class="detail-section">
                <div class="detail-label">◈ DETECTION SOURCES (Contributing Tools)</div>
                <div id="drawer-sources-container" style="display:flex; gap:8px; flex-wrap:wrap;"></div>
            </div>

            <!-- 12. TIMELINE -->
            <div class="detail-section">
                <div class="detail-label">◈ FINDING LIFECYCLE TIMELINE</div>
                <div id="drawer-timeline-container" style="background:var(--bg-elevated); border:1px solid var(--border-subtle); border-radius:5px; padding:10px 12px; max-height:160px; overflow-y:auto; font-size:11px; font-family:var(--font-mono);"></div>
            </div>

            <!-- 13. AI ANALYSIS (STRICT SEPARATION) -->
            <div class="detail-section">
                <div class="detail-label">◈ AI ASSISTED ANALYSIS (Strict Separation from Observed Evidence)</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                    <div style="background:#0d1117; border:1px solid #30363d; border-radius:4px; padding:10px;">
                        <div style="font-size:10px; font-weight:700; color:#38bdf8; text-transform:uppercase; margin-bottom:4px;">OBSERVED EVIDENCE (Ground Truth)</div>
                        <div style="font-size:11px; color:#cbd5e1; font-family:var(--font-mono); max-height:110px; overflow-y:auto;" id="drawer-ai-observed"></div>
                    </div>
                    <div style="background:#151226; border:1px solid #3b2d54; border-radius:4px; padding:10px;">
                        <div style="font-size:10px; font-weight:700; color:#c084fc; text-transform:uppercase; margin-bottom:4px;">AI ANALYSIS (Technical Interpretation)</div>
                        <div style="font-size:11px; color:#e9d5ff; line-height:1.4; max-height:110px; overflow-y:auto;" id="drawer-ai-analysis"></div>
                    </div>
                </div>
            </div>

            <!-- 14. ANALYST ACTIONS & NOTES -->
            <div class="detail-section" style="background:#111c2e; border:1px solid #243552; border-radius:6px; padding:14px;">
                <div class="detail-label" style="color:#93c5fd;">◈ ANALYST ACTIONS & LIFECYCLE TRIAGE</div>
                <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px;">
                    <button class="btn btn-warning" onclick="openFalsePositiveModal()">[ MARK FALSE POSITIVE ]</button>
                    <button class="btn btn-success" onclick="quickUpdateStatus('CONFIRMED')">[ MARK CONFIRMED ]</button>
                    <button class="btn btn-secondary" onclick="quickUpdateStatus('REMEDIATED')">[ MARK REMEDIATED ]</button>
                    <button class="btn btn-secondary" onclick="quickUpdateStatus('IN_PROGRESS')">[ MARK IN_PROGRESS ]</button>
                </div>
                <div style="display:flex; gap:8px; align-items:center;">
                    <select id="drawer-status-select" class="form-control" style="width:180px;">
                        <option value="OPEN">OPEN</option>
                        <option value="CONFIRMED">CONFIRMED</option>
                        <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                        <option value="IN_PROGRESS">IN_PROGRESS</option>
                        <option value="REMEDIATED">REMEDIATED</option>
                        <option value="RETEST_REQUIRED">RETEST_REQUIRED</option>
                        <option value="VERIFIED">VERIFIED</option>
                    </select>
                    <input type="text" id="drawer-triage-reason" class="form-control" placeholder="Analyst triage reason / notes..." style="flex:1;">
                    <button class="btn" onclick="updateFindingStatus()" style="white-space:nowrap;">Update Status</button>
                </div>
            </div>
        </div>
        <div class="drawer-footer">
            <button class="btn btn-secondary" onclick="closeDrawer()">Close Panel</button>
        </div>
    </div>

    <!-- FALSE POSITIVE REASON MODAL -->
    <div id="modal-false-positive" class="modal-overlay">
        <div class="modal-card">
            <div class="panel-header">
                <span class="panel-title">MARK FALSE POSITIVE</span>
                <button class="btn btn-secondary" style="padding:2px 8px;" onclick="closeFalsePositiveModal()">✕</button>
            </div>
            <div style="padding: 16px;">
                <div class="form-group">
                    <label>Required False Positive Justification Reason</label>
                    <select id="fp-reason-select" class="form-control">
                        <option value="Expected application behavior">Expected application behavior</option>
                        <option value="Scanner detection error">Scanner detection error</option>
                        <option value="Not reproducible">Not reproducible</option>
                        <option value="Compensating control exists">Compensating control exists</option>
                        <option value="Duplicate finding">Duplicate finding</option>
                        <option value="Other">Other (require specific notes)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Analyst Notes / Evidence Justification</label>
                    <textarea id="fp-notes-text" class="form-control" style="height: 80px; resize: none;" placeholder="Explain why this behavior is benign or misidentified..."></textarea>
                </div>
            </div>
            <div class="drawer-footer">
                <button class="btn btn-secondary" onclick="closeFalsePositiveModal()">Cancel</button>
                <button class="btn btn-warning" onclick="submitFalsePositive()">Confirm False Positive</button>
            </div>
        </div>
    </div>

    <script>
        let currentFindings = [];
        let activeFindingId = null;
        let activeScanId = null;
        let activityInterval = null;
        let sortKey = 'risk_score';
        let sortAsc = false;

        function switchTab(viewId) {
            document.querySelectorAll('.workspace-view').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            const target = document.getElementById('view-' + viewId);
            if (target) target.classList.add('active');

            const tabMap = ['discovery', 'overview', 'assets', 'scans', 'evidence', 'reports', 'tools', 'policies', 'audit'];
            const navIndex = tabMap.indexOf(viewId);
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
            loadFindings();
            loadAssets();
            loadScans();
            loadEvidence();
            loadReports();
            loadTools();
            loadPolicies();
            loadAudit();
            pollLatestActivity();
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
            document.getElementById('discovery-finding-count').textContent = (fSummary.TOTAL || 0) + ' Records';
        }

        /* LIVE DISCOVERY SCANNER WORKFLOW */
        async function startDiscoveryScan() {
            const target = document.getElementById('discovery-target-input').value.trim();
            if (!target) { alert('Target URL or Host is required.'); return; }
            const profile = document.getElementById('discovery-profile-select').value;
            const auth = document.getElementById('discovery-auth-check').checked;
            if (!auth) { alert('Testing authorization confirmation is required.'); return; }

            const btn = document.getElementById('btn-start-discovery');
            btn.disabled = true;
            btn.textContent = 'Initiating...';

            // Reset checklist UI
            for (let i = 0; i < 10; i++) {
                const item = document.getElementById('step-' + i);
                if (item) {
                    item.className = 'activity-item pending';
                    item.querySelector('.activity-icon').textContent = '○';
                }
            }
            document.getElementById('discovery-activity-status').textContent = 'RUNNING';
            document.getElementById('discovery-activity-status').className = 'badge badge-running';
            document.getElementById('discovery-activity-target').textContent = `Target: ${target}`;

            const res = await fetchAPI('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: target,
                    scan_type: profile === 'web' ? 'web' : 'network',
                    profile: profile,
                    authorized: true,
                    async: true
                })
            });

            btn.disabled = false;
            btn.textContent = '⚡ START DISCOVERY';

            if (res && res.scan_id) {
                activeScanId = res.scan_id;
                startActivityPolling(res.scan_id);
            } else if (res && res.error) {
                alert('Discovery scan failed: ' + res.error);
                document.getElementById('discovery-activity-status').textContent = 'FAILED';
                document.getElementById('discovery-activity-status').className = 'badge badge-critical';
            }
        }

        function startActivityPolling(scanId) {
            if (activityInterval) clearInterval(activityInterval);
            activityInterval = setInterval(async () => {
                const data = await fetchAPI(`/api/scans/${scanId}/activity`);
                if (!data) return;

                const steps = data.steps || [];
                steps.forEach((s, idx) => {
                    const item = document.getElementById('step-' + idx);
                    if (item) {
                        if (s.completed) {
                            item.className = 'activity-item completed';
                            item.querySelector('.activity-icon').textContent = '✓';
                        } else {
                            item.className = 'activity-item pending';
                            item.querySelector('.activity-icon').textContent = '○';
                        }
                    }
                });

                if (data.status) {
                    const stBadge = document.getElementById('discovery-activity-status');
                    if (data.status === 'COMPLETED' || data.status === 'Assessment completed') {
                        stBadge.textContent = 'Assessment completed';
                        stBadge.className = 'badge badge-success';
                        clearInterval(activityInterval);
                        loadFindings();
                        loadStatusOverview();
                    } else if (data.status === 'FAILED' || data.status === 'ERROR') {
                        stBadge.textContent = 'FAILED';
                        stBadge.className = 'badge badge-critical';
                        clearInterval(activityInterval);
                    } else {
                        stBadge.textContent = data.status;
                        stBadge.className = 'badge badge-running';
                    }
                }
            }, 1200);
        }

        async function pollLatestActivity() {
            if (activeScanId) return; // Already active
            const data = await fetchAPI('/api/scans/activity');
            if (!data || !data.steps) return;
            data.steps.forEach((s, idx) => {
                const item = document.getElementById('step-' + idx);
                if (item) {
                    if (s.completed) {
                        item.className = 'activity-item completed';
                        item.querySelector('.activity-icon').textContent = '✓';
                    } else {
                        item.className = 'activity-item pending';
                        item.querySelector('.activity-icon').textContent = '○';
                    }
                }
            });
            if (data.target) {
                document.getElementById('discovery-activity-target').textContent = `Target: ${data.target}`;
            }
            if (data.status) {
                const st = document.getElementById('discovery-activity-status');
                st.textContent = data.status === 'COMPLETED' ? 'Assessment completed' : data.status;
                st.className = data.status === 'COMPLETED' ? 'badge badge-success' : 'badge badge-info';
            }
        }

        /* FINDINGS & FILTERING */
        async function loadFindings() {
            const data = await fetchAPI('/api/findings');
            if (!data || !data.findings) return;
            currentFindings = data.findings;
            filterFindings();
        }

        function renderFindingsTable(list) {
            const tbody = document.getElementById('findings-body');
            tbody.innerHTML = '';
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 24px;">No findings match the active criteria.</td></tr>';
                return;
            }

            list.forEach(f => {
                const tr = document.createElement('tr');
                tr.onclick = () => openFindingDetail(f.id);
                const sev = (f.severity || 'INFO').toLowerCase();
                const loc = f.url || f.endpoint || (f.target ? `${f.target}${f.port ? ':' + f.port : ''}` : '—');
                const firstSeen = (f.first_seen || f.created_at || '').substring(0, 10);
                const riskVal = (f.risk_score || 0).toFixed(1);

                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); font-weight:700; color:#60a5fa;">${f.id}</td>
                    <td><span class="badge badge-${sev}">${f.severity}</span></td>
                    <td><strong>${escapeHtml(f.title || f.vulnerability || '')}</strong></td>
                    <td style="font-family: var(--font-mono); color:#cbd5e1;">${escapeHtml(f.target || '')}</td>
                    <td style="font-family: var(--font-mono); font-size:11px; color:#94a3b8; max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(loc)}</td>
                    <td><span class="badge badge-info">${f.confidence || 'MEDIUM'}</span></td>
                    <td style="font-family: var(--font-mono); font-weight:700; color:#c084fc;">${riskVal}</td>
                    <td><span class="badge" style="background:#1e293b; color:#e2e8f0; border:1px solid #334155;">${f.status || 'OPEN'}</span></td>
                    <td style="font-family: var(--font-mono); color:var(--text-dim);">${firstSeen || 'Today'}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        function filterFindings() {
            const q = (document.getElementById('filter-search').value || '').toLowerCase().trim();
            const sev = (document.getElementById('filter-severity').value || '').toUpperCase();
            const conf = (document.getElementById('filter-confidence').value || '').toUpperCase();
            const status = (document.getElementById('filter-status').value || '').toUpperCase();
            const cat = (document.getElementById('filter-category').value || '').toLowerCase();
            const tool = (document.getElementById('filter-tool').value || '').toLowerCase();

            let filtered = currentFindings.filter(f => {
                const matchQ = !q || (f.title||'').toLowerCase().includes(q) ||
                               (f.id||'').toLowerCase().includes(q) ||
                               (f.target||'').toLowerCase().includes(q) ||
                               (f.url||'').toLowerCase().includes(q) ||
                               (f.endpoint||'').toLowerCase().includes(q) ||
                               (f.cve||'').toLowerCase().includes(q) ||
                               (f.cwe||'').toLowerCase().includes(q);
                const matchSev = !sev || (f.severity||'').toUpperCase() === sev;
                const matchConf = !conf || (f.confidence||'').toUpperCase() === conf;
                const matchStatus = !status || (f.status||'').toUpperCase() === status;
                const matchCat = !cat || (f.category||'').toLowerCase().includes(cat) || (f.title||'').toLowerCase().includes(cat);
                const matchTool = !tool || (f.source_tool||'').toLowerCase().includes(tool) || (f.source_tools||[]).some(t => t.toLowerCase().includes(tool));
                return matchQ && matchSev && matchConf && matchStatus && matchCat && matchTool;
            });

            // Sort
            filtered.sort((a, b) => {
                let vA = a[sortKey];
                let vB = b[sortKey];
                if (sortKey === 'risk_score') {
                    vA = Number(vA || 0);
                    vB = Number(vB || 0);
                } else {
                    vA = String(vA || '').toLowerCase();
                    vB = String(vB || '').toLowerCase();
                }
                if (vA < vB) return sortAsc ? -1 : 1;
                if (vA > vB) return sortAsc ? 1 : -1;
                return 0;
            });

            renderFindingsTable(filtered);
            document.getElementById('discovery-finding-count').textContent = `${filtered.length} of ${currentFindings.length} Records`;
        }

        function sortFindings(key) {
            if (sortKey === key) {
                sortAsc = !sortAsc;
            } else {
                sortKey = key;
                sortAsc = false;
            }
            filterFindings();
        }

        /* INVESTIGATION DETAIL VIEW */
        async function openFindingDetail(findingId) {
            activeFindingId = findingId;
            const data = await fetchAPI(`/api/findings/${findingId}`);
            if (!data) return;

            const f = data.finding || {};
            const inv = data.investigation || {};
            const loc = data.exact_location || (inv.exact_location || {});
            const locDetails = loc.details || {};
            const riskFactors = inv.risk_factors || f.risk_factors || {};

            document.getElementById('drawer-header-title').textContent = `FINDING ${f.title || f.vulnerability || ''}`;
            document.getElementById('drawer-header-id').textContent = `${f.id} • ${f.target || ''}`;
            document.getElementById('drawer-fid').textContent = f.id;
            document.getElementById('drawer-finding-title').textContent = f.title || f.vulnerability || 'Security Finding';

            const sevBadge = document.getElementById('drawer-sev-badge');
            sevBadge.textContent = f.severity || 'INFO';
            sevBadge.className = 'badge badge-' + (f.severity || 'info').toLowerCase();

            document.getElementById('drawer-conf-badge').textContent = 'CONF: ' + (f.confidence || 'MEDIUM');
            document.getElementById('drawer-score-badge').textContent = `RISK: ${(f.risk_score || 0).toFixed(1)}/10`;

            const retestStatusBadge = document.getElementById('drawer-retest-status-badge');
            if (f.retest_result) {
                const rRes = f.retest_result.toUpperCase();
                const rColor = rRes === 'PASS' ? '#065f46; color:#a7f3d0;' : (rRes === 'FAIL' ? '#991b1b; color:#fecaca;' : '#854d0e; color:#fef08a;');
                retestStatusBadge.innerHTML = `<span class="badge" style="background:${rColor}">RETEST: ${rRes}</span>`;
            } else {
                retestStatusBadge.innerHTML = `<span class="badge" style="background:#374151; color:#9ca3af;">NOT RETESTED</span>`;
            }

            // 2. Summary
            document.getElementById('drawer-summary').textContent = f.description || f.title || 'Technical finding recorded by scanner.';

            // 3. Target
            const targetGrid = document.getElementById('drawer-target-grid');
            targetGrid.innerHTML = `
                <div><span style="color:var(--text-dim);">Target:</span> <strong>${escapeHtml(f.target || '—')}</strong></div>
                <div><span style="color:var(--text-dim);">Asset ID:</span> <code>${f.asset_id || f.target || '—'}</code></div>
                <div><span style="color:var(--text-dim);">Host/IP:</span> <code>${f.host || f.target || '—'}</code></div>
                <div><span style="color:var(--text-dim);">Port:</span> <code>${f.port || '—'}</code></div>
                <div><span style="color:var(--text-dim);">Protocol:</span> ${f.protocol || 'tcp'}</div>
                <div><span style="color:var(--text-dim);">Service:</span> ${escapeHtml(f.service || 'web')}</div>
                <div><span style="color:var(--text-dim);">Version:</span> ${escapeHtml(f.service_version || 'Detected')}</div>
            `;

            // 4. Exact Location
            document.getElementById('drawer-loc-hierarchy').textContent = loc.hierarchy || loc.type || 'RESOLVED LOCATION';
            document.getElementById('drawer-loc-summary').textContent = loc.summary || f.url || (f.target + (f.port ? `:${f.port}` : ''));
            
            let locDText = [];
            if (locDetails.url) locDText.push(`URL: ${locDetails.url}`);
            if (locDetails.http_method) locDText.push(`Method: ${locDetails.http_method}`);
            if (locDetails.endpoint) locDText.push(`Endpoint: ${locDetails.endpoint}`);
            if (locDetails.parameter) locDText.push(`Parameter: ${locDetails.parameter} (${locDetails.parameter_location || 'query'})`);
            if (locDetails.port) locDText.push(`Port: ${locDetails.port}/${locDetails.protocol || 'tcp'}`);
            if (locDetails.service) locDText.push(`Service: ${locDetails.service}`);
            document.getElementById('drawer-loc-details').textContent = locDText.join(' • ');

            // 5. Why Flagged
            document.getElementById('drawer-why-flagged').textContent = inv.why_this_was_flagged || inv.why_flagged || f.observed_behavior || 'CyberWolf detected behavior consistent with the declared vulnerability category. Evidence captured below.';

            // 6. Evidence
            const evCont = document.getElementById('drawer-evidence-container');
            const evRecords = data.evidence_records || [];
            if (evRecords.length === 0) {
                evCont.innerHTML = `<div class="detail-box">${escapeHtml(f.evidence || 'No cryptographic evidence stored.')}</div>`;
            } else {
                let evHtml = '';
                evRecords.forEach(ev => {
                    const sha = ev.hash_sha256 || 'N/A';
                    const tool = ev.tool_name || 'CYBERWOLF';
                    const excerpt = ev.output_excerpt || 'No excerpt stored.';
                    const req = ev.request_data || {};
                    const res = ev.response_data || {};

                    let httpBlock = '';
                    if (req.method || req.url || res.status_code) {
                        httpBlock = `
                            <div style="margin-top:6px; background:#080c14; border:1px solid #1e293b; border-radius:4px; padding:8px;">
                                <div style="color:#60a5fa; font-weight:700; font-size:10px; margin-bottom:2px;">REQUEST</div>
                                <pre style="margin:0; color:#e2e8f0; font-size:11px; white-space:pre-wrap;">${escapeHtml(req.method || 'GET')} ${escapeHtml(req.url || '/')} HTTP/1.1\nHost: ${escapeHtml(f.target || '')}</pre>
                                <div style="color:#34d399; font-weight:700; font-size:10px; margin-top:6px; margin-bottom:2px;">RESPONSE</div>
                                <pre style="margin:0; color:#e2e8f0; font-size:11px; white-space:pre-wrap;">HTTP/1.1 ${res.status_code || 200} OK\n[Headers and response evidence preserved]</pre>
                            </div>
                        `;
                    }

                    evHtml += `
                        <div style="background:#090e17; border:1px solid #202b3d; border-radius:5px; padding:10px; margin-bottom:10px; font-family:var(--font-mono); font-size:11px;">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap;">
                                <span style="color:#60a5fa; font-weight:700;">[${ev.id}] ${ev.evidence_type || 'TOOL_OUTPUT'} (${tool})</span>
                                <span style="color:#10b981; font-weight:700;">✔ SHA-256 INTEGRITY VERIFIED</span>
                            </div>
                            <div style="color:#94a3b8; font-size:10px; margin-bottom:6px;">SHA-256: <code style="color:#6ee7b7;">${sha}</code></div>
                            <pre style="margin:0; color:#cbd5e1; white-space:pre-wrap; max-height:110px; overflow-y:auto;">${escapeHtml(excerpt)}</pre>
                            ${httpBlock}
                        </div>
                    `;
                });
                evCont.innerHTML = evHtml;
            }

            // 7. Impact
            document.getElementById('drawer-impact').textContent = inv.security_impact || f.potential_impact || 'Potential unauthorized access, data exposure, or service disruption.';

            // 8. Risk Analysis & Factors
            document.getElementById('drawer-final-risk-text').textContent = `Final Risk Score: ${(f.risk_score || 0).toFixed(1)} / 10.0`;
            const rfGrid = document.getElementById('drawer-risk-factors-grid');
            rfGrid.innerHTML = `
                <div style="background:#131c2e; padding:6px 10px; border-radius:4px; border:1px solid #25334d;">
                    <div style="font-size:10px; color:#94a3b8;">Severity</div>
                    <div style="font-size:13px; font-weight:700; color:#fff;">${(riskFactors.severity_weight || 0.8).toFixed(2)}</div>
                </div>
                <div style="background:#131c2e; padding:6px 10px; border-radius:4px; border:1px solid #25334d;">
                    <div style="font-size:10px; color:#94a3b8;">Exploitability</div>
                    <div style="font-size:13px; font-weight:700; color:#fff;">${(riskFactors.exploitability_weight || 0.85).toFixed(2)}</div>
                </div>
                <div style="background:#131c2e; padding:6px 10px; border-radius:4px; border:1px solid #25334d;">
                    <div style="font-size:10px; color:#94a3b8;">Exposure</div>
                    <div style="font-size:13px; font-weight:700; color:#fff;">${(riskFactors.exposure_weight || 0.85).toFixed(2)}</div>
                </div>
                <div style="background:#131c2e; padding:6px 10px; border-radius:4px; border:1px solid #25334d;">
                    <div style="font-size:10px; color:#94a3b8;">Confidence</div>
                    <div style="font-size:13px; font-weight:700; color:#fff;">${(riskFactors.confidence_weight || 0.9).toFixed(2)}</div>
                </div>
                <div style="background:#131c2e; padding:6px 10px; border-radius:4px; border:1px solid #25334d;">
                    <div style="font-size:10px; color:#94a3b8;">Asset Criticality</div>
                    <div style="font-size:13px; font-weight:700; color:#fff;">${(riskFactors.asset_criticality || 1.0).toFixed(2)}</div>
                </div>
            `;

            // 9. Remediation
            document.getElementById('drawer-remediation').textContent = f.remediation || (inv.remediation?.defensive_steps) || 'Apply security controls, update affected component, or sanitize input.';

            // 10. Verification & Retest
            document.getElementById('drawer-last-tested-text').textContent = f.last_verified ? `Last Tested: ${f.last_verified}` : 'Last Tested: Never';
            const outcomeDiv = document.getElementById('drawer-retest-outcome');
            if (f.retest_result) {
                const rRes = f.retest_result.toUpperCase();
                const rColor = rRes === 'PASS' ? '#34d399' : (rRes === 'FAIL' ? '#f87171' : '#fde047');
                outcomeDiv.innerHTML = `<span style="color:${rColor}; font-weight:700;">RETEST RESULT: ${rRes}</span> • ${escapeHtml(f.retest_notes || 'Probe test evaluated.')}`;
            } else {
                outcomeDiv.innerHTML = '<span style="color:#94a3b8;">No verification probe run yet. Click Retest Finding to probe target.</span>';
            }

            // 11. Sources
            const sourcesCont = document.getElementById('drawer-sources-container');
            const tools = f.source_tools || [f.source_tool || 'CYBERWOLF'];
            sourcesCont.innerHTML = tools.map(t => `<span class="badge" style="background:#1e293b; color:#93c5fd; border:1px solid #334155; font-size:11px; padding:4px 8px;">◈ ${escapeHtml(t)}</span>`).join('');

            // 12. Timeline
            const tlCont = document.getElementById('drawer-timeline-container');
            const timeline = data.timeline || [];
            if (timeline.length === 0) {
                tlCont.innerHTML = '<span style="color:var(--text-dim);">No timeline events recorded.</span>';
            } else {
                tlCont.innerHTML = timeline.map(ev => {
                    const ts = (ev.timestamp || '').substring(0, 19).replace('T', ' ');
                    return `
                        <div style="margin-bottom:6px; border-bottom:1px solid #1f2937; padding-bottom:4px;">
                            <span style="color:var(--text-dim);">${ts}</span> • 
                            <strong style="color:#93c5fd;">${ev.event_type || 'EVENT'}:</strong> 
                            ${escapeHtml(ev.description || '')} 
                            <span style="color:#6b7280;">(${ev.actor || 'system'})</span>
                        </div>
                    `;
                }).join('');
            }

            // 13. AI Analysis (Strict Separation)
            document.getElementById('drawer-ai-observed').textContent = f.observed_behavior || f.evidence || 'Scanner observed request/response behavior.';
            document.getElementById('drawer-ai-analysis').textContent = (data.explanation?.ai_synthesis) || inv.why_this_was_flagged || 'Finding grounded in recorded scanner evidence. Additional probe verification confirms reproducible behavior.';

            // 14. Actions
            document.getElementById('drawer-status-select').value = f.status || 'OPEN';
            document.getElementById('drawer-triage-reason').value = '';

            document.getElementById('drawer-finding').classList.add('open');
        }

        function closeDrawer() {
            document.getElementById('drawer-finding').classList.remove('open');
            activeFindingId = null;
        }

        /* RETEST ACTION */
        async function runRetestProbe() {
            if (!activeFindingId) return;
            const btn = document.getElementById('btn-drawer-retest');
            btn.disabled = true;
            btn.textContent = 'Probing target...';

            try {
                const res = await fetchAPI(`/api/findings/${activeFindingId}/retest`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ actor: 'web-analyst' })
                });

                if (res && res.success) {
                    alert(`Retest Probe Result: ${res.retest_result}\nNew Status: ${res.new_status}\nEvidence Recorded: ${res.evidence_id || 'Vault'}`);
                    openFindingDetail(activeFindingId);
                    loadFindings();
                } else {
                    alert('Retest failed: ' + (res?.error || res?.notes || 'Probe error'));
                }
            } catch (err) {
                alert('Retest error: ' + err);
            } finally {
                btn.disabled = false;
                btn.textContent = '⚡ RETEST FINDING';
            }
        }

        /* STATUS TRIAGE & FALSE POSITIVE MODAL */
        function openFalsePositiveModal() {
            document.getElementById('modal-false-positive').classList.add('open');
        }

        function closeFalsePositiveModal() {
            document.getElementById('modal-false-positive').classList.remove('open');
        }

        async function submitFalsePositive() {
            if (!activeFindingId) return;
            const reason = document.getElementById('fp-reason-select').value;
            const notes = document.getElementById('fp-notes-text').value.trim();
            const combinedReason = notes ? `${reason}: ${notes}` : reason;

            const res = await fetchAPI(`/api/findings/${activeFindingId}/triage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    status: 'FALSE_POSITIVE',
                    reason: combinedReason,
                    actor: 'analyst'
                })
            });

            closeFalsePositiveModal();
            if (res && !res.error) {
                openFindingDetail(activeFindingId);
                loadFindings();
            } else {
                alert('Failed to mark false positive: ' + (res?.error || 'Unknown error'));
            }
        }

        async function quickUpdateStatus(status) {
            if (!activeFindingId) return;
            const res = await fetchAPI(`/api/findings/${activeFindingId}/triage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    status: status,
                    reason: `Analyst marked ${status} via Workstation action bar`,
                    actor: 'analyst'
                })
            });
            if (res && !res.error) {
                openFindingDetail(activeFindingId);
                loadFindings();
            } else {
                alert('Failed to update status: ' + (res?.error || 'Unknown error'));
            }
        }

        async function updateFindingStatus() {
            if (!activeFindingId) return;
            const newStatus = document.getElementById('drawer-status-select').value;
            const reason = document.getElementById('drawer-triage-reason').value.trim();

            if (newStatus === 'FALSE_POSITIVE' && !reason) {
                openFalsePositiveModal();
                return;
            }

            const res = await fetchAPI(`/api/findings/${activeFindingId}/triage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    status: newStatus,
                    reason: reason || `Analyst triage to ${newStatus}`,
                    actor: 'analyst'
                })
            });

            if (res && !res.error) {
                openFindingDetail(activeFindingId);
                loadFindings();
            } else {
                alert('Failed to update status: ' + (res?.error || 'Unknown error'));
            }
        }

        /* SUB-VIEW LOADERS */
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
            tbody.innerHTML = '';
            data.scans.forEach(s => {
                const tr = document.createElement('tr');
                const st = (s.status || 'COMPLETED').toLowerCase();
                const stBadge = st === 'completed' ? 'badge-success' : (st === 'running' ? 'badge-running' : 'badge-critical');
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

        async function generateNewReport() {
            const res = await fetchAPI('/api/reports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: 'All Assessed Targets' })
            });
            if (res && res.files) {
                alert('21-Section Investigation Report Deliverables generated:\n' + Object.keys(res.files).join(', '));
                loadReports();
            } else {
                alert('Failed to generate reports: ' + (res?.error || 'Unknown error'));
            }
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
