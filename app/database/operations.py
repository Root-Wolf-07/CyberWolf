"""CYBERWOLF Database CRUD Operations & Queries."""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from app.database.db_manager import get_db
from app.database.models import Finding, HostRecord, PortRecord, ScanRecord
from app.core.logger import get_logger

logger = get_logger()

def create_scan(scan_type: str, target: str, mode: str = "SAFE_SCAN") -> str:
    """Initialize and persist a new scan record."""
    scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO scans (id, scan_type, target, mode, status, start_time, summary)
            VALUES (?, ?, ?, ?, 'RUNNING', CURRENT_TIMESTAMP, ?)
        """, (scan_id, scan_type, target, mode, json.dumps({})))
    return scan_id

def complete_scan(scan_id: str, status: str = "COMPLETED", summary: Optional[Dict[str, Any]] = None, findings_count: int = 0):
    """Mark a scan as completed with final summary and findings count."""
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            UPDATE scans
            SET status = ?, end_time = CURRENT_TIMESTAMP, findings_count = ?, summary = ?
            WHERE id = ?
        """, (status, findings_count, json.dumps(summary or {}), scan_id))

def upsert_host(ip: str, hostname: Optional[str] = None, mac: Optional[str] = None, os_name: Optional[str] = None) -> int:
    """Insert or update a host record, returning host_id."""
    db = get_db()
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM hosts WHERE ip_address = ?", (ip,))
        row = cur.fetchone()
        if row:
            host_id = row["id"]
            cur.execute("""
                UPDATE hosts
                SET hostname = COALESCE(?, hostname),
                    mac_address = COALESCE(?, mac_address),
                    os_name = COALESCE(?, os_name),
                    last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (hostname, mac, os_name, host_id))
            return host_id
        else:
            cur.execute("""
                INSERT INTO hosts (ip_address, hostname, mac_address, os_name, status)
                VALUES (?, ?, ?, ?, 'UP')
            """, (ip, hostname, mac, os_name))
            return cur.lastrowid

def upsert_port(host_id: int, port_number: int, protocol: str = "tcp",
                state: str = "open", service_name: Optional[str] = None,
                service_product: Optional[str] = None, service_version: Optional[str] = None,
                banner: Optional[str] = None) -> int:
    """Insert or update a discovered port."""
    db = get_db()
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id FROM ports WHERE host_id = ? AND port_number = ? AND protocol = ?
        """, (host_id, port_number, protocol))
        row = cur.fetchone()
        if row:
            port_id = row["id"]
            cur.execute("""
                UPDATE ports
                SET state = ?, service_name = COALESCE(?, service_name),
                    service_product = COALESCE(?, service_product),
                    service_version = COALESCE(?, service_version),
                    banner = COALESCE(?, banner),
                    last_discovered = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (state, service_name, service_product, service_version, banner, port_id))
            return port_id
        else:
            cur.execute("""
                INSERT INTO ports (host_id, port_number, protocol, state, service_name, service_product, service_version, banner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (host_id, port_number, protocol, state, service_name, service_product, service_version, banner))
            return cur.lastrowid

def create_finding(finding: Finding) -> str:
    """Store a normalized security finding."""
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO findings (
                id, target, port, protocol, service, vulnerability,
                cve, cwe, severity, confidence, evidence, remediation, source_tool, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.id, finding.target, finding.port, finding.protocol,
            finding.service, finding.vulnerability, finding.cve, finding.cwe,
            finding.severity.upper(), finding.confidence.upper(), finding.evidence,
            finding.remediation, finding.source_tool, finding.status
        ))
    return finding.id

def get_all_findings(target: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve findings with optional filtering."""
    db = get_db()
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if target:
        query += " AND target LIKE ?"
        params.append(f"%{target}%")
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, created_at DESC"
    
    with db.get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

def get_findings_summary() -> Dict[str, int]:
    """Return count of findings grouped by severity."""
    db = get_db()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0}
    with db.get_connection() as conn:
        rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity").fetchall()
        for r in rows:
            sev = r["severity"].upper()
            if sev in counts:
                counts[sev] = r["cnt"]
                counts["TOTAL"] += r["cnt"]
    return counts

def save_tool_output(tool_name: str, raw_output: str, scan_id: Optional[str] = None,
                     command_line: Optional[str] = None, exit_code: int = 0,
                     structured_json: Optional[Dict[str, Any]] = None):
    """Persist raw output from security tools."""
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO tool_outputs (scan_id, tool_name, command_line, exit_code, raw_output, structured_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, tool_name, command_line, exit_code, raw_output, json.dumps(structured_json or {})))

def save_ai_analysis(specialist_role: str, model_name: str, analysis_text: str,
                     recommendations: Optional[str] = None, scan_id: Optional[str] = None,
                     finding_id: Optional[str] = None, confidence_score: float = 0.95):
    """Save an AI analysis response for persistence and RAG."""
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO ai_analyses (scan_id, finding_id, specialist_role, model_name, analysis_text, recommendations, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, finding_id, specialist_role, model_name, analysis_text, recommendations, confidence_score))

def get_database_status() -> Dict[str, Any]:
    """Return diagnostic metrics about the local SQLite database."""
    db = get_db()
    with db.get_connection() as conn:
        hosts_cnt = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        ports_cnt = conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
        findings_cnt = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        scans_cnt = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        tools_cnt = conn.execute("SELECT COUNT(*) FROM tool_outputs").fetchone()[0]
        ai_cnt = conn.execute("SELECT COUNT(*) FROM ai_analyses").fetchone()[0]
        reports_cnt = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    return {
        "db_path": str(db.db_path),
        "db_size_bytes": db.db_path.stat().st_size if db.db_path.exists() else 0,
        "hosts": hosts_cnt,
        "ports": ports_cnt,
        "findings": findings_cnt,
        "scans": scans_cnt,
        "tool_outputs": tools_cnt,
        "ai_analyses": ai_cnt,
        "reports": reports_cnt
    }

def search_database(term: str) -> Dict[str, List[Dict[str, Any]]]:
    """Full-text search across findings, hosts, and AI analyses."""
    db = get_db()
    pattern = f"%{term}%"
    results = {"findings": [], "hosts": [], "ai_analyses": []}
    
    with db.get_connection() as conn:
        f_rows = conn.execute("""
            SELECT * FROM findings 
            WHERE vulnerability LIKE ? OR evidence LIKE ? OR target LIKE ? OR cve LIKE ?
        """, (pattern, pattern, pattern, pattern)).fetchall()
        results["findings"] = [dict(r) for r in f_rows]

        h_rows = conn.execute("""
            SELECT * FROM hosts WHERE ip_address LIKE ? OR hostname LIKE ? OR os_name LIKE ?
        """, (pattern, pattern, pattern)).fetchall()
        results["hosts"] = [dict(r) for r in h_rows]

        a_rows = conn.execute("""
            SELECT * FROM ai_analyses WHERE analysis_text LIKE ? OR specialist_role LIKE ?
        """, (pattern, pattern)).fetchall()
        results["ai_analyses"] = [dict(r) for r in a_rows]

    return results

def export_database_json() -> Dict[str, Any]:
    """Export complete database contents to structured dictionary."""
    db = get_db()
    with db.get_connection() as conn:
        return {
            "exported_at": datetime.now().isoformat(),
            "hosts": [dict(r) for r in conn.execute("SELECT * FROM hosts").fetchall()],
            "ports": [dict(r) for r in conn.execute("SELECT * FROM ports").fetchall()],
            "findings": [dict(r) for r in conn.execute("SELECT * FROM findings").fetchall()],
            "scans": [dict(r) for r in conn.execute("SELECT * FROM scans").fetchall()],
            "reports": [dict(r) for r in conn.execute("SELECT * FROM reports").fetchall()],
            "ai_analyses": [dict(r) for r in conn.execute("SELECT * FROM ai_analyses").fetchall()]
        }
