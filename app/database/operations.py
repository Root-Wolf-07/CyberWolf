"""CYBERWOLF Database CRUD Operations & Queries (V2).

Provides unified data persistence and querying for:
- Scans & Scan Sessions
- Assets & Host/Port records
- Normalized Findings & Multi-tool Sources
- Cryptographic Evidence & Tool Runs
- Audit Events & Reports
- Full-text search and JSON exports
"""

import json
import uuid
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from app.database.db_manager import get_db
from app.database.models import (
    Finding, HostRecord, PortRecord, ScanRecord, Asset,
    Evidence, ToolRun, ReportRecord, AuditEvent,
    SeverityLevel, ConfidenceLevel, FindingStatus, ScanStatus,
    FindingRetest, FindingStatusHistory, EvidenceType, RetestResult
)
from app.core.logger import get_logger

logger = get_logger()


# ---------------------------------------------------------------------------
# SCANS
# ---------------------------------------------------------------------------

def create_scan(scan_type: str, target: str, mode: str = "SAFE_SCAN",
                authorization_status: str = "AUTHORIZED", policy: Optional[str] = None,
                scan_id: Optional[str] = None) -> str:
    """Initialize and persist a new scan record."""
    scan_id = scan_id or f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO scans (
                id, scan_type, target, mode, status, authorization_status,
                policy_applied, start_time, tools_executed, summary
            ) VALUES (?, ?, ?, ?, 'RUNNING', ?, ?, CURRENT_TIMESTAMP, ?, ?)
        """, (
            scan_id, scan_type, target, mode, authorization_status,
            policy or mode, json.dumps([]), json.dumps({})
        ))
        # Also record in scan_targets
        conn.execute("""
            INSERT INTO scan_targets (scan_id, target, authorized, scope_name)
            VALUES (?, ?, 1, ?)
        """, (scan_id, target, mode))
    return scan_id


def complete_scan(scan_id: str, status: str = "COMPLETED",
                  summary: Optional[Dict[str, Any]] = None,
                  findings_count: int = 0,
                  severity_counts: Optional[Dict[str, int]] = None,
                  tools_executed: Optional[List[str]] = None):
    """Mark a scan as completed with final metrics and summary."""
    db = get_db()
    counts = severity_counts or {}
    with db.get_connection() as conn:
        conn.execute("""
            UPDATE scans
            SET status = ?,
                end_time = CURRENT_TIMESTAMP,
                findings_count = ?,
                critical_count = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?,
                tools_executed = COALESCE(?, tools_executed),
                summary = ?
            WHERE id = ?
        """, (
            status,
            findings_count,
            counts.get("CRITICAL", 0),
            counts.get("HIGH", 0),
            counts.get("MEDIUM", 0),
            counts.get("LOW", 0),
            json.dumps(tools_executed) if tools_executed is not None else None,
            json.dumps(summary or {}),
            scan_id
        ))


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full scan session record by ID."""
    db = get_db()
    with db.get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row:
            d = dict(row)
            if isinstance(d.get("summary"), str):
                try:
                    d["summary"] = json.loads(d["summary"])
                except Exception:
                    pass
            if isinstance(d.get("tools_executed"), str):
                try:
                    d["tools_executed"] = json.loads(d["tools_executed"])
                except Exception:
                    pass
            return d
        return None


def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent scans ordered by start time descending."""
    db = get_db()
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT ?", (limit,)
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("tools_executed"), str):
                try:
                    d["tools_executed"] = json.loads(d["tools_executed"])
                except Exception:
                    d["tools_executed"] = []
            results.append(d)
        return results


def cancel_scan(scan_id: str, reason: str = "Operator requested cancellation") -> bool:
    """Safely transition a running scan to CANCELLED."""
    db = get_db()
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE scans
            SET status = 'CANCELLED',
                end_time = CURRENT_TIMESTAMP,
                summary = json_set(COALESCE(summary, '{}'), '$.cancellation_reason', ?)
            WHERE id = ? AND status = 'RUNNING'
        """, (reason, scan_id))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# ASSETS & HOSTS
# ---------------------------------------------------------------------------

def upsert_asset(target_identifier: str, hostname: Optional[str] = None,
                 ip_address: Optional[str] = None, mac_address: Optional[str] = None,
                 operating_system: Optional[str] = None, device_type: Optional[str] = None,
                 asset_type: str = "ip", risk_score: float = 0.0) -> int:
    """Insert or update an asset entity with automatic deduplication."""
    db = get_db()
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, risk_score FROM assets WHERE target_identifier = ?", (target_identifier,))
        row = cur.fetchone()
        if row:
            asset_id = row["id"]
            cur.execute("""
                UPDATE assets
                SET hostname = COALESCE(?, hostname),
                    ip_address = COALESCE(?, ip_address),
                    mac_address = COALESCE(?, mac_address),
                    operating_system = COALESCE(?, operating_system),
                    device_type = COALESCE(?, device_type),
                    risk_score = MAX(COALESCE(risk_score, 0.0), ?),
                    last_scanned = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (hostname, ip_address, mac_address, operating_system, device_type, risk_score, asset_id))
            return asset_id
        else:
            cur.execute("""
                INSERT INTO assets (
                    target_identifier, asset_type, hostname, ip_address,
                    mac_address, operating_system, device_type, risk_score,
                    first_seen, last_scanned
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (target_identifier, asset_type, hostname, ip_address, mac_address, operating_system, device_type, risk_score))
            return cur.lastrowid


def get_all_assets() -> List[Dict[str, Any]]:
    """Retrieve list of all discovered assets."""
    db = get_db()
    with db.get_connection() as conn:
        rows = conn.execute("SELECT * FROM assets ORDER BY last_scanned DESC").fetchall()
        return [dict(r) for r in rows]


def get_asset(asset_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve asset by internal integer ID."""
    db = get_db()
    with db.get_connection() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        return dict(row) if row else None


def upsert_host(ip: str, hostname: Optional[str] = None, mac: Optional[str] = None,
                os_name: Optional[str] = None, asset_id: Optional[int] = None) -> int:
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
                    asset_id = COALESCE(?, asset_id),
                    last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (hostname, mac, os_name, asset_id, host_id))
            return host_id
        else:
            cur.execute("""
                INSERT INTO hosts (ip_address, hostname, mac_address, os_name, status, asset_id)
                VALUES (?, ?, ?, ?, 'UP', ?)
            """, (ip, hostname, mac, os_name, asset_id))
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
                INSERT INTO ports (
                    host_id, port_number, protocol, state,
                    service_name, service_product, service_version, banner
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (host_id, port_number, protocol, state, service_name, service_product, service_version, banner))
            return cur.lastrowid


# ---------------------------------------------------------------------------
# FINDINGS & PROVENANCE
# ---------------------------------------------------------------------------

def create_finding(finding: Finding) -> str:
    """Store or update a normalized security finding (BDIE V2)."""
    db = get_db()
    now_iso = datetime.now().isoformat()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO findings (
                id, target, asset_id, host_id, port, protocol, service, service_version,
                vulnerability, title, description, category, host,
                cve, cve_ids, cwe, cwe_ids, owasp_category, cvss,
                severity, confidence, evidence, evidence_ids, remediation, source_tool,
                risk_score, risk_factors, first_seen, last_seen, created_at, updated_at,
                resolved_at, last_verified, verified, status,
                url, http_method, endpoint, parameter, component, technology,
                config_area, config_setting, config_observed, config_expected,
                source_file, source_line, source_function, source_commit,
                observed_behavior, verified_behavior, potential_impact,
                exploitability, exploit_prerequisites, exploit_limitations,
                retest_status, retest_result, scan_id, tool_run_id
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?
            )
        """, (
            finding.id, finding.target, finding.asset_id, finding.host_id,
            finding.port, finding.protocol, finding.service, finding.service_version,
            finding.vulnerability, finding.title or finding.vulnerability,
            finding.description or finding.evidence, finding.category, finding.host or finding.target,
            finding.cve, json.dumps(finding.cve_ids or []),
            finding.cwe, json.dumps(finding.cwe_ids or []), finding.owasp_category, finding.cvss,
            finding.severity.upper(), finding.confidence.upper(),
            finding.evidence, json.dumps(finding.evidence_ids or []), finding.remediation,
            finding.source_tool, finding.risk_score, json.dumps(finding.risk_factors or {}),
            finding.first_seen, finding.last_seen, finding.created_at, finding.updated_at or now_iso,
            finding.resolved_at, finding.last_verified, 1 if finding.verified else 0, finding.status,
            finding.url, finding.http_method, finding.endpoint, finding.parameter,
            finding.component, finding.technology,
            finding.config_area, finding.config_setting, finding.config_observed, finding.config_expected,
            finding.source_file, finding.source_line, finding.source_function, finding.source_commit,
            finding.observed_behavior or finding.evidence, finding.verified_behavior, finding.potential_impact,
            finding.exploitability, finding.exploit_prerequisites, finding.exploit_limitations,
            finding.retest_status, finding.retest_result, finding.scan_id, finding.tool_run_id
        ))

        # Record source tool provenance
        for tool in (finding.source_tools or [finding.source_tool]):
            if tool:
                conn.execute("""
                    INSERT OR IGNORE INTO finding_sources (finding_id, tool_name)
                    VALUES (?, ?)
                """, (finding.id, tool))

    return finding.id


def get_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve finding by ID with all sources, evidence, retests, and history."""
    db = get_db()
    with db.get_connection() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        d = dict(row)

        # Parse JSON fields safely
        for json_field in ["cve_ids", "cwe_ids", "evidence_ids", "risk_factors"]:
            if isinstance(d.get(json_field), str):
                try:
                    d[json_field] = json.loads(d[json_field])
                except Exception:
                    pass

        # Fetch sources
        sources_rows = conn.execute(
            "SELECT tool_name, discovered_at FROM finding_sources WHERE finding_id = ?",
            (finding_id,)
        ).fetchall()
        d["source_tools"] = [r["tool_name"] for r in sources_rows] if sources_rows else [d.get("source_tool", "CYBERWOLF")]

        # Fetch retests and status history
        retests_rows = conn.execute(
            "SELECT * FROM finding_retests WHERE finding_id = ? ORDER BY timestamp DESC",
            (finding_id,)
        ).fetchall()
        d["retests"] = [dict(r) for r in retests_rows]

        history_rows = conn.execute(
            "SELECT * FROM finding_status_history WHERE finding_id = ? ORDER BY changed_at ASC",
            (finding_id,)
        ).fetchall()
        d["status_history"] = [dict(r) for r in history_rows]

        return d


def update_finding_status(finding_id: str, new_status: str, verified: Optional[bool] = None,
                          reason: Optional[str] = None, changed_by: str = "ANALYST") -> bool:
    """Update status of a finding with audit trail and lifecycle tracking."""
    norm_status = FindingStatus.normalize(new_status)
    db = get_db()
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT status FROM findings WHERE id = ?", (finding_id,))
        row = cur.fetchone()
        if not row:
            return False
        old_status = row["status"]

        now_iso = datetime.now().isoformat()
        resolved_at = now_iso if norm_status == FindingStatus.RESOLVED else None

        if verified is not None:
            cur.execute("""
                UPDATE findings
                SET status = ?, verified = ?, last_seen = CURRENT_TIMESTAMP,
                    updated_at = ?, resolved_at = COALESCE(?, resolved_at)
                WHERE id = ?
            """, (norm_status, 1 if verified else 0, now_iso, resolved_at, finding_id))
        else:
            cur.execute("""
                UPDATE findings
                SET status = ?, last_seen = CURRENT_TIMESTAMP,
                    updated_at = ?, resolved_at = COALESCE(?, resolved_at)
                WHERE id = ?
            """, (norm_status, now_iso, resolved_at, finding_id))

        if cur.rowcount > 0:
            cur.execute("""
                INSERT INTO finding_status_history (
                    finding_id, old_status, new_status, reason, changed_by, changed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (finding_id, old_status, norm_status, reason or "Status transition", changed_by, now_iso))
            return True
        return False


def record_finding_retest(retest: FindingRetest) -> str:
    """Record an authorized vulnerability re-test verification."""
    db = get_db()
    now_iso = datetime.now().isoformat()
    with db.get_connection() as conn:
        valid_evidence_id = retest.evidence_id
        if valid_evidence_id:
            exists = conn.execute("SELECT id FROM evidence WHERE id = ?", (valid_evidence_id,)).fetchone()
            if not exists:
                valid_evidence_id = None

        valid_scan_id = retest.scan_id
        if valid_scan_id:
            exists = conn.execute("SELECT id FROM scans WHERE id = ?", (valid_scan_id,)).fetchone()
            if not exists:
                valid_scan_id = None

        conn.execute("""
            INSERT OR REPLACE INTO finding_retests (
                id, finding_id, scan_id, evidence_id, test_type,
                result, details, retested_by, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            retest.id, retest.finding_id, valid_scan_id, valid_evidence_id,
            retest.test_type, retest.result, retest.details,
            retest.retested_by, retest.timestamp or now_iso
        ))

        # Synchronize finding retest fields
        resolved_at = now_iso if retest.result == RetestResult.PASS else None
        conn.execute("""
            UPDATE findings
            SET retest_result = ?, retest_status = ?, last_verified = ?,
                updated_at = ?, resolved_at = COALESCE(?, resolved_at)
            WHERE id = ?
        """, (retest.result, f"RETEST_{retest.result}", now_iso, now_iso, resolved_at, retest.finding_id))
    return retest.id


def get_finding_retests(finding_id: str) -> List[Dict[str, Any]]:
    """Retrieve all retest records for a finding."""
    db = get_db()
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM finding_retests WHERE finding_id = ? ORDER BY timestamp DESC",
            (finding_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_finding_status_history(finding_id: str) -> List[Dict[str, Any]]:
    """Retrieve complete audit trail of status transitions for a finding."""
    db = get_db()
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM finding_status_history WHERE finding_id = ? ORDER BY changed_at ASC",
            (finding_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_findings(target: Optional[str] = None, severity: Optional[str] = None,
                     status: Optional[str] = None, cve: Optional[str] = None,
                     limit: int = 500) -> List[Dict[str, Any]]:
    """Retrieve findings with multi-criteria filtering."""
    db = get_db()
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if target:
        query += " AND (target LIKE ? OR host LIKE ?)"
        params.extend([f"%{target}%", f"%{target}%"])
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if status:
        query += " AND status = ?"
        params.append(status.upper())
    if cve:
        query += " AND (cve LIKE ? OR cve_ids LIKE ?)"
        params.extend([f"%{cve}%", f"%{cve}%"])

    query += """
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            risk_score DESC,
            created_at DESC
        LIMIT ?
    """
    params.append(limit)

    with db.get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if not d.get("title") and d.get("vulnerability"):
                d["title"] = d["vulnerability"]
            results.append(d)
        return results


def get_findings_summary() -> Dict[str, int]:
    """Return count of findings grouped by severity."""
    db = get_db()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0}
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ).fetchall()
        for r in rows:
            sev = (r["severity"] or "INFO").upper()
            if sev in counts:
                counts[sev] = r["cnt"]
                counts["TOTAL"] += r["cnt"]
    return counts


# ---------------------------------------------------------------------------
# EVIDENCE & TOOL RUNS
# ---------------------------------------------------------------------------

def create_evidence(evidence: Evidence) -> str:
    """Store structured, hashed evidence linked to findings and scans (BDIE V2)."""
    db = get_db()
    # Compute sha256 hash if not already computed
    if not evidence.hash_sha256 and evidence.output_excerpt:
        evidence.hash_sha256 = hashlib.sha256(evidence.output_excerpt.encode("utf-8")).hexdigest()

    with db.get_connection() as conn:
        valid_finding_id = evidence.finding_id
        if valid_finding_id:
            exists = conn.execute("SELECT id FROM findings WHERE id = ?", (valid_finding_id,)).fetchone()
            if not exists:
                valid_finding_id = None
        valid_scan_id = evidence.scan_id
        if valid_scan_id:
            exists = conn.execute("SELECT id FROM scans WHERE id = ?", (valid_scan_id,)).fetchone()
            if not exists:
                valid_scan_id = None

        conn.execute("""
            INSERT OR REPLACE INTO evidence (
                id, target, tool_name, output_excerpt, command_used,
                finding_id, scan_id, timestamp, raw_result_path,
                packet_metadata, http_metadata, scanner_result, hash_sha256,
                evidence_type, request_data, response_data, observed_data, tool_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence.id, evidence.target, evidence.tool_name, evidence.output_excerpt,
            evidence.command_used, valid_finding_id, valid_scan_id,
            evidence.timestamp, evidence.raw_result_path,
            json.dumps(evidence.packet_metadata or {}), json.dumps(evidence.http_metadata or {}),
            json.dumps(evidence.scanner_result or {}), evidence.hash_sha256,
            evidence.evidence_type or "TOOL_OUTPUT",
            json.dumps(evidence.request_data or {}),
            json.dumps(evidence.response_data or {}),
            json.dumps(evidence.observed_data or {}),
            evidence.tool_run_id
        ))
    return evidence.id


def get_evidence(evidence_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve specific evidence record by ID."""
    db = get_db()
    with db.get_connection() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return dict(row) if row else None


def get_evidence_by_scan(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieve all evidence collected during a scan."""
    db = get_db()
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE scan_id = ? ORDER BY timestamp ASC", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_evidence_by_finding(finding_id: str) -> List[Dict[str, Any]]:
    """Retrieve all evidence associated with a specific finding."""
    db = get_db()
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY timestamp ASC", (finding_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def record_tool_run(tool_run: ToolRun) -> str:
    """Record an individual tool execution instance."""
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO tool_runs (
                id, scan_id, tool_name, command_line, exit_code,
                start_time, end_time, duration_sec, stdout_excerpt,
                stderr_excerpt, raw_output_path, hash_sha256, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tool_run.id, tool_run.scan_id, tool_run.tool_name,
            tool_run.command_line, tool_run.exit_code,
            tool_run.start_time, tool_run.end_time, tool_run.duration_sec,
            tool_run.stdout_excerpt, tool_run.stderr_excerpt,
            tool_run.raw_output_path, tool_run.hash_sha256, tool_run.status
        ))
    return tool_run.id


def get_tool_runs(scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve tool run history."""
    db = get_db()
    with db.get_connection() as conn:
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM tool_runs WHERE scan_id = ? ORDER BY start_time ASC", (scan_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM tool_runs ORDER BY start_time DESC LIMIT 100"
            ).fetchall()
        return [dict(r) for r in rows]


def save_tool_output(tool_name: str, raw_output: str, scan_id: Optional[str] = None,
                     command_line: Optional[str] = None, exit_code: int = 0,
                     structured_json: Optional[Dict[str, Any]] = None):
    """Persist raw output from security tools (backward compatible)."""
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO tool_outputs (scan_id, tool_name, command_line, exit_code, raw_output, structured_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, tool_name, command_line, exit_code, raw_output, json.dumps(structured_json or {})))


# ---------------------------------------------------------------------------
# AUDIT & AI LOGS
# ---------------------------------------------------------------------------

def record_audit_event(event: AuditEvent) -> int:
    """Insert structured audit event."""
    db = get_db()
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_logs (
                event_type, user_action, target, tool_name, mode, decision, details, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_type, event.user_action, event.target,
            event.tool_name, event.mode, event.decision, event.details,
            event.timestamp or datetime.now().isoformat()
        ))
        return cur.lastrowid


def get_audit_events(limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve audit events in reverse chronological order."""
    db = get_db()
    with db.get_connection() as conn:
        if event_type:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                (event_type, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def save_ai_analysis(specialist_role: str, model_name: str, analysis_text: str,
                     recommendations: Optional[str] = None, scan_id: Optional[str] = None,
                     finding_id: Optional[str] = None, confidence_score: float = 0.95):
    """Save an AI analysis response for persistence and RAG (backward compatible)."""
    db = get_db()
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO ai_analyses (
                scan_id, finding_id, specialist_role, model_name,
                analysis_text, recommendations, confidence_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, finding_id, specialist_role, model_name, analysis_text, recommendations, confidence_score))


def get_all_reports(limit: int = 50, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve generated report deliverables."""
    db = get_db()
    with db.get_connection() as conn:
        if target:
            rows = conn.execute(
                "SELECT * FROM reports WHERE target = ? ORDER BY created_at DESC LIMIT ?", (target, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def get_report(report_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve specific report record by ID."""
    db = get_db()
    with db.get_connection() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# SYSTEM STATUS & EXPORT
# ---------------------------------------------------------------------------

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
        assets_cnt = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        evidence_cnt = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    return {
        "db_path": str(db.db_path),
        "db_size_bytes": db.db_path.stat().st_size if db.db_path.exists() else 0,
        "assets": assets_cnt,
        "hosts": hosts_cnt,
        "ports": ports_cnt,
        "findings": findings_cnt,
        "scans": scans_cnt,
        "tool_outputs": tools_cnt,
        "evidence": evidence_cnt,
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
            "assets": [dict(r) for r in conn.execute("SELECT * FROM assets").fetchall()],
            "hosts": [dict(r) for r in conn.execute("SELECT * FROM hosts").fetchall()],
            "ports": [dict(r) for r in conn.execute("SELECT * FROM ports").fetchall()],
            "findings": [dict(r) for r in conn.execute("SELECT * FROM findings").fetchall()],
            "scans": [dict(r) for r in conn.execute("SELECT * FROM scans").fetchall()],
            "evidence": [dict(r) for r in conn.execute("SELECT * FROM evidence").fetchall()],
            "reports": [dict(r) for r in conn.execute("SELECT * FROM reports").fetchall()],
            "ai_analyses": [dict(r) for r in conn.execute("SELECT * FROM ai_analyses").fetchall()]
        }
