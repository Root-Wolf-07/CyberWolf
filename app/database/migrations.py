"""CYBERWOLF Non-Destructive Database Migrations Engine.

Ensures existing SQLite databases are upgraded smoothly without data loss.
Tracks applied migrations in the `schema_migrations` table.
"""

import sqlite3
from typing import List, Tuple
from app.core.logger import get_logger

logger = get_logger()

# Ordered migration list: (migration_version, description, migration_sql)
MIGRATIONS: List[Tuple[str, str, str]] = [
    (
        "001_initial_schema",
        "Initial CYBERWOLF schema with assets, hosts, ports, findings, scans, reports, audit_logs",
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_identifier TEXT NOT NULL UNIQUE,
            asset_type TEXT NOT NULL DEFAULT 'ip',
            description TEXT,
            risk_level TEXT DEFAULT 'LOW',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scanned TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            ip_address TEXT NOT NULL,
            hostname TEXT,
            mac_address TEXT,
            os_name TEXT,
            os_accuracy INTEGER,
            status TEXT DEFAULT 'UP',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            state TEXT NOT NULL DEFAULT 'open',
            service_name TEXT,
            service_product TEXT,
            service_version TEXT,
            banner TEXT,
            last_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
            UNIQUE(host_id, port_number, protocol)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            asset_id INTEGER,
            host_id INTEGER,
            port INTEGER,
            protocol TEXT DEFAULT 'tcp',
            service TEXT,
            vulnerability TEXT NOT NULL,
            cve TEXT,
            cwe TEXT,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence TEXT NOT NULL,
            remediation TEXT,
            source_tool TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verified BOOLEAN DEFAULT 0,
            status TEXT DEFAULT 'OPEN',
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'SAFE_SCAN',
            status TEXT NOT NULL DEFAULT 'RUNNING',
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            findings_count INTEGER DEFAULT 0,
            summary JSON
        );

        CREATE TABLE IF NOT EXISTS tool_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            tool_name TEXT NOT NULL,
            command_line TEXT,
            exit_code INTEGER,
            raw_output TEXT,
            structured_json JSON,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ai_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            finding_id TEXT,
            specialist_role TEXT NOT NULL,
            model_name TEXT NOT NULL,
            analysis_text TEXT NOT NULL,
            recommendations TEXT,
            confidence_score REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL,
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            report_format TEXT NOT NULL,
            file_path TEXT NOT NULL,
            target TEXT NOT NULL,
            summary_text TEXT,
            findings_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            user_action TEXT NOT NULL,
            target TEXT,
            tool_name TEXT,
            mode TEXT,
            decision TEXT NOT NULL,
            details TEXT
        );
        """
    ),
    (
        "002_v2_canonical_tables",
        "V2 enhancements: evidence, tool_runs, finding_sources, scan_targets, policies",
        """
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            output_excerpt TEXT NOT NULL,
            command_used TEXT,
            finding_id TEXT,
            scan_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            raw_result_path TEXT,
            packet_metadata JSON,
            http_metadata JSON,
            scanner_result JSON,
            hash_sha256 TEXT,
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tool_runs (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            tool_name TEXT NOT NULL,
            command_line TEXT NOT NULL,
            exit_code INTEGER DEFAULT 0,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            duration_sec REAL DEFAULT 0.0,
            stdout_excerpt TEXT,
            stderr_excerpt TEXT,
            raw_output_path TEXT,
            hash_sha256 TEXT,
            status TEXT DEFAULT 'COMPLETED',
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS finding_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            evidence_id TEXT,
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE,
            FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL,
            UNIQUE(finding_id, tool_name)
        );

        CREATE TABLE IF NOT EXISTS scan_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            target TEXT NOT NULL,
            authorized BOOLEAN DEFAULT 1,
            scope_name TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS policies (
            name TEXT PRIMARY KEY,
            allow_network_scan BOOLEAN DEFAULT 1,
            allow_web_scan BOOLEAN DEFAULT 1,
            allow_packet_capture BOOLEAN DEFAULT 1,
            allow_bruteforce BOOLEAN DEFAULT 0,
            allow_destructive BOOLEAN DEFAULT 0,
            max_scan_duration INTEGER DEFAULT 900,
            allowed_tools JSON,
            rate_limit_delay_ms INTEGER DEFAULT 50,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    ),
    (
        "003_v2_indexes_and_constraints",
        "V2 Indexes for fast asset, host, finding, scan, CVE, and evidence lookups",
        """
        CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address);
        CREATE INDEX IF NOT EXISTS idx_hosts_asset ON hosts(asset_id);
        CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(hash_sha256);
        CREATE INDEX IF NOT EXISTS idx_tool_runs_scan ON tool_runs(scan_id);
        """
    )
]


def _column_exists(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a given table."""
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name});")
    columns = [row[1] for row in cur.fetchall()]
    return column_name in columns


def apply_migrations(conn: sqlite3.Connection):
    """Safely apply all pending migrations in order."""
    # Ensure migration tracking table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        );
    """)

    cur = conn.cursor()
    cur.execute("SELECT version FROM schema_migrations;")
    applied = set(row[0] for row in cur.fetchall())

    for version, desc, sql in MIGRATIONS:
        if version not in applied:
            logger.info(f"Applying database migration '{version}': {desc}")
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations (version, description) VALUES (?, ?);",
                (version, desc)
            )
            logger.info(f"Migration '{version}' applied successfully.")

    # Column upgrades for backward-compatible existing tables
    _upgrade_table_columns(conn)


def _upgrade_table_columns(conn: sqlite3.Connection):
    """Add new V2 columns to existing tables if missing (non-destructive)."""
    # 1. Findings table column additions
    findings_cols = [
        ("title", "TEXT"),
        ("description", "TEXT"),
        ("category", "TEXT DEFAULT 'general'"),
        ("host", "TEXT"),
        ("cve_ids", "JSON"),
        ("cwe_ids", "JSON"),
        ("owasp_category", "TEXT"),
        ("risk_score", "REAL DEFAULT 0.0"),
        ("risk_factors", "JSON"),
        ("first_seen", "TIMESTAMP"),
        ("last_seen", "TIMESTAMP")
    ]
    for col_name, col_type in findings_cols:
        if not _column_exists(conn, "findings", col_name):
            try:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type};")
            except Exception as e:
                logger.debug(f"Column {col_name} alter warning: {e}")

    # 2. Scans table column additions
    scans_cols = [
        ("authorization_status", "TEXT DEFAULT 'AUTHORIZED'"),
        ("policy_applied", "TEXT DEFAULT 'SAFE_SCAN'"),
        ("tools_executed", "JSON"),
        ("critical_count", "INTEGER DEFAULT 0"),
        ("high_count", "INTEGER DEFAULT 0"),
        ("medium_count", "INTEGER DEFAULT 0"),
        ("low_count", "INTEGER DEFAULT 0"),
        ("info_count", "INTEGER DEFAULT 0"),
        ("report_locations", "JSON")
    ]
    for col_name, col_type in scans_cols:
        if not _column_exists(conn, "scans", col_name):
            try:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type};")
            except Exception as e:
                logger.debug(f"Column {col_name} alter warning: {e}")

    # 3. Assets table column additions
    assets_cols = [
        ("asset_id", "TEXT"),
        ("hostname", "TEXT"),
        ("ip_address", "TEXT"),
        ("mac_address", "TEXT"),
        ("operating_system", "TEXT"),
        ("device_type", "TEXT"),
        ("open_ports", "JSON"),
        ("discovered_services", "JSON"),
        ("technologies", "JSON"),
        ("risk_score", "REAL DEFAULT 0.0")
    ]
    for col_name, col_type in assets_cols:
        if not _column_exists(conn, "assets", col_name):
            try:
                conn.execute(f"ALTER TABLE assets ADD COLUMN {col_name} {col_type};")
            except Exception as e:
                logger.debug(f"Column {col_name} alter warning: {e}")

    # 4. Reports table column additions
    reports_cols = [
        ("scan_id", "TEXT")
    ]
    for col_name, col_type in reports_cols:
        if not _column_exists(conn, "reports", col_name):
            try:
                conn.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_type};")
            except Exception as e:
                logger.debug(f"Column {col_name} alter warning: {e}")


class MigrationRunner:
    """Manages idempotent schema migration execution across databases."""

    def __init__(self, db_path=None):
        self.db_path = db_path

    def run_all_migrations(self) -> bool:
        """Run all pending schema migrations."""
        if self.db_path:
            with sqlite3.connect(self.db_path) as conn:
                apply_migrations(conn)
                conn.commit()
        else:
            from app.database.db_manager import get_db
            with get_db().get_connection() as conn:
                apply_migrations(conn)
                conn.commit()
        return True

