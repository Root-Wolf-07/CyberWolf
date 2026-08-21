-- CYBERWOLF Local SQLite Security Schema

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_identifier TEXT NOT NULL UNIQUE,
    asset_type TEXT NOT NULL, -- 'ip', 'cidr', 'domain', 'url'
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
    protocol TEXT NOT NULL DEFAULT 'tcp', -- 'tcp', 'udp'
    state TEXT NOT NULL DEFAULT 'open', -- 'open', 'filtered', 'closed'
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    banner TEXT,
    last_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE(host_id, port_number, protocol)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, -- e.g. 'CW-FIND-2026-0001'
    target TEXT NOT NULL,
    asset_id INTEGER,
    host_id INTEGER,
    port INTEGER,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    vulnerability TEXT NOT NULL,
    cve TEXT,
    cwe TEXT,
    severity TEXT NOT NULL, -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    confidence TEXT NOT NULL, -- 'HIGH', 'MEDIUM', 'LOW'
    evidence TEXT NOT NULL,
    remediation TEXT,
    source_tool TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT 0,
    status TEXT DEFAULT 'OPEN', -- 'OPEN', 'RESOLVED', 'FALSE_POSITIVE'
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, -- e.g. 'SCAN-20260820-001'
    scan_type TEXT NOT NULL, -- 'network', 'vulnerability', 'web', 'sqli', 'traffic', 'pentest'
    target TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'SAFE_SCAN',
    status TEXT NOT NULL DEFAULT 'RUNNING', -- 'RUNNING', 'COMPLETED', 'FAILED', 'ABORTED'
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
    report_format TEXT NOT NULL, -- 'HTML', 'JSON', 'TXT', 'CSV'
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
    decision TEXT NOT NULL, -- 'APPROVED', 'REJECTED', 'PROCEEDED', 'CONFIRMED'
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
