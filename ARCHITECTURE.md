# CYBERWOLF V2 — Architectural Specification

## 1. Executive Summary & Design Philosophy

**CYBERWOLF V2** is an offline-capable, local-first cybersecurity assessment and investigation platform. Rather than serving as a simplistic wrapper around command-line scanners, CYBERWOLF acts as a centralized security orchestrator that:
1. Enforces mandatory authorization, target scope validation, and policy checks prior to tool execution.
2. Ingests raw outputs from heterogeneous security tools (Nmap, Nuclei, Nikto, ffuf, Gobuster, TShark, native sockets).
3. Normalizes findings into a strongly typed canonical data model.
4. Deduplicates overlapping findings across tools while preserving multi-source provenance.
5. Performs deterministic cross-tool vulnerability correlation.
6. Computes explainable, formula-driven risk scores based on severity, confidence, exposure, and asset criticality.
7. Preserves unalterable cryptographic evidence (SHA-256) for auditability and forensic defensibility.
8. Generates professional client deliverables in JSON, CSV, HTML, and PDF formats.

---

## 2. High-Level System Architecture

CYBERWOLF strictly enforces a **unidirectional layered architecture** where presentation layers (CLI and Web Dashboard) interact solely with the Core Service Layer:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION & CLIENTS                          │
│   Unified CLI (app/main.py)    │   SOC Analyst Workstation (app/web/)  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                          CORE SERVICE LAYER                            │
│  ScanService  │  FindingService  │  AssetService  │  TargetService     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│SECURITY ENGINE│           │DETECTION / KB │           │EVIDENCE VAULT │
│• Scope Auth   │           │• Normalizer   │           │• SHA-256 Hash │
│• Sanitizer    │           │• Deduplicator │           │• Provenance   │
│• Policy Rules │           │• Correlator   │           │• Raw Excerpts │
│• Audit Log    │           │• Risk Engine  │           │• File Store   │
└───────┬───────┘           │• CVE/OWASP KB │           └───────┬───────┘
        │                   └───────────────┘                   │
        │                                                       │
        ▼                                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         TOOL ADAPTER SUBSYSTEM                         │
│  Nmap  │  Nuclei  │  Nikto  │  ffuf  │  Gobuster  │  TShark  │  Socket │
│  (subprocess.run, shell=False, timeouts, 5MB cap, output hashing)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                    STORAGE & REPORTING SUBSYSTEM                       │
│  SQLite WAL Database + Migrations  │  JSON / CSV / HTML / PDF Reports  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Domain Models

CYBERWOLF V2 defines eight canonical domain entities in `app/database/models.py`. Every subsystem interacts with these models rather than tool-specific data structures.

### 3.1 `Finding`
Represents an identified security issue, misconfiguration, or vulnerability.
- `id` (str): Unique finding identifier (e.g. `FIND-20261006-A1B2C3D4`)
- `title` (str): Concise vulnerability title
- `description` (str): Technical explanation of the issue
- `severity` (str): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `confidence` (str): `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`
- `category` (str): Classification (e.g. `web_vuln`, `open_port`, `misconfiguration`)
- `asset_id` (str): Foreign key to the associated Asset
- `host` (str): IP address or hostname
- `port` (int): Target TCP/UDP port (0 if host-wide)
- `protocol` (str): `tcp`, `udp`, `http`, `https`
- `service` (str): Discovered service name (e.g. `http`, `ssh`, `apache`)
- `cve_ids` (List[str]): Associated CVE identifiers (e.g. `["CVE-2021-44228"]`)
- `cwe_ids` (List[str]): Associated CWE identifiers (e.g. `["CWE-89"]`)
- `owasp_category` (str): Relevant OWASP classification (e.g. `A01:2021-Broken Access Control`)
- `evidence` (str): Technical proof excerpt, HTTP request/response, or banner
- `evidence_id` (str): Reference to cryptographic record in `EvidenceVault`
- `source_tools` (List[str]): Tools that observed or confirmed the finding (e.g. `["nmap", "nuclei"]`)
- `risk_score` (float): Transparent risk score (0.0 to 10.0)
- `risk_factors` (Dict[str, Any]): Mathematical factor breakdown
- `remediation` (str): Comprehensive remediation guidance
- `status` (str): Triage state (`OPEN`, `CONFIRMED`, `FALSE_POSITIVE`, `RESOLVED`, `ACCEPTED_RISK`)
- `first_seen` / `last_seen` (str): ISO-8601 timestamps

### 3.2 `Asset`
Represents a distinct discovered network entity.
- `asset_id` (str): Unique asset identifier (derived from IP/hostname)
- `ip_address` (str): Discovered IPv4 or IPv6 address
- `hostname` (str): Reverse-resolved or queried DNS name
- `mac_address` (str): Physical hardware address if local
- `operating_system` (str): Fingerprinted OS (e.g. `Linux 5.4`, `Windows Server 2022`)
- `device_type` (str): Host category (`server`, `workstation`, `router`, `firewall`)
- `open_ports` (List[int]): Monitored open ports
- `discovered_services` (Dict[str, Any]): Mapped port-to-service records
- `technologies` (List[str]): Identified software stacks (e.g. `Apache 2.4`, `PHP 8.1`)
- `risk_score` (float): Aggregate calculated host risk
- `criticality` (str): Business value (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)

### 3.3 `Scan`
Encapsulates a bounded security assessment session.
- `scan_id` (str): Session identifier (e.g. `CW-2026-00042`)
- `target` (str): Evaluated target input
- `target_type` (str): `ip`, `cidr`, `domain`, `url`
- `status` (str): `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`, `PARTIAL`
- `tools_executed` (List[str]): Adapters dispatched during assessment
- `findings_count` (int): Total unique findings detected
- `critical_count` / `high_count` / `medium_count` / `low_count` (int): Severity breakdown
- `start_time` / `end_time` (str): Execution timestamps
- `error_message` (str): Failure diagnostics if status is `FAILED`

### 3.4 `Evidence`
Cryptographically verified raw observation.
- `evidence_id` (str): Hash-derived ID (e.g. `EVID-SHA256`)
- `finding_id` (str): Associated finding
- `tool_name` (str): Sensor that produced the artifact
- `command_used` (str): Complete sanitized execution vector
- `raw_content` (str): Raw stdout/stderr or packet excerpt
- `file_path` (str): Path in `database/evidence/`
- `sha256_hash` (str): Cryptographic digest of raw artifact
- `timestamp` (str): Collection timestamp

### 3.5 Additional Supporting Models
- **`ToolRun`**: Records individual tool lifecycle (`RUNNING`, `COMPLETED`, `FAILED`, `TIMED_OUT`), exit codes, and durations.
- **`ReportRecord`**: Tracks generated deliverable artifacts (format, checksum, file size).
- **`AuditEvent`**: Unalterable security log for authorization changes and tool dispatches.
- **`Policy`**: Active operational boundaries (scan duration limits, destructive testing prohibitions).

---

## 4. Security & Authorization Pipeline

CyberWolf assumes all targets require authorization. The scan pipeline executes strictly in sequence:

```
Target Input
     │
     ▼
[Target Sanitizer] ──> Validates format (IPv4, IPv6, CIDR, Domain, URL)
     │                 Rejects shell metacharacters (; & | ` $ > <)
     ▼
[Target Authorizer] ──> Checks config/targets.yaml scopes & exclusions
     │                  Blocks unauthorized scans unless explicitly enrolled
     ▼
[Policy Engine] ──────> Checks operation permission, rate limits, timeouts
     │                  Prohibits destructive actions & brute-forcing
     ▼
[Tool Adapter] ───────> Validates arguments, checks binary in system PATH
     │
     ▼
[Subprocess Runner] ──> Executes binary:
                        • shell=False (argument lists only)
                        • hard execution timeout (SIGKILL on expiry)
                        • stdout/stderr capped at 5MB
                        • SHA-256 output digest calculated
```

---

## 5. Detection & Risk Engine

### 5.1 Finding Normalization (`FindingNormalizer`)
Disparate tool formats are translated into canonical `Finding` records:
- **Nmap XML**: Parses `<host>`, `<port>`, `<service>`, and `<script>` blocks into open port and service vulnerability findings.
- **Nuclei JSONL**: Ingests JSONLines objects, mapping template IDs, severities (`critical`, `high`, `medium`, `low`, `info`), CVE tags, and curl evidence.
- **Nikto Output**: Extracts web server banners, HTTP header flaws, outdated software notices, and OSVDB/CVE references.
- **ffuf JSON**: Maps sensitive directory disclosures and status codes.
- **TShark Output**: Ingests packet captures, identifying unencrypted cleartext protocols (HTTP, Telnet, FTP).

### 5.2 Deduplication (`FindingDeduplicator`)
When multiple tools discover identical issues (e.g., Nmap and Nikto both reporting an open Apache web server on port 80), CYBERWOLF merges them using a deterministic **Correlation Key**:
$$\text{Key} = \text{SHA256}(\text{Host} + \text{Port} + \text{Protocol} + \text{CVE/Signature} + \text{Normalized Title})$$
- Merges source tools (`["nmap", "nikto"]`).
- Elevates confidence to `CONFIRMED` when cross-verified by multiple tools.
- Preserves all unique evidence excerpts.

### 5.3 Finding Correlation (`FindingCorrelator`)
Cross-references discovered services with known vulnerability patterns without hallucination. For example:
- Open Port 80/443 + Identified Web Server Version + Matching Nuclei finding $\to$ Unified Correlated Web Asset Vulnerability.

### 5.4 Explainable Risk Engine (`RiskEngine`)
Risk scores are calculated using a transparent, deterministic mathematical formula rather than arbitrary values:

$$\text{Risk Score} = 10.0 \times \left( W_{\text{sev}} \times 0.50 + W_{\text{conf}} \times 0.20 + W_{\text{exp}} \times 0.20 + W_{\text{crit}} \times 0.10 \right)$$

Where:
- **Severity Weight ($W_{\text{sev}}$)**: `CRITICAL` (1.0), `HIGH` (0.8), `MEDIUM` (0.5), `LOW` (0.2), `INFO` (0.05)
- **Confidence Weight ($W_{\text{conf}}$)**: `CONFIRMED` (1.0), `HIGH` (0.85), `MEDIUM` (0.6), `LOW` (0.3)
- **Exposure Weight ($W_{\text{exp}}$)**: Public internet exposure (1.0), DMZ (0.8), Internal lab subnet (0.5), Loopback (0.3)
- **Asset Criticality ($W_{\text{crit}}$)**: `CRITICAL` (1.0), `HIGH` (0.8), `MEDIUM` (0.5), `LOW` (0.2)

Every finding stores both the final score (0.0 to 10.0) and the exact factor breakdown in `risk_factors` for analyst auditing.

---

## 6. Intelligence & Knowledge Layer

CYBERWOLF operates completely offline using local curated datasets:
- **`knowledge/cve_database.json`**: Indexed CVE repository providing CVSS base scores, affected product CPEs, and remediation steps.
- **`knowledge/owasp_playbooks.json`**: OWASP Top 10 mappings and defense verification tests.
- **`RemediationAdvisor`**: Generates a structured 6-point remediation plan for any finding:
  1. **Summary**: Clear executive explanation of the flaw.
  2. **Technical Impact**: Business and technical ramifications.
  3. **Immediate Mitigation**: Short-term defensive workaround.
  4. **Permanent Remediation**: Code, patch, or configuration fix.
  5. **Verification Steps**: Actionable command or test to verify the fix.
  6. **References**: Authoritative RFC, NIST, or OWASP links.

---

## 7. Cryptographic Evidence Vault (`EvidenceVault`)

To ensure evidentiary integrity for incident response and formal audits:
1. Every tool run stdout/stderr stream is written to `database/evidence/<scan_id>/<tool>_<timestamp>.raw`.
2. A cryptographic **SHA-256 digest** is computed from the byte stream.
3. The metadata record is committed to the SQLite `evidence` table.
4. Integrity verification can be executed at any time via `EvidenceVault.verify_evidence_integrity()`.

---

## 8. Reporting Subsystem (`app/reports/generator.py`)

Produces client-ready security assessment deliverables:
- **JSON**: Machine-readable, full fidelity export of scans, assets, findings, and evidence.
- **CSV**: Spreadsheet-compatible vulnerability tracking table.
- **Plain Text**: Terminal-formatted summary for CLI output or incident ticketing systems.
- **HTML Deliverable**: High-density, professional dark-mode SOC report featuring executive summaries, risk breakdowns, expandable finding cards, evidence viewers, and remediation tabs.
- **PDF Deliverable**: Multi-page formal assessment document built with ReportLab, featuring:
  - Cover page and executive summary
  - Risk metric summary tables
  - Detailed findings categorized by severity
  - Cryptographic evidence citations
  - Automatic page numbering and running headers

---

## 9. Database Architecture & Migrations

CYBERWOLF uses a local SQLite database configured with **WAL (Write-Ahead Logging)** mode for high-concurrency read/write operations without locking.

### 9.1 Schema Migrations (`app/database/migrations.py`)
Schema evolution is managed via an idempotent, version-tracked migration engine. The `schema_migrations` table tracks applied versions:
- `v1_initial_core`: Base scans, findings, targets, and events.
- `v2_canonical_platform`: Normalized assets, canonical findings, evidence vault, tool runs, reports, and policies.
- `v3_indexes_and_integrity`: Performance B-tree indexes across `asset_id`, `host`, `scan_id`, `severity`, `status`, and `cve`.

Database upgrades never destroy user data. Safe backups are created via `cyberwolf database backup`.

---

## 10. Web Workstation & REST API (`app/web/server.py`)

A zero-dependency HTTP service built on Python's `http.server.ThreadingHTTPServer`:
- **Decoupled Architecture**: Routes invoke `ScanService`, `FindingService`, and `AssetService`; no scanning or business logic lives in HTTP handlers.
- **SOC Analyst Workstation**: Clean, density-optimized interface prioritizing operational visibility, live scan telemetry, finding triage (`CONFIRMED`, `FALSE_POSITIVE`, `RESOLVED`), and evidence inspection.
