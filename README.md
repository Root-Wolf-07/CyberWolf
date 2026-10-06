# CYBERWOLF V2 — Professional Cybersecurity Platform

```text
================================================================================
                     C Y B E R W O L F   V 2 . 0 . 0
          Modular Cybersecurity Assessment & Investigation Platform
        HUNT THREATS  •  NORMALIZE DATA  •  CALCULATE RISK  •  DEFEND
================================================================================
```

[![CI Tests](https://github.com/Root-Wolf-07/CyberWolf/actions/workflows/tests.yml/badge.svg)](https://github.com/Root-Wolf-07/CyberWolf/actions/workflows/tests.yml)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/Root-Wolf-07/CyberWolf)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Security Boundary](https://img.shields.io/badge/safety-authorized--only-red.svg)](#-legal--authorized-testing-disclaimer)

**CYBERWOLF V2** is a modular, local-first cybersecurity assessment and investigation platform engineered for authorized security researchers, SOC analysts, and lab administrators. It orchestrates external security scanners, normalizes disparate tool findings into a canonical data model, performs rule-based vulnerability correlation, calculates transparent and explainable risk scores, preserves cryptographic evidence with SHA-256 provenance, generates client-ready executive deliverables (JSON, CSV, dark SOC HTML, and ReportLab PDF), and serves an operational workstation interface.

---

## ⚠️ Legal & Authorized Testing Disclaimer

> **IMPORTANT**: CYBERWOLF is engineered exclusively for authorized security assessments, owned infrastructure, CTF competitions, local laboratory experiments, and academic cybersecurity research.
>
> 1. **Authorization Required**: Never execute scans against external networks, systems, or targets without explicit, documented written authorization from the system owner.
> 2. **Prohibited Actions**: Features whose primary purpose is unauthorized intrusion, persistence, malware execution, credential theft, or denial-of-service are strictly prohibited and intentionally omitted from this software.
> 3. **Compliance**: Users are solely responsible for ensuring compliance with all local, national, and international cybersecurity laws (including the CFAA in the United States and equivalent computer misuse legislation worldwide).

---

## 🐺 Core Architecture & Philosophy

CYBERWOLF V2 is built around an **audit-first, offline-capable, local-first** engineering design. External tools are treated as interchangeable sensor adapters whose raw observations are ingested, validated, normalized, and bound to verifiable evidence.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION & INTERFACE                        │
│   Unified CLI (app/main.py)   │   SOC Analyst Workstation (app/web/)   │
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
│• Audit Log    │           │• Risk Engine  │           │• Storage      │
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

## 🚀 Key Features

- **Authorization-First Pipeline**: Mandates that every target passes through `Target Parser -> Scope Check -> Policy Engine -> Tool Validation` prior to subprocess execution.
- **Canonical Security Models**: Standardizes findings, assets, scans, evidence, and tool runs with strongly typed dataclasses and SQLite constraints.
- **Deduplication & Correlation**: Groups findings sharing host, port, protocol, and vulnerability signature across multiple tools while maintaining source provenance.
- **Transparent Risk Scoring**: Replaces arbitrary numbers with explainable risk metrics computed from severity weight, tool confidence, asset criticality, and attack surface exposure.
- **Cryptographic Evidence Vault**: Stores raw tool outputs, command lines, and timestamps with SHA-256 integrity digests in `database/evidence/`.
- **Knowledge & 6-Point Remediation**: Offline CVE/CWE database and OWASP Top 10 playbooks mapped to findings with actionable remediation instructions.
- **Client-Ready Reporting**: Generates auditable reports in JSON, CSV, plain text, interactive dark SOC HTML, and multi-page printable PDF (via ReportLab).
- **Subprocess Security**: All tool adapters invoke system binaries via argument lists (`shell=False`), enforcing strict timeouts, process termination, and 5MB output capture caps.
- **Decoupled REST API & Web Dashboard**: Zero-dependency `ThreadingHTTPServer` serving JSON REST endpoints and a clean, density-optimized SOC Analyst Workstation.
- **Offline-First & Local**: Full scanning, normalization, reporting, and database management work autonomously without external network or cloud AI dependencies.

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.9, 3.10, or 3.11
- Standard POSIX or Windows shell (Linux, macOS, Windows PowerShell)
- External security tools (optional, installed as needed): Nmap, Nuclei, Nikto, ffuf, Wireshark/TShark

### 1. Clone & Setup Virtual Environment

```bash
# Clone the repository
git clone https://github.com/Root-Wolf-07/CyberWolf.git
cd CyberWolf

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# macOS / Linux:
source .venv/bin/activate
# Windows:
# .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration

```bash
# Copy template configuration
cp .env.example .env

# Configure environment variables (optional API keys, custom database paths, etc.)
```

### 3. Run System Diagnostic (`doctor`)

Verify your local environment, database schema, file permissions, and tool discovery:

```bash
cyberwolf doctor
# Or via Python module directly:
python -m app.main doctor
```

```text
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          CYBERWOLF V2 DOCTOR DIAGNOSTIC                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
 Component              Status      Details
 Python Version         ✓ READY     Python 3.9.6
 Database Engine        ✓ HEALTHY   SQLite WAL (Migrations: 3, Integrity: ok)
 Configuration          ✓ VALID     All 4 config files present (SAFE_SCAN mode)
 Filesystem Perms       ✓ WRITABLE  logs, reports, database & knowledge dirs ready
 Knowledge Base         ✓ LOADED    CVE offline database & OWASP playbooks valid
```

---

## 🛠️ CLI Command Reference

CYBERWOLF provides an intuitive, auditable command interface:

### Target & Scope Management
```bash
# List all pre-configured authorized targets
cyberwolf targets list

# Enroll a new target into authorized scope (explicit authorization)
cyberwolf target add 192.168.1.100 --scope lab-network --description "Primary Lab Server"
cyberwolf target add 10.0.0.15 --authorized
```

### Scanning Operations
```bash
# Scan an authorized target with default safe tools
cyberwolf scan 127.0.0.1

# Execute specific tool assessment against authorized target
cyberwolf scan 127.0.0.1 --tool nmap
cyberwolf scan 127.0.0.1 --tool nuclei --ports 80,443

# List previous scan sessions
cyberwolf scan list

# View detailed scan execution record
cyberwolf scan show CW-2026-00001

# Cancel an active in-flight scan
cyberwolf scan cancel CW-2026-00001
```

### Finding Investigation & Knowledge
```bash
# List all normalized security findings
cyberwolf findings list

# Filter findings by severity
cyberwolf findings list --severity HIGH

# Inspect a specific finding with complete evidence and remediation
cyberwolf findings show FIND-001

# View actionable remediation explanation
cyberwolf findings explain FIND-001
```

### Discovered Asset Management
```bash
# List all tracked network assets
cyberwolf assets list

# View details, open ports, and risk score for an asset
cyberwolf assets show 127.0.0.1
```

### Security Reporting
```bash
# List generated reports
cyberwolf report list

# Generate reports for a scan in HTML, PDF, JSON, or CSV
cyberwolf report generate --scan CW-2026-00001 --format html
cyberwolf report generate --scan CW-2026-00001 --format pdf
cyberwolf report generate --scan CW-2026-00001 --format json
cyberwolf report generate --scan CW-2026-00001 --format csv
```

### Security Policy & Tools
```bash
# Inspect active safety policy constraints
cyberwolf policy show

# List supported tool adapters and system availability
cyberwolf tools list

# Create a secure database backup
cyberwolf database backup
```

### SOC Analyst Workstation & REST API
```bash
# Start local REST API & Workstation Web Dashboard on port 8080
cyberwolf serve --port 8080
# Or using the alias:
cyberwolf dashboard --port 8080
```
Open `http://127.0.0.1:8080/` in any modern browser to access the SOC Analyst Workstation.

---

## 🌐 REST API Endpoints

The internal server (`app/web/server.py`) provides clean, unauthenticated local REST endpoints for integration:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | System health, database integrity, and timestamp |
| `GET` | `/api/status` | Global metrics (scans, findings, assets, risk distribution) |
| `GET` | `/api/scans` | List scan history |
| `POST` | `/api/scans` | Launch new assessment (`{"target": "127.0.0.1", "tools": ["nmap"]}`) |
| `GET` | `/api/scans/<id>` | Inspect scan details and progress |
| `POST` | `/api/scans/<id>/cancel` | Cancel active scan session |
| `GET` | `/api/findings` | Query normalized findings (`?severity=HIGH&status=OPEN`) |
| `GET` | `/api/findings/<id>` | Full finding detail with evidence links |
| `PATCH` | `/api/findings/<id>/status` | Update finding triage status (`CONFIRMED`, `FALSE_POSITIVE`, `RESOLVED`) |
| `GET` | `/api/assets` | Query discovered assets and open ports |
| `GET` | `/api/targets` | List authorized scopes |
| `POST` | `/api/targets` | Enroll target (`{"target": "10.0.0.5", "scope_id": "lab"}`) |
| `GET` | `/api/tools` | Inspect tool adapter readiness |
| `GET` | `/api/policies` | Active policy configuration |
| `GET` | `/api/reports` | List generated report artifacts |
| `POST` | `/api/reports` | Generate report (`{"scan_id": "CW-...", "format": "pdf"}`) |

---

## 🔒 Security Execution Model

CYBERWOLF enforces defense-in-depth across the entire execution stack:

1. **Strict Input Sanitization**: Target inputs are validated against strict RFC standards for IPv4, IPv6, CIDR blocks, hostnames, and URLs using `ipaddress` and Python networking libraries. Shell metacharacters (`;&|$\` etc.) are permanently rejected.
2. **Deterministic Process Execution**: Scanners are executed strictly with `subprocess.run(args_list, shell=False)` without shell expansion.
3. **Execution Timeouts & Process Cleanup**: Every subprocess is bound to a hard timeout (default 300s). On expiry or cancellation, the process tree is killed via `SIGKILL`.
4. **Output Buffering & Hashing**: Standard output and error streams are capped at 5MB to avoid memory exhaustion and hashed with SHA-256 for cryptographic evidence integrity.
5. **Audit Logging & Secret Scrubbing**: All operations, scope decisions, and policy events are written to structured audit logs (`logs/security/audit.log`) with automated masking of credentials, tokens, and sensitive query parameters.

---

## 🧪 Automated Testing

CYBERWOLF includes a comprehensive, offline-first automated test suite. Unit and security tests mock external tool executions, requiring no external scanners to be installed.

```bash
# Run complete test suite
pytest tests

# Run specific test modules
pytest tests/unit/
pytest tests/security/
pytest tests/integration/

# Check test coverage
pytest --tb=short -q
```

All 66 tests pass cleanly across unit, integration, security, and parser fixtures.

---

## 📂 Project Structure

```text
CyberWolf/
├── app/
│   ├── main.py                     # Unified CLI & Command Dispatcher
│   ├── cli/                        # Interactive REPL & CLI Command Handlers
│   ├── core/                       # Configuration, Logger, Platform Adapter, Exceptions
│   ├── database/                   # SQLite Manager, Canonical Models, Migrations, Operations
│   ├── detection/                  # Normalizer, Deduplicator, Correlator, Risk Engine
│   ├── evidence/                   # EvidenceVault (SHA-256 provenance, excerpt capture)
│   ├── intelligence/               # CVE KB, OWASP Playbooks, Remediation Advisor
│   ├── reports/                    # Report Generator (JSON, CSV, HTML, ReportLab PDF)
│   ├── security/                   # Target Sanitizer, Scope Authorizer, Policy Engine
│   ├── services/                   # ScanService, FindingService, AssetService, TargetService
│   ├── tools/                      # Base Adapter, Runner, Adapters (Nmap, Nuclei, Nikto, ffuf, TShark)
│   └── web/                        # ThreadingHTTPServer, REST API, SOC Analyst Workstation
├── bin/
│   └── cyberwolf                   # POSIX Executable Shell Launcher
├── config/
│   ├── config.yaml                 # Core Platform Configuration
│   ├── targets.yaml                # Authorized Scopes & Exclusions
│   ├── policies.yaml               # Safety Policies & Rate Limits
│   └── authorization.yaml          # Signed Legal Scope Records
├── database/
│   ├── cyberwolf.db                # SQLite Working Database (WAL mode)
│   ├── backups/                    # Timestamped Database Backups
│   └── evidence/                   # Cryptographic Evidence Storage
├── examples/reports/               # Example Deliverable Reports
├── knowledge/                      # Offline CVE & OWASP Datasets
├── logs/                           # System & Security Audit Logs
├── tests/
│   ├── unit/                       # Unit Tests (Models, Adapters, Engines)
│   ├── integration/                # Service & REST API Integration Tests
│   ├── security/                   # Command Injection, Traversal, XSS, Policy Tests
│   └── fixtures/                   # Realistic Scanner Output Fixtures (XML, JSONL, TXT)
├── .github/workflows/tests.yml     # Multi-Version CI Workflow
├── ARCHITECTURE.md                 # Deep Architectural Specification
├── DEVELOPMENT.md                  # Contributor & Adapter Development Guide
├── SECURITY.md                     # Vulnerability Policy & Safety Controls
├── CONTRIBUTING.md                 # Pull Request & Code Standards
├── CHANGELOG.md                    # Release History & Migration Notes
└── pyproject.toml                  # Package Configuration
```

---

## 📄 License & Attribution

CYBERWOLF V2 is distributed under the MIT License. See [LICENSE](LICENSE) for details.
Designed and maintained for ethical cybersecurity engineering and defense.
