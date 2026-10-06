# CYBERWOLF V2 — ARCHITECTURE AUDIT & REFACTORING SPECIFICATION

**Date**: 2026-10-06  
**Auditor**: Antigravity Principal Security Software Engineer  
**Repository**: [Root-Wolf-07/CyberWolf](https://github.com/Root-Wolf-07/CyberWolf.git)  
**Project**: CyberWolf V2  

---

## 1. Executive Summary

CyberWolf is a local, AI-augmented cybersecurity command center and vulnerability assessment platform designed for authorized security testing, lab environments, owned infrastructure, and educational research.

This audit evaluates the codebase as cloned from Git commit `50f5cce` ("initial commit"). The core functionality provides a strong, working foundation with defensive principles already in place (e.g., `shell=False` execution, strict target regex sanitization, authorization scopes, and an active safety policy system). However, the project suffers from repo-level contamination (committed `.venv` and runtime artifacts), architectural coupling (CLI commands directly calling scanners without a shared service abstraction), lack of finding deduplication/correlation, static risk scoring, missing PDF report generation, and lack of a decoupled Web/API layer.

This document details the complete current state and establishes the step-by-step migration path to **CyberWolf V2**.

---

## 2. Current Architecture & Codebase Map

### 2.1 Directory Structure
```
CyberWolf/
├── .venv/                      # CRITICAL DEFECT: Committed virtual environment (58MB, non-portable)
├── bin/
│   └── cyberwolf               # Bash wrapper configuring PYTHONPATH and executing app/main.py
├── app/
│   ├── __init__.py
│   ├── main.py                 # Argparse entrypoint & command router
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── ollama_client.py    # Local Ollama HTTP API client
│   │   ├── orchestrator.py    # Multi-agent role prompting & analysis router
│   │   ├── prompts.py          # Specialist defensive personas & system directives
│   │   └── rag.py              # Local Jaccard/token-based RAG retrieval engine
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── banner.py           # Terminal ASCII banner & branding
│   │   ├── formatter.py        # Rich table formatting utilities
│   │   ├── menu.py             # REPL menu options
│   │   ├── repl.py             # Interactive shell loop
│   │   └── commands/           # 13 CLI command handlers (doctor, scan, vuln, reports, etc.)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py           # YAML configuration loader (app, ai, db, security)
│   │   ├── exceptions.py       # Domain exceptions hierarchy
│   │   ├── logger.py           # Logging & security audit trail logger
│   │   └── platform_adapter.py # OS privilege & platform detection
│   ├── database/
│   │   ├── __init__.py
│   │   ├── db_manager.py       # SQLite connection manager & schema initializer
│   │   ├── models.py           # Dataclasses: HostRecord, PortRecord, Finding, ScanRecord
│   │   └── operations.py       # SQLite CRUD operations
│   ├── demo/
│   │   ├── __init__.py
│   │   └── demo_runner.py      # Simulated end-to-end security assessment
│   ├── monitors/
│   │   ├── __init__.py
│   │   ├── ddos_detector.py    # Defensive traffic anomaly & rate surge detector
│   │   └── traffic_monitor.py  # Packet capture and rate monitor
│   ├── pentest/
│   │   ├── __init__.py
│   │   └── workflow.py         # Human-in-the-loop controlled pentest workflow
│   ├── reports/
│   │   ├── __init__.py
│   │   └── generator.py        # HTML (Dark SOC theme), JSON, CSV, and TXT report generator
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── bug_analyzer.py     # Sensitive file & misconfiguration probes
│   │   ├── network_scanner.py  # Nmap orchestration + Python native socket fallback
│   │   ├── sqli_scanner.py     # Non-destructive error/boolean SQL injection testing
│   │   ├── vuln_scanner.py     # Nuclei & Nikto vulnerability orchestration
│   │   └── web_scanner.py      # HTTP security headers & cookie audit
│   ├── security/
│   │   ├── __init__.py
│   │   ├── authorization.py    # Scope checking, target exclusion, consent prompts
│   │   ├── policies.py         # Mode-based policy constraints (PASSIVE to LAB_MODE)
│   │   └── sanitizer.py        # Shell injection prevention, regex validation
│   └── tools/
│       ├── __init__.py
│       ├── base_adapter.py     # Base abstract tool adapter
│       ├── detector.py         # Binary discovery in PATH & homebrew
│       ├── runner.py           # Subprocess execution engine (shell=False, timeouts)
│       └── adapters/
│           ├── ffuf_adapter.py
│           ├── nikto_adapter.py
│           ├── nmap_adapter.py
│           ├── nuclei_adapter.py
│           └── tshark_adapter.py
├── config/
│   ├── authorization.yaml      # Signed consent records & approved scopes
│   ├── config.yaml             # Main operational settings
│   ├── policies.yaml           # Operational modes and restrictions
│   └── targets.yaml            # Target scopes and exclusions
├── database/
│   ├── cyberwolf.db            # Committed runtime SQLite database
│   ├── cyberwolf.db-shm        # SQLite shared-memory file
│   ├── cyberwolf.db-wal        # SQLite write-ahead log file
│   └── schema.sql              # Core SQLite DDL schema
├── knowledge/
│   ├── cve_database.json       # Curated offline CVE definitions
│   └── owasp_playbooks.json    # OWASP Top 10 playbooks & detection logic
├── logs/
│   ├── cyberwolf.log           # Committed runtime log
│   └── security/audit.log      # Committed runtime audit log
├── reports/                    # Committed sample HTML/JSON/CSV/TXT reports
├── pyproject.toml              # Build config and dependencies
├── requirements.txt            # Minimal pip dependencies
└── tests/
    ├── test_ai_and_rag.py      # 4 tests (1 minor prompt case assertion mismatch)
    ├── test_config.py          # 6 tests
    ├── test_database.py        # 4 tests
    ├── test_reports.py         # 1 test
    ├── test_scanners.py        # 3 tests
    └── test_tools.py           # 3 tests
```

---

## 3. Entry Points

1. **CLI Script**: `bin/cyberwolf` (executable shell script wrapping `python3 app/main.py`).
2. **Package Entrypoint**: `cyberwolf = "app.main:main"` defined in `pyproject.toml`.
3. **Application Main Router**: `app/main.py`:
   - Subcommands: `doctor`, `status`, `demo`, `scan network`, `vuln`, `pentest`, `web`, `sql-test`, `monitor`, `ddos-monitor`, `reports`, `ai`, `database`, `config`, `lab`.
   - Default fallback: Interactive REPL terminal session (`app.cli.repl:run_interactive_repl()`).

---

## 4. Dependencies & Runtime Environment

### 4.1 Declared Dependencies
- `rich>=13.0.0`: Terminal styling, tables, panels.
- `pyyaml>=6.0`: YAML configuration reading.
- `requests>=2.28.0`: HTTP web security scanning, Ollama API communications.

### 4.2 Runtime Environment Requirements
- Python 3.9+ (tested on Python 3.9.6).
- Standard libraries heavily utilized: `subprocess`, `socket`, `urllib.parse`, `ipaddress`, `sqlite3`, `json`, `dataclasses`, `hashlib`, `concurrent.futures`.

---

## 5. Security Tools & Adapters Analyzed

| Tool Adapter | File Location | Detection Method | Command Construction | Execution Controls | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Nmap** | `app/tools/adapters/nmap_adapter.py` | `shutil.which` / paths | Structured `cmd` list (`-F`, `-sV`, `-p`) | `ToolRunner.execute`, `shell=False`, 90s timeout | Functional; regex parser handles stdout |
| **Nuclei** | `app/tools/adapters/nuclei_adapter.py` | Binary lookup | Structured list (`-json-export`, `-silent`) | `ToolRunner.execute`, `shell=False`, 120s timeout | Functional; JSON parser extracts CVE/CWE |
| **Nikto** | `app/tools/adapters/nikto_adapter.py` | Binary lookup (`nikto`, `nikto.pl`) | Structured list (`-h`, `-p`, `-ssl`) | `ToolRunner.execute`, `shell=False`, 120s timeout | Functional; lines beginning with `+` parsed |
| **ffuf** | `app/tools/adapters/ffuf_adapter.py` | Binary lookup (`ffuf`) | Structured list (`-u`, `-w`, `-of json`) | `ToolRunner.execute`, `shell=False` | Functional; JSON results parsed |
| **Gobuster**| `app/tools/adapters/ffuf_adapter.py` | Binary lookup (`gobuster`) | Structured list (`mode`, `-u`, `-w`) | `ToolRunner.execute`, `shell=False` | Functional; text output parsed |
| **TShark** | `app/tools/adapters/tshark_adapter.py` | Binary lookup (`tshark`) | Structured list (`-i`, `-a duration`, `-T fields`) | `ToolRunner.execute`, `shell=False` | Functional; tab-separated line parser |
| **Metasploit**| `app/tools/adapters/tshark_adapter.py` | Binary lookup (`msfconsole`) | Structured list (`-q`, `-r script`) | `ToolRunner.execute`, `shell=False` | Stub/raw execution only |
| **Hydra** | `app/tools/adapters/tshark_adapter.py` | Binary lookup (`hydra`) | Structured list (`-L`, `-P`, `-s`) | `ToolRunner.execute`, `shell=False` | Stub/credential regex parser |

---

## 6. Database & Storage Architecture

### 6.1 Database Schema (`database/schema.sql`)
- `assets`: Target identifiers, asset types, risk level, timestamps.
- `hosts`: IP address, hostname, MAC, OS, status, foreign key to `assets`.
- `ports`: Port number, protocol, state, service, version, banner, foreign key to `hosts`.
- `findings`: Finding ID (`CW-FIND-YYYY-XXXX`), target, port, protocol, service, vulnerability, CVE, CWE, severity, confidence, evidence, remediation, source tool, status.
- `scans`: Scan ID (`SCAN-YYYYMMDDHHMMSS-XXXX`), type, target, mode, status, timestamps, findings count, summary JSON.
- `tool_outputs`: Scan ID, tool name, command line, exit code, raw output, structured JSON.
- `ai_analyses`: Scan ID, finding ID, specialist role, model name, analysis text, recommendations, confidence score.
- `reports`: Report ID, title, format, file path, target, summary, findings count.
- `audit_logs`: Timestamp, event type, user action, target, tool, mode, decision, details.

### 6.2 Data Models (`app/database/models.py`)
- Python `@dataclass`: `HostRecord`, `PortRecord`, `Finding`, `ScanRecord`.
- Missing in current dataclasses: `Asset` model, `Evidence` model, `ToolRun` model, `Policy` model, `AuditEvent` model, and detailed risk factors in `Finding`.

---

## 7. Security & Authorization Controls

1. **Authorization Engine (`app/security/authorization.py`)**:
   - Compares targets against `excluded_targets` in `config/targets.yaml` (e.g., `8.8.8.8`, `*.gov`, `*.mil`, `*.edu`).
   - Validates membership in approved scopes (`local-loopback`, `lab-network`, `test-domains`).
   - Interactive CLI prompt for unlisted targets.
2. **Policy Engine (`app/security/policies.py`)**:
   - Supports 5 operational modes: `PASSIVE`, `SAFE_SCAN`, `ACTIVE_SCAN`, `AUTHORIZED_PENTEST`, `LAB_MODE`.
   - Gatekeeper for port scanning, web fuzzing, SQLi probing, and controlled exploit validation.
3. **Input Sanitization (`app/security/sanitizer.py`)**:
   - Strict detection of dangerous shell metacharacters (`[;&|`$><!\\\'"\n\r]`).
   - RFC/IPv4/IPv6/CIDR parsing via standard library `ipaddress`.
   - Port validation via range checking (1-65535).
   - Filename sanitization against path traversal (`..`, `/`, `\`).
4. **Audit Logging (`app/core/logger.py`)**:
   - Formatted security audit event writer writing to `logs/security/audit.log`.

---

## 8. Test Suite Analysis

Current tests are located in `tests/`:
- `test_config.py`: Tests config loader, active mode toggling, sanitizer regex, and validation exceptions. (All PASS)
- `test_database.py`: Tests scope checks, policy restrictions, and SQLite CRUD operations. (All PASS)
- `test_reports.py`: Tests generation of JSON, TXT, HTML, and CSV reports. (All PASS)
- `test_scanners.py`: Tests native network scanner, traffic monitor snapshot, and DDoS detector. (All PASS)
- `test_tools.py`: Tests tool detection, subprocess safe execution, and Nmap/Nuclei output parsers. (All PASS)
- `test_ai_and_rag.py`: Tests RAG Jaccard retrieval, Ollama client status, and demo runner.
  - *Bug identified*: `test_system_prompts` fails on `assertIn("NEVER hallucinate", prompt)` because `app/ai/prompts.py` uses `"Never hallucinate"`. (20 PASS / 1 FAIL).

---

## 9. Technical Debt & Weaknesses Identified

1. **Committed Non-Portable Virtual Environment (`.venv/`)**:
   - 1,200+ files committed in `.git`.
   - Hardcoded broken interpreter path: `#!/Users/syudent_02/...`.
   - Must be removed from Git index and added to `.gitignore`.
2. **Committed Runtime State**:
   - `database/cyberwolf.db`, `cyberwolf.db-wal`, `cyberwolf.db-shm` committed.
   - `logs/cyberwolf.log`, `logs/security/audit.log` committed.
   - `reports/*.html`, `reports/*.csv`, `reports/*.json`, `reports/*.txt` committed.
3. **Lack of a Unified Service Layer**:
   - CLI command handlers directly instantiate scanners.
   - Scanners directly execute database writes.
   - No intermediary `ScanService`, `FindingService`, `AssetService`, or `TargetService`.
4. **No Finding Deduplication & Correlation**:
   - If Nmap detects port 80 Apache and Nikto also detects port 80 Apache, they are saved as independent, unlinked findings.
   - No correlation key (Host + Port + Service + CVE/CWE) or evidence merging.
5. **Static / Arbitrary Risk Scoring**:
   - Risk is currently tied solely to static tool severity strings (`CRITICAL`, `HIGH`, etc.).
   - No multi-factor formula evaluating severity weight, confidence weight, exposure, and asset criticality.
6. **No Evidence SHA-256 Hashing & Provenance**:
   - Tool outputs and raw responses are not cryptographically hashed.
   - Finding evidence is stored merely as plain text snippets without strict provenance links.
7. **Missing PDF Reporting**:
   - Reports support HTML, JSON, CSV, and TXT, but no standalone PDF export capability.
8. **Missing Target Management CLI**:
   - Targets can only be edited manually in YAML; missing commands like `cyberwolf target add` or `cyberwolf targets list`.
9. **Doctor Command Gaps**:
   - Missing verification of database integrity, knowledge database schema validation, and permissions.
10. **Lack of Web/API Layer & Dashboard**:
    - No REST API or operational web console for analyst workflows.

---

## 10. Target V2 Architecture & Phased Implementation Plan

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CYBERWOLF V2 ARCHITECTURE                       │
└────────────────────────────────────────────────────────────────────────┘
       ▲                                                 ▲
       │                                                 │
┌──────────────┐                                 ┌──────────────┐
│  CLI Engine  │                                 │ Web / REST   │
│ (Argparse &  │                                 │ API Service  │
│  Interactive)│                                 │ & Dashboard  │
└──────┬───────┘                                 └──────┬───────┘
       │                                                │
       └───────────────────────┬────────────────────────┘
                               ▼
     ┌───────────────────────────────────────────────────┐
     │                CORE SERVICE LAYER                 │
     │  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ │
     │  │ ScanService  │ │FindingService│ │AssetService│ │
     │  └──────┬───────┘ └──────┬───────┘ └─────┬──────┘ │
     │         │                │               │        │
     │  ┌──────▼───────┐ ┌──────▼───────┐ ┌─────▼──────┐ │
     │  │TargetService │ │PolicyEngine  │ │RiskEngine  │ │
     │  └──────────────┘ └──────────────┘ └────────────┘ │
     └─────────────────────────┬─────────────────────────┘
                               │
       ┌───────────────────────┼────────────────────────┐
       ▼                       ▼                        ▼
┌──────────────┐       ┌──────────────┐         ┌──────────────┐
│ Tool Engine  │       │ Intelligence │         │ Data & Audit │
│  & Adapters  │       │ (Correlation,│         │ Storage      │
│(Nmap,Nuclei, │       │  CVE/CWE/    │         │ (SQLite,     │
│ Nikto,ffuf,  │       │  OWASP, RAG) │         │  Evidence,   │
│ TShark,etc.) │       │              │         │  Migrations) │
└──────────────┘       └──────────────┘         └──────────────┘
```

### Migration Phasing:
- **Phase 1**: Audit (`ARCHITECTURE_AUDIT.md`) — [COMPLETED]
- **Phase 2**: Repository Cleanup (.gitignore, git rm `.venv`, runtime files, sample reports to `examples/reports/`)
- **Phase 3**: Canonical Domain Models (Asset, Scan, Finding, Evidence, ToolRun, Report, AuditEvent, Policy)
- **Phase 4**: Tool Engine & Adapter Hardening (BaseAdapter, Nmap, Nuclei, Nikto, ffuf, TShark; shell=False, timeouts, normalization)
- **Phase 5**: Security Layer (Scope validation, authorization checks, policy enforcement, command validation, audit trail)
- **Phase 6**: Detection Intelligence (Finding normalization, deduplication, deterministic correlation, explainable risk scoring)
- **Phase 7**: Knowledge Layer (CVE/CWE/OWASP offline lookup, remediation advisor, local intelligence)
- **Phase 8**: Evidence Engine (SHA-256 storage, file management, provenance tracking)
- **Phase 9**: Canonical Report Engine (JSON, CSV, professional SOC HTML, offline-capable PDF)
- **Phase 10**: CLI Evolution (`cyberwolf doctor`, `targets`, `scan`, `findings`, `assets`, `reports`, `database backup`)
- **Phase 11**: Decoupled Web/API & Analyst Dashboard (REST API + SOC workstation UI)
- **Phase 12**: Comprehensive Test Suite (unit, integration, security, parser fixtures)
- **Phase 13**: CI/CD Pipeline (GitHub Actions `.github/workflows/tests.yml`)
- **Phase 14**: Final Documentation & Release Verification (README, ARCHITECTURE, DEVELOPMENT, SECURITY, CONTRIBUTING, CHANGELOG)
