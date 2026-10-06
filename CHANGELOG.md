# Changelog

All notable changes to the **CYBERWOLF** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-10-06

### Major Architectural Evolution: CYBERWOLF V2
Version 2.0.0 transforms CYBERWOLF from a collection of command-line security scripts into a unified, modular, locally controlled cybersecurity assessment and investigation platform.

### Added
- **Core Domain Models (`app/database/models.py`)**: Strongly typed canonical definitions for `Asset`, `Scan`, `Finding`, `Evidence`, `ToolRun`, `ReportRecord`, `AuditEvent`, and `Policy`.
- **Database Migration Framework (`app/database/migrations.py`)**: Idempotent schema migrations tracked in `schema_migrations`, supporting non-destructive upgrades with SQLite WAL mode and performance indexes.
- **Service Layer Abstraction (`app/services/`)**:
  - `ScanService`: Complete scan pipeline orchestration (`Target -> Scope -> Policy -> Tool -> Execution -> Detection -> Evidence -> Reports`).
  - `FindingService`: Canonical finding query, filtering, and triage status management.
  - `AssetService`: Discovered asset tracking, host deduplication, and open port aggregation.
  - `TargetService`: Authorized scope management and explicit target enrollment.
- **Hardened Tool Adapter Architecture (`app/tools/base_adapter.py`, `app/tools/runner.py`)**:
  - Standardized `BaseToolAdapter` interface (`is_available`, `validate_arguments`, `build_command`, `execute`, `parse_output`, `normalize_results`).
  - Strict subprocess sandboxing (`shell=False`, discrete argument lists, hard timeouts, process cleanup, 5MB output capture cap, and SHA-256 output digests).
  - Production-hardened adapters for Nmap, Nuclei, Nikto, ffuf, Gobuster, and TShark.
- **Detection & Correlation Engine (`app/detection/`)**:
  - `FindingNormalizer`: Converts raw scanner outputs into canonical `Finding` objects.
  - `FindingDeduplicator`: Merges duplicate findings using deterministic correlation keys while maintaining multi-tool source provenance.
  - `FindingCorrelator`: Correlates open ports, service banners, and vulnerability signatures deterministically.
  - `RiskEngine`: Transparent, formulaic risk scoring combining severity, tool confidence, asset criticality, and attack surface exposure.
- **Cryptographic Evidence Vault (`app/evidence/vault.py`)**:
  - Structured evidence storage in `database/evidence/<scan_id>/`.
  - SHA-256 content hashing, command recording, and timestamped chain of custody.
  - Evidence integrity verification method (`verify_evidence_integrity()`).
- **Authorization & Security Layer (`app/security/`)**:
  - `TargetSanitizer`: Strict RFC validation for IPv4, IPv6, CIDR blocks, hostnames, and URLs; rejection of shell metacharacters.
  - `TargetAuthorizer`: Scope validation against `config/targets.yaml`, explicit target enrollment, and interactive authorization workflows.
  - `PolicyEngine`: Central enforcement of safe modes, prohibited operations (no destructive exploits or brute force), and rate limits.
  - Structured Audit Logging (`app/core/logger.py`) with automated credential and token scrubbing.
- **Offline Intelligence & Knowledge Layer (`app/intelligence/`)**:
  - Offline CVE database (`knowledge/cve_database.json`) with CVSS scores and CPE mappings.
  - OWASP Top 10 playbooks (`knowledge/owasp_playbooks.json`).
  - `RemediationAdvisor`: Structured 6-point remediation plan (Summary, Impact, Mitigation, Remediation, Verification, References).
- **Multi-Format Report Generator (`app/reports/generator.py`)**:
  - Full-fidelity JSON, CSV, and plain-text summaries.
  - Professional, dark-mode SOC HTML deliverable with executive summaries and evidence drawers.
  - Multi-page printable PDF deliverable powered by ReportLab with automatic page numbers and metrics tables.
- **Unified CLI (`app/main.py`)**:
  - `cyberwolf doctor`: Full environment and dependency diagnostic.
  - `cyberwolf --version`: Semantic version reporting (`CyberWolf 2.0.0`).
  - `cyberwolf target [list|add]`: Scope and authorized target management.
  - `cyberwolf scan [<target>|list|show|cancel]`: Assessment session management.
  - `cyberwolf findings [list|show|explain]`: Vulnerability investigation.
  - `cyberwolf assets [list|show]`: Discovered host inventory.
  - `cyberwolf tools list`: Adapter discovery and availability tracking.
  - `cyberwolf policy show`: Active policy rule inspection.
  - `cyberwolf database backup`: Safe timestamped database backups.
  - `cyberwolf report [list|generate]`: Assessment deliverable generation.
  - `cyberwolf dashboard` / `serve`: Local web workstation and REST API launcher.
- **REST API & SOC Analyst Workstation (`app/web/server.py`)**:
  - Zero-dependency `ThreadingHTTPServer` serving `/api/health`, `/api/status`, `/api/scans`, `/api/findings`, `/api/assets`, `/api/targets`, `/api/tools`, and `/api/reports`.
  - Operational, density-optimized SOC Analyst Workstation web UI.
- **Testing & Quality Assurance (`tests/`)**:
  - Reorganized into `tests/unit/`, `tests/integration/`, `tests/security/`, and `tests/fixtures/`.
  - Comprehensive fixtures for Nmap XML, Nuclei JSONL, Nikto text, ffuf JSON, and TShark text.
  - 66 passing automated tests covering all modules without external tool dependencies.
- **CI/CD Automation (`.github/workflows/tests.yml`)**: Multi-version test matrix for Python 3.9, 3.10, and 3.11.

### Changed
- Converted all legacy subprocess calls to secure argument lists (`shell=False`).
- Removed over 1,200 committed runtime artifacts from Git tracking (`.venv/`, database files, WAL/SHM files, runtime logs, generated reports).
- Created clean `.gitignore` and template `.env.example`.
- Relocated legacy sample reports to `examples/reports/`.
- Updated all legacy CLI commands (`vuln`, `pentest`, `web`, `sql-test`, `monitor`, `ddos-monitor`, `demo`, `ai`) to maintain full backward compatibility with the new architecture.

### Fixed
- Arbitrary command injection risks in scanner execution routines.
- Unbounded stdout stream memory consumption in long-running tool runs.
- Concurrency locking in SQLite through Write-Ahead Logging (WAL) activation.
- Cross-Site Scripting (XSS) risks in HTML report generation by enforcing HTML escaping across all dynamic inputs.
- ReportLab XML flowable parser crashes on unescaped bracket characters in evidence payloads.

---

## [1.0.0] - Legacy Initial Release
- Initial prototype script collection for autonomous security probing, local LLM integration via Ollama, and basic scanning scripts.
