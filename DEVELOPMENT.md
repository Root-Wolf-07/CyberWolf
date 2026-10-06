# CYBERWOLF V2 — Developer & Contributor Guide

Welcome to the development documentation for **CYBERWOLF V2**. This guide explains how to set up your local development environment, run automated tests, create new security tool adapters, add database migrations, and adhere to engineering standards.

---

## 1. Local Development Setup

### 1.1 Prerequisites
- Python 3.9, 3.10, or 3.11
- Git
- Standard build tools

### 1.2 Virtual Environment & Dependencies
```bash
# Clone the repository
git clone https://github.com/Root-Wolf-07/CyberWolf.git
cd CyberWolf

# Create virtual environment
python3 -m venv .venv

# Activate environment
source .venv/bin/activate  # macOS / Linux
# .\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Upgrade pip and install development dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Create local environment config
cp .env.example .env
```

### 1.3 Verify Installation
Verify the development environment using the internal diagnostic:
```bash
python -m app.main doctor
```

---

## 2. Project Directory Structure

```text
CyberWolf/
├── app/
│   ├── main.py                     # CLI entrypoint and command router
│   ├── cli/                        # Terminal subcommands (scan, report, target, etc.)
│   ├── core/                       # Config manager, logger, audit logging, exceptions
│   ├── database/                   # SQLite engine, models, migrations, operations
│   ├── detection/                  # Normalizer, deduplicator, correlator, risk engine
│   ├── evidence/                   # EvidenceVault (SHA-256 hashing, provenance)
│   ├── intelligence/               # CVE database, OWASP playbooks, RemediationAdvisor
│   ├── reports/                    # Multi-format report generator (HTML, PDF, JSON, CSV)
│   ├── security/                   # Target sanitizer, authorization engine, policy engine
│   ├── services/                   # Service layer (ScanService, FindingService, etc.)
│   ├── tools/                      # Base adapter, runner, and scanner adapters
│   └── web/                        # ThreadingHTTPServer, REST API, SOC Workstation
├── config/                         # Configuration YAML files (config, targets, policies)
├── database/                       # SQLite database files and evidence repository
├── knowledge/                      # Offline CVE and OWASP datasets
├── logs/                           # System and security audit logs
├── reports/                        # Default export directory for reports
└── tests/                          # Automated test suites
    ├── unit/                       # Unit tests (isolated, fast, mocked tools)
    ├── integration/                # Service layer and REST API tests
    ├── security/                   # Input validation, command injection, path traversal tests
    └── fixtures/                   # Realistic scanner output samples (XML, JSONL, TXT)
```

---

## 3. Running Automated Tests

CYBERWOLF enforces high test coverage. All tests run offline and mock external security scanners, meaning tests can run without Nmap, Nuclei, or Wireshark installed.

```bash
# Run all tests
pytest tests

# Run specific test suites
pytest tests/unit/
pytest tests/security/
pytest tests/integration/

# Run with short tracebacks
pytest -q --tb=short

# Run specific test file
pytest tests/unit/test_risk_engine.py -v
```

### Testing Guidelines
1. **Never require external binaries**: Unit and integration tests must never fail because a system binary (`nmap`, `nuclei`) is absent. Use mocking (`unittest.mock.patch` or adapter mock fixtures).
2. **Use Realistic Fixtures**: Place scanner output samples in `tests/fixtures/` and test parsers against realistic tool outputs.
3. **Idempotent Tests**: Tests modifying temporary target configurations or database records must clean up afterwards.

---

## 4. Creating a New Tool Adapter

All security tool integrations inherit from `BaseToolAdapter` in `app/tools/base_adapter.py`.

### Step 1: Subclass `BaseToolAdapter`
Create a new file in `app/tools/adapters/mytool_adapter.py`:

```python
"""Adapter for MyTool security scanner."""

import shutil
from typing import Dict, Any, List
from app.tools.base_adapter import BaseToolAdapter
from app.database.models import Finding
from app.core.logger import get_logger

logger = get_logger()

class MyToolAdapter(BaseToolAdapter):
    """Integrates MyTool into CYBERWOLF orchestration."""

    def __init__(self):
        super().__init__(name="mytool", description="MyTool vulnerability scanner")

    def is_available(self) -> bool:
        """Check if binary exists in PATH."""
        return shutil.which("mytool") is not None

    def validate_arguments(self, target: str, options: Dict[str, Any]) -> bool:
        """Validate target and options before building command."""
        if not target or not isinstance(target, str):
            return False
        return True

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Construct command argument vector. NEVER use shell=True or string joins."""
        cmd = ["mytool", "-u", target, "--format", "json"]
        if options.get("timeout"):
            cmd.extend(["--timeout", str(options["timeout"])])
        return cmd

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse raw stdout/file output into structured dictionary records."""
        parsed_items = []
        # Parse JSON/text and populate parsed_items
        return parsed_items

    def normalize_results(self, parsed_results: List[Dict[str, Any]], target: str) -> List[Finding]:
        """Convert parsed items into canonical CYBERWOLF Finding instances."""
        from app.detection.normalizer import FindingNormalizer
        normalizer = FindingNormalizer()
        findings = []
        for item in parsed_results:
            findings.append(normalizer.normalize_mytool_record(item, target))
        return findings
```

### Step 2: Register Adapter
Register the new adapter in `app/tools/runner.py` within `get_supported_adapters()`.

### Step 3: Add Unit Tests & Fixtures
1. Add a sample tool output fixture in `tests/fixtures/sample_mytool.json`.
2. Add parser and command construction tests in `tests/unit/test_tool_adapters.py`.

---

## 5. Subprocess Execution Security Rules

When modifying or adding tool adapters, strictly observe these rules:
1. **Never use `shell=True`**: Always supply command vectors as `List[str]`.
2. **Never format raw shell strings**: Avoid `f"nmap {target}"` passed to shell environments.
3. **Always specify timeouts**: Provide an explicit execution timeout (default 300s).
4. **Cap output capture**: Do not read unbounded streams; use `max_output_bytes` (5MB cap).
5. **Compute SHA-256 digests**: Capture hashes of raw stdout for evidentiary integrity.

---

## 6. Database Migrations

Schema modifications must be applied via `app/database/migrations.py`:
1. Increment the version number (e.g. `v4_new_feature`).
2. Add an idempotent migration function checking table/column presence before executing `ALTER TABLE` or `CREATE TABLE`.
3. Register the migration in `MIGRATIONS_REGISTRY`.
4. Verify migration idempotency using `pytest tests/unit/test_migrations.py`.

---

## 7. Audit Logging & Secret Scrubbing

Whenever modifying security-sensitive areas (authorization, scope validation, scan dispatches):
```python
from app.core.logger import audit_log

audit_log(
    event_type="SCAN_DISPATCH",
    action="EXECUTE",
    target="192.168.1.50",
    tool="nmap",
    decision="APPROVED",
    details="Executed authorized Nmap scan"
)
```
The audit logging engine automatically redacts credentials, passwords, Bearer tokens, and sensitive query parameters before writing to disk.

---

## 8. Code Style & Quality Standards

- **Formatting & Linting**: Adhere to PEP 8 standards. Run `ruff check .` or `flake8`.
- **Type Annotations**: Provide explicit type hints on all public functions and methods.
- **Exceptions**: Raise structured exceptions from `app.core.exceptions` (`TargetValidationError`, `AuthorizationError`, `PolicyViolationError`, `ToolExecutionError`).
- **No Mock/Fake Scan Data**: In production scanning modes, always surface real tool telemetry. If demo data is required, it must reside in `app/demo/` and be explicitly flagged as `DEMO MODE`.
