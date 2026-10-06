# CYBERWOLF V2 — Security Policy & Controls

## 1. Intended Purpose & Operational Boundaries

**CYBERWOLF V2** is engineered as a defensive, auditable, and locally controlled cybersecurity assessment platform. Its primary purpose is to assist security analysts, network administrators, and students in testing and hardening systems they own or are explicitly authorized to test.

### 1.1 Permitted Use Cases
- Owned local devices, home labs, and internal infrastructure.
- Formal penetration testing assessments conducted under an active, legally binding Rules of Engagement (RoE).
- Capture The Flag (CTF) challenges and designated training cyber ranges.
- Academic, educational, and defense-oriented security research.

### 1.2 Strictly Prohibited Functionality
The following behaviors are intentionally prohibited and permanently excluded from CYBERWOLF:
- Automated unauthorized access or exploitation against systems without explicit scope consent.
- Credential harvesting, unauthorized keylogging, or credential stuffing attacks.
- Malware creation, dropper generation, or rootkit installation.
- Anti-forensic capabilities, evasion techniques, or unauthenticated audit log destruction.
- Denial of Service (DoS) attacks, flood packets, or resource exhaustion exploits.

---

## 2. Defensive Engineering Controls

CYBERWOLF treats its own code and execution environment as security-sensitive software. The following technical controls are enforced throughout the codebase:

### 2.1 Subprocess Sandboxing & Command Construction
- **Zero Shell Interpolation**: All tool invocations use `subprocess.run(command_list, shell=False)`. Constructing commands from concatenated shell strings is forbidden.
- **Strict Argument Vectors**: User input (such as target hostnames or IP addresses) is passed as discrete list elements without shell expansion.
- **Execution Deadlines**: Every subprocess is bound to a hard timeout (default: 300 seconds). On expiry, CYBERWOLF terminates the process tree using `SIGKILL` to prevent orphan scanner processes.
- **Output Capping**: Subprocess stdout and stderr captures are capped at 5MB to avoid memory exhaustion or denial-of-service via unbounded scanner outputs.

### 2.2 Target Validation & RFC Compliance
- Every target string passes through `app/security/sanitizer.py`.
- Evaluated against Python `ipaddress` standards for IPv4 and IPv6 networks.
- Domain names and URLs are checked for RFC compliance.
- Unsafe characters (`;&|`$`><\n\r`) are permanently rejected, raising `TargetValidationError`.

### 2.3 Authorization & Scope Enforcement
- Targets must belong to configured scopes in `config/targets.yaml` or be explicitly enrolled via `cyberwolf target add <target> --authorized`.
- Unenrolled targets are blocked before any tool is dispatched.
- All scope evaluation decisions (approved or rejected) are logged with full provenance.

### 2.4 Central Policy Engine
- Configured safety policies (`config/policies.yaml`) enforce rate limits, permitted tool types, and operational restrictions.
- Destructive tests (`allow_destructive=False`) and brute-force modules (`allow_bruteforce=False`) are disabled by default.

### 2.5 Secret Hygiene & Audit Logging
- Zero hardcoded credentials or API tokens are allowed in the repository.
- Sensitive environment variables are managed via `.env` (template in `.env.example`).
- The audit logging engine (`app/core/logger.py`) automatically redacts passwords, tokens, API keys, and authorization headers before committing entries to disk.

### 2.6 SQL Injection & Data Integrity
- All database operations in `app/database/operations.py` utilize parameterized queries (`?` placeholders in SQLite).
- Raw SQL query string concatenation with user-supplied values is strictly disallowed.

### 2.7 XSS & Report Neutralization
- All dynamic fields (target names, raw tool outputs, headers, and evidence excerpts) inserted into HTML deliverables and the SOC Workstation dashboard pass through `html.escape()`.
- HTML reports enforce a strict dark SOC styling without external untrusted scripts.

---

## 3. Reporting a Vulnerability

If you discover a security flaw or vulnerability within CYBERWOLF:

1. **Do Not File Public GitHub Issues**: Please do not open a public issue for zero-day vulnerabilities or security bypasses.
2. **Contact the Maintainers**: Email security concerns to the designated repository maintainer or open a private GitHub Security Advisory.
3. **Provide Detailed Reproduction Steps**: Include target environment, proof-of-concept steps, and affected version.
4. **Resolution SLA**: The maintainers strive to acknowledge security reports within 48 hours and provide a fix or mitigation within 14 days.
