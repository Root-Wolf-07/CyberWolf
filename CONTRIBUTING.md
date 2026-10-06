# Contributing to CYBERWOLF

Thank you for your interest in contributing to **CYBERWOLF V2**! We welcome contributions that improve tool adapters, enhance detection normalization, strengthen security controls, and refine reporting capabilities.

---

## 1. Ethical & Legal Standards

All contributors must adhere to ethical cybersecurity practices:
- **Defensive Focus**: CYBERWOLF is built exclusively for authorized security assessment, lab testing, and defense.
- **No Malicious Features**: Pull requests introducing exploits, persistence mechanisms, credential harvesting, or bypasses intended for unauthorized intrusion will be immediately rejected and closed.
- **Authorization Enforcement**: New tool integrations must respect the central scope authorizer and policy engine.

---

## 2. Getting Started

1. **Fork the Repository**: Create a fork of `Root-Wolf-07/CyberWolf` on GitHub.
2. **Clone Locally**:
   ```bash
   git clone https://github.com/<your-username>/CyberWolf.git
   cd CyberWolf
   ```
3. **Set Up Development Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```
4. **Verify Environment**:
   ```bash
   python -m app.main doctor
   pytest tests
   ```

---

## 3. Development Workflow

### 3.1 Branching Convention
Create a descriptive branch for your work:
- `feature/add-amass-adapter`
- `fix/nmap-xml-service-parsing`
- `docs/update-architecture`

### 3.2 Coding Guidelines
- **Python 3.9+ Compatibility**: Code must run cleanly on Python 3.9 through 3.11. Avoid syntax unsupported in Python 3.9 (e.g. backslashes inside f-string expressions).
- **Type Annotations**: Annotate function parameters and return types using `typing`.
- **Subprocess Safety**: Always pass argument vectors as `List[str]` with `shell=False`. Hardcode timeout parameters.
- **Audit Logging**: Call `audit_log()` when performing security-critical operations.
- **Zero Secrets**: Never commit API keys, passwords, or test credentials. Use `.env`.

### 3.3 Testing Requirements
Every pull request must include tests:
- Place unit tests in `tests/unit/` using mocked tool runners.
- Place sample tool outputs in `tests/fixtures/`.
- Ensure all tests pass locally:
  ```bash
  pytest tests
  ```

---

## 4. Pull Request Checklist

Before submitting your PR, verify:
- [ ] All automated tests pass (`pytest tests`).
- [ ] `python -m app.main doctor` runs with exit code 0.
- [ ] No generated files (`.venv/`, `*.db`, `logs/*`, `reports/*`) are committed.
- [ ] New tool adapters inherit from `BaseToolAdapter` and implement `is_available()`, `validate_arguments()`, `build_command()`, `parse_output()`, and `normalize_results()`.
- [ ] New database columns or tables are accompanied by an idempotent migration in `app/database/migrations.py`.
- [ ] Code is formatted cleanly and adheres to PEP 8 standards.
- [ ] Documentation and docstrings are provided for new features.

Thank you for helping keep the security community safe and resilient!
