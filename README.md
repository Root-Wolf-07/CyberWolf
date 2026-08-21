# CYBERWOLF — Local AI Cybersecurity Security Command Center

```text
================================================================================

                           C Y B E R W O L F

           HUNT THREATS  •  FIND WEAKNESSES  •  DEFEND EVERYTHING

                        [ WOLF SECURITY ENGINE ]

================================================================================
```

**CYBERWOLF** is an autonomous, local-first AI cybersecurity assistant and security assessment platform designed for authorized security researchers, SOC analysts, and lab administrators. It integrates local LLM intelligence (via Ollama/Gemma) with structured security tool adapters, deterministic evidence collection, local SQLite persistence, lightweight RAG retrieval, and strict safety controls.

---

## 🐺 Key Capabilities

- **Local-First & Private**: Keeps all scan telemetry, findings, database records, and AI prompts on the user's host machine.
- **Strict Authorization Engine**: Enforces target scope validation (`config/targets.yaml`, `config/authorization.yaml`) and safe execution modes (`PASSIVE`, `SAFE_SCAN`, `ACTIVE_SCAN`, `AUTHORIZED_PENTEST`, `LAB_MODE`).
- **Grounded AI Intelligence**: Connects to local Ollama models (`gemma4:26b`, `gemma`, `llama3.2`, `qwen2.5`) with zero-hallucination guardrails and specialized security analyst personas.
- **15+ Security Tool Adapters**: Automatically detects and interfaces with Nmap, Wireshark/tshark, Burp Suite, Metasploit, Gobuster, ffuf, Nikto, John the Ripper, Hashcat, Hydra, Aircrack-ng, Kismet, BloodHound, Impacket, and Nuclei.
- **Autonomous Fallback Probes**: Includes native socket scanners, HTTP security inspectors, non-destructive SQL injection heuristic testers, and traffic monitors that function out-of-the-box even before third-party tools are installed.
- **Multi-Format Security Reports**: Generates dark SOC HTML reports, JSON data exports, plain text summaries, and CSV spreadsheets with executive summaries and remediation guidance.
- **Safe Demo Mode (`cyberwolf demo`)**: Full simulated assessment suite showcasing end-to-end security workflows safely.

---

## 📁 Repository Structure

```
cyberwolf/
├── app/
│   ├── main.py                     # CLI Entrypoint & Argument Parser
│   ├── cli/                        # Terminal REPL, Banner, & Subcommands
│   ├── core/                       # Config, OS Platform Adapter, Logger, Exceptions
│   ├── security/                   # Authorization Engine, Policies, Input Sanitizer
│   ├── database/                   # SQLite Manager, Schema, Models, CRUD
│   ├── ai/                         # Ollama Client, Prompts, RAG, AI Orchestrator
│   ├── tools/                      # Tool Detector & Adapters (Nmap, Nuclei, Nikto, etc.)
│   ├── scanners/                   # Network, Vuln, Web, SQLi, Bug Scanners
│   ├── monitors/                   # Traffic & DDoS Anomaly Radar
│   ├── pentest/                    # Human-in-the-Loop Pentest Workflow
│   ├── reports/                    # Multi-Format Report Generator (HTML/JSON/TXT/CSV)
│   └── demo/                       # Safe Demonstration Engine
├── bin/
│   └── cyberwolf                   # Executable Launcher
├── config/
│   ├── config.yaml                 # Core Settings
│   ├── targets.yaml                # Authorized Target Scopes
│   ├── authorization.yaml          # Signed Authorizations
│   └── policies.yaml               # Safety Policy Rules
├── database/
│   ├── cyberwolf.db                # Local SQLite Database
│   └── schema.sql                  # Database Schema
├── knowledge/
│   ├── cve_database.json           # Curated CVE / CWE Knowledge Base
│   └── owasp_playbooks.json        # OWASP Top 10 Remediation Playbooks
├── reports/                        # Exported Assessment Reports
├── logs/                           # Operational & Security Audit Logs
├── tests/                          # Automated Unit & Integration Tests
└── pyproject.toml
```

---

## 🚀 Installation & Setup (Cross-Platform)

### 📦 Platform Quick Comparison

| Step | 🍎 macOS | 🐧 Linux (Debian / Ubuntu / Kali) | 🪟 Windows (PowerShell) |
|---|---|---|---|
| **1. Prerequisites** | `brew install python git ollama` | `sudo apt update && sudo apt install python3 python3-venv git -y` | `winget install Python.Python.3.11 Git.Git Ollama.Ollama` |
| **2. Clone & Enter** | `cd cyberwolf` | `cd cyberwolf` | `cd cyberwolf` |
| **3. Virtual Env** | `python3 -m venv .venv && source .venv/bin/activate` | `python3 -m venv .venv && source .venv/bin/activate` | `python -m venv .venv; .\.venv\Scripts\Activate.ps1` |
| **4. Install Dependencies**| `pip install -r requirements.txt` | `pip install -r requirements.txt` | `pip install -r requirements.txt` |
| **5. Core Security Tools** | `brew install nmap tshark nuclei nikto ffuf gobuster` | `sudo apt install nmap tshark nikto ffuf gobuster nuclei -y` | `winget install Insecure.Nmap WiresharkFoundation.Wireshark` |
| **6. Run CYBERWOLF** | `./bin/cyberwolf` | `./bin/cyberwolf` | `python app\main.py` |

---

### 🍎 1. macOS Installation (Homebrew)

```bash
# 1. Install prerequisites via Homebrew
brew install python git ollama
brew install nmap tshark nuclei nikto ffuf gobuster

# 2. Setup CYBERWOLF virtual environment
cd /Users/syudent_02/.gemini/antigravity-ide/scratch/cyberwolf
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Pull local AI model in Ollama
ollama pull qwen2.5-coder:1.5b    # Fast default model
ollama pull llama3.2:1b            # Alternative lightweight model
ollama pull gemma4:26b             # High-capacity model (optional)

# 5. Run diagnostics and start CYBERWOLF
./bin/cyberwolf doctor
./bin/cyberwolf
```

---

### 🐧 2. Linux Installation (Debian / Ubuntu / Kali Linux)

```bash
# 1. Update package lists and install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git curl
sudo apt-get install -y nmap tshark nikto ffuf gobuster hydra john

# For Kali Linux, most security tools are pre-installed:
# sudo apt-get install -y nuclei metasploit-framework python3-impacket

# 2. Setup Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull qwen2.5-coder:1.5b

# 3. Setup CYBERWOLF virtual environment
cd cyberwolf
python3 -m venv .venv
source .venv/bin/activate

# 4. Install Python dependencies & run
pip install -r requirements.txt
chmod +x bin/cyberwolf
./bin/cyberwolf doctor
./bin/cyberwolf
```

---

### 🪟 3. Windows Installation (PowerShell / Windows Terminal)

```powershell
# 1. Install Python, Git, and Ollama using winget (Run PowerShell as Administrator)
winget install Python.Python.3.11
winget install Git.Git
winget install Ollama.Ollama
winget install Insecure.Nmap
winget install WiresharkFoundation.Wireshark

# 2. Setup CYBERWOLF virtual environment
cd cyberwolf
python -m venv .venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv\Scripts\Activate.ps1

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Pull local AI model in Ollama
ollama pull qwen2.5-coder:1.5b

# 5. Run diagnostics and launch CYBERWOLF
python app\main.py doctor
python app\main.py
```

---

## 🛠️ CLI Subcommand Reference

| Command | Description | Example |
|---|---|---|
| `cyberwolf doctor` | Run system and security tool diagnostics | `./bin/cyberwolf doctor` |
| `cyberwolf status` | Display operational status and metrics | `./bin/cyberwolf status` |
| `cyberwolf demo` | Execute simulated assessment showcase | `./bin/cyberwolf demo` |
| `cyberwolf scan network` | Scan authorized network host / ports | `./bin/cyberwolf scan network --target 127.0.0.1 -p 80,443,8080` |
| `cyberwolf vuln` | Vulnerability assessment | `./bin/cyberwolf vuln --target 127.0.0.1` |
| `cyberwolf pentest` | Controlled pentest validation workflow | `./bin/cyberwolf pentest --target 192.168.1.50` |
| `cyberwolf web` | Web application posture & headers | `./bin/cyberwolf web --target https://example.local` |
| `cyberwolf sql-test` | Safe non-destructive SQLi testing | `./bin/cyberwolf sql-test --target "http://testphp.vulnweb.com/list.php?id=1"` |
| `cyberwolf monitor` | Live network traffic packet capture | `./bin/cyberwolf monitor -d 5` |
| `cyberwolf ddos-monitor`| Defensive traffic anomaly / DoS radar | `./bin/cyberwolf ddos-monitor -d 5` |
| `cyberwolf reports` | List or generate security reports | `./bin/cyberwolf reports generate --target 127.0.0.1` |
| `cyberwolf ai` | Query local AI security analyst | `./bin/cyberwolf ai "How do I secure an Apache Tomcat server?"` |
| `cyberwolf database` | Database status, backup, export, search | `./bin/cyberwolf database status` |
| `cyberwolf config` | View settings or change safety mode | `./bin/cyberwolf config set-mode ACTIVE_SCAN` |

---

## 🔒 Authorization & Safety Policies

CYBERWOLF enforces strict authorization rules:
1. **Target Allowlisting**: Scans only execute against targets configured in `config/targets.yaml` or interactively confirmed with legal authorization.
2. **Safe Modes**:
   - `PASSIVE`: Zero active probing; observation and headers only.
   - `SAFE_SCAN` *(Default)*: Standard port discovery, service detection, non-destructive vulnerability checks.
   - `ACTIVE_SCAN`: Deep enumeration and directory discovery.
   - `AUTHORIZED_PENTEST`: Controlled penetration testing with mandatory confirmation before exploit validation.
   - `LAB_MODE`: Dedicated security lab & CTF testing.
3. **No Destructive Exploits**: Destructive attacks, data modification, and DoS floods are permanently barred.
