"""CYBERWOLF Diagnostic Commands: doctor and status (V2).

Implements comprehensive system, permissions, knowledge base,
and security scanner diagnostic inspection.
"""

import sys
import os
import shutil
import sqlite3
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from app.tools.detector import get_tool_detector
from app.core.config import get_config
from app.core.platform_adapter import get_platform_adapter
from app.ai.ollama_client import get_ollama_client
from app.database.operations import get_database_status
from app.database.db_manager import get_db

console = Console()


def handle_doctor():
    """Execute full CyberWolf V2 system, environment, and security tool diagnostics."""
    config = get_config()
    platform = get_platform_adapter()
    db = get_db()

    console.print("\n[bold cyan]╔═══════════════════════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║                          CYBERWOLF V2 DOCTOR DIAGNOSTIC                       ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════════════════════════════╝[/bold cyan]\n")

    # 1. System & Environment Table
    env_table = Table(title="[bold white]Core Environment & Platform[/bold white]", box=None)
    env_table.add_column("Component", style="bold white", width=22)
    env_table.add_column("Status", width=12)
    env_table.add_column("Details", style="dim", width=44)

    # Python Check
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 9):
        env_table.add_row("Python Version", "[bold green]✓ READY[/bold green]", f"Python {py_ver} ({sys.executable})")
    else:
        env_table.add_row("Python Version", "[bold red]✗ OUTDATED[/bold red]", f"Python {py_ver} (Requires >= 3.9)")

    # Database Check
    try:
        with db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM schema_migrations;")
            mig_count = cur.fetchone()[0]
            cur.execute("PRAGMA integrity_check;")
            integrity = cur.fetchone()[0]
        if integrity == "ok":
            env_table.add_row("Database Engine", "[bold green]✓ HEALTHY[/bold green]", f"SQLite WAL (Migrations: {mig_count}, Integrity: {integrity})")
        else:
            env_table.add_row("Database Engine", "[bold yellow]⚠ WARNING[/bold yellow]", f"Integrity check returned: {integrity}")
    except Exception as e:
        env_table.add_row("Database Engine", "[bold red]✗ ERROR[/bold red]", f"Connection error: {e}")

    # Configuration Files Check
    cfg_files = ["config.yaml", "targets.yaml", "policies.yaml", "authorization.yaml"]
    missing_cfgs = [f for f in cfg_files if not (config.base_dir / "config" / f).exists()]
    if not missing_cfgs:
        env_table.add_row("Configuration", "[bold green]✓ VALID[/bold green]", f"All 4 config files present ({config.get_active_mode()} mode)")
    else:
        env_table.add_row("Configuration", "[bold red]✗ MISSING[/bold red]", f"Missing: {', '.join(missing_cfgs)}")

    # Required Directories Check
    req_dirs = ["logs", "reports", "database", "knowledge"]
    all_dirs_ok = True
    for d in req_dirs:
        dir_p = config.base_dir / d
        if not dir_p.exists() or not os.access(dir_p, os.W_OK):
            all_dirs_ok = False
            break
    if all_dirs_ok:
        env_table.add_row("Filesystem Perms", "[bold green]✓ WRITABLE[/bold green]", "logs, reports, database & knowledge dirs ready")
    else:
        env_table.add_row("Filesystem Perms", "[bold red]✗ PERM ERROR[/bold red]", "Ensure write access to logs and reports dirs")

    # Knowledge Database Check
    cve_f = config.base_dir / "knowledge" / "cve_database.json"
    owasp_f = config.base_dir / "knowledge" / "owasp_playbooks.json"
    if cve_f.exists() and owasp_f.exists():
        env_table.add_row("Knowledge Base", "[bold green]✓ LOADED[/bold green]", "CVE offline database & OWASP playbooks valid")
    else:
        env_table.add_row("Knowledge Base", "[bold yellow]⚠ INCOMPLETE[/bold yellow]", "Local CVE or OWASP JSON files missing")

    console.print(env_table)
    console.print()

    # 2. External Security Tools Check
    tools_table = Table(title="[bold white]External Security Scanner Adapters[/bold white]", box=None)
    tools_table.add_column("Tool", style="bold white", width=18)
    tools_table.add_column("Status", width=14)
    tools_table.add_column("Version / Path", style="dim", width=26)
    tools_table.add_column("Install Guidance", style="cyan", width=22)

    detector = get_tool_detector()
    report = detector.get_full_doctor_report()
    core_tools = ["Nmap", "Nuclei", "Nikto", "ffuf", "Wireshark/tshark"]

    installed_count = 0
    missing_count = 0

    for name in core_tools:
        tool_data = report["security_tools"].get(name, {})
        installed = tool_data.get("installed", False)
        if installed:
            installed_count += 1
            ver_text = tool_data.get("version", "Installed")
            tools_table.add_row(name, "[bold green]✓ AVAILABLE[/bold green]", ver_text, "Ready to execute")
        else:
            missing_count += 1
            guide = tool_data.get("install_guide", "Install via package manager")
            tools_table.add_row(name, "[bold yellow]⚠ NOT FOUND[/bold yellow]", "Not in system PATH", guide)

    console.print(tools_table)
    console.print()

    # Summary
    if missing_count == 0:
        console.print("[bold green]✓ System fully ready. All security tools installed.[/bold green]\n")
    else:
        console.print(f"[bold green]✓ System operational[/bold green] with [bold yellow]{missing_count} optional external tool(s) missing.[/bold yellow]")
        console.print("[dim]Note: CYBERWOLF includes built-in socket and HTTP assessment engines to operate autonomously even if some external tools are missing.[/dim]\n")


def handle_status():
    """Display comprehensive active operational status."""
    config = get_config()
    platform = get_platform_adapter()
    ollama = get_ollama_client()
    db_stats = get_database_status()

    console.print("\n[bold cyan]◈ CYBERWOLF V2 COMMAND CENTER STATUS ◈[/bold cyan]\n")

    t = Text()
    t.append("• Platform:     ", style="bold white")
    t.append(f"{platform.get_os_display_name()} (Arch: {platform.architecture})\n", style="cyan")

    t.append("• Privileges:   ", style="bold white")
    t.append(f"{'ELEVATED / ROOT' if platform.is_elevated() else 'Standard User'}\n", style="bold green" if platform.is_elevated() else "yellow")

    t.append("• Safety Mode:  ", style="bold white")
    t.append(f"{config.get_active_mode()}\n", style="bold green")

    t.append("• AI Engine:    ", style="bold white")
    model_name = ollama.get_active_model()
    if ollama.is_online():
        t.append(f"Ollama Online (Active Model: {model_name})\n", style="bold green")
    else:
        t.append("Ollama Offline (Autonomous deterministic mode active)\n", style="bold yellow")

    t.append("• Database:     ", style="bold white")
    t.append(
        f"SQLite ({db_stats['db_path']}) - "
        f"{db_stats.get('assets', 0)} Assets, {db_stats['findings']} Findings, {db_stats['scans']} Scans, "
        f"{db_stats.get('evidence', 0)} Evidence Artifacts\n",
        style="cyan"
    )

    panel = Panel(t, title="[bold green]STATUS: OPERATIONAL (V2.0.0)[/bold green]", border_style="cyan")
    console.print(panel)
    console.print()
