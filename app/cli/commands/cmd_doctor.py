"""CYBERWOLF Diagnostic Commands: doctor and status."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from app.tools.detector import get_tool_detector
from app.cli.formatter import display_doctor_table
from app.core.config import get_config
from app.core.platform_adapter import get_platform_adapter
from app.ai.ollama_client import get_ollama_client
from app.database.operations import get_database_status

console = Console()

def handle_doctor():
    """Execute full system and tool diagnostic."""
    console.print("\n[bold cyan]◈ RUNNING CYBERWOLF SYSTEM & SECURITY TOOL DOCTOR ◈[/bold cyan]\n")
    detector = get_tool_detector()
    report = detector.get_full_doctor_report()
    
    display_doctor_table(report["dependencies"], report["security_tools"])
    
    installed_tools = sum(1 for t in report["security_tools"].values() if t["installed"])
    total_tools = len(report["security_tools"])
    console.print(f"[bold white]Summary:[/bold white] {installed_tools}/{total_tools} security tools installed.")
    console.print("[dim]Note: CYBERWOLF includes built-in socket and HTTP assessment engines to operate autonomously even if some external tools are missing.[/dim]\n")

def handle_status():
    """Display comprehensive active operational status."""
    config = get_config()
    platform = get_platform_adapter()
    ollama = get_ollama_client()
    db_stats = get_database_status()

    console.print("\n[bold cyan]◈ CYBERWOLF COMMAND CENTER STATUS ◈[/bold cyan]\n")
    
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
        t.append(f"Ollama Offline (Start daemon with 'ollama serve')\n", style="bold yellow")

    t.append("• Database:     ", style="bold white")
    t.append(f"SQLite ({db_stats['db_path']}) - {db_stats['hosts']} Hosts, {db_stats['findings']} Findings, {db_stats['scans']} Scans\n", style="cyan")

    panel = Panel(t, title="[bold green]STATUS: READY[/bold green]", border_style="cyan")
    console.print(panel)
    console.print()
