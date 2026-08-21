"""CYBERWOLF Security Test Lab Command (cyberwolf lab)."""

from rich.console import Console
from rich.table import Table
from app.core.config import get_config
from app.scanners.network_scanner import NetworkScanner
from app.cli.formatter import display_findings_table

console = Console()

def handle_lab(action: str = "status"):
    """Manage and assess local security test labs / CTF targets."""
    config = get_config()
    scopes = config.targets_data.get("scopes", [])
    lab_scopes = [s for s in scopes if "lab" in s.get("id", "").lower() or "local" in s.get("id", "").lower()]

    if action == "status":
        console.print("\n[bold cyan]◈ LOCAL SECURITY LAB CONFIGURATION & TARGETS ◈[/bold cyan]\n")
        table = Table(title="◈ REGISTERED LAB SCOPES ◈", border_style="cyan")
        table.add_column("Scope ID", style="bold cyan")
        table.add_column("Name", style="white")
        table.add_column("Target Ranges", style="green")
        table.add_column("Risk Level", style="yellow")

        for s in lab_scopes:
            targets_str = ", ".join(s.get("targets", []))
            table.add_row(s.get("id"), s.get("name"), targets_str, s.get("risk_level", "low").upper())

        console.print(table)
        console.print("\n[dim]To execute a lab scan, run: cyberwolf lab scan --target 127.0.0.1[/dim]\n")

    elif action == "scan":
        console.print("\n[bold cyan]◈ EXECUTING DEDICATED LAB SECURITY SCAN ◈[/bold cyan]\n")
        scanner = NetworkScanner()
        results = scanner.scan("127.0.0.1", port_spec="80,443,8000,8080,3000,5000,8888")
        display_findings_table(results.get("findings", []), title="LOCAL LAB SCAN FINDINGS")
