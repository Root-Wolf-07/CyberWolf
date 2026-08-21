"""CYBERWOLF Terminal Output Formatter & Component Library."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import List, Dict, Any, Optional

console = Console()

def get_severity_style(severity: str) -> str:
    sev = str(severity).upper()
    return {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold cyan",
        "INFO": "dim white"
    }.get(sev, "white")

def display_findings_table(findings: List[Dict[str, Any]], title: str = "SECURITY FINDINGS"):
    """Render structured findings in a stylized rich table."""
    if not findings:
        console.print("[green]✔ No security vulnerabilities found.[/green]\n")
        return

    table = Table(title=f"◈ {title} ({len(findings)} Findings) ◈", border_style="cyan", header_style="bold cyan")
    table.add_column("Severity", justify="center", style="bold", width=12)
    table.add_column("Vulnerability", style="white", min_width=25)
    table.add_column("Target / Port", style="dim", width=22)
    table.add_column("Tool", style="magenta", width=14)
    table.add_column("Evidence", style="cyan", min_width=30)

    for f in findings:
        sev = f.get("severity", "INFO").upper()
        style = get_severity_style(sev)
        target_info = f"{f.get('target', '')}"
        if f.get("port"):
            target_info += f":{f.get('port')}"
        
        evidence = f.get("evidence", "")
        if len(evidence) > 60:
            evidence = evidence[:57] + "..."

        table.add_row(
            Text(sev, style=style),
            f.get("vulnerability", "Security Finding"),
            target_info,
            f.get("source_tool", "CYBERWOLF"),
            evidence
        )

    console.print(table)
    console.print()

def display_doctor_table(system_deps: Dict[str, Any], security_tools: Dict[str, Any]):
    """Render doctor diagnostic status."""
    table1 = Table(title="◈ SYSTEM RUNTIME DEPENDENCIES ◈", border_style="blue", header_style="bold blue")
    table1.add_column("Dependency", style="bold white", width=15)
    table1.add_column("Status", justify="center", width=12)
    table1.add_column("Path / Version", style="dim")
    table1.add_column("Description", style="white")

    for name, data in system_deps.items():
        status_text = Text("FOUND", style="bold green") if data["installed"] else Text("NOT FOUND", style="bold red")
        path_ver = data.get("version") or data.get("path") or "Missing"
        table1.add_row(name, status_text, path_ver, data.get("description", ""))

    console.print(table1)
    console.print()

    table2 = Table(title="◈ SECURITY TOOL ADAPTERS (15 TOOLS) ◈", border_style="cyan", header_style="bold cyan")
    table2.add_column("Tool", style="bold white", width=18)
    table2.add_column("Status", justify="center", width=12)
    table2.add_column("Category", style="cyan", width=32)
    table2.add_column("Install / Binary", style="dim")

    for name, data in security_tools.items():
        status_text = Text("[+] FOUND", style="bold green") if data["installed"] else Text("[-] NOT FOUND", style="bold yellow")
        info = data.get("path") if data["installed"] else f"Run: {data.get('install_command')}"
        table2.add_row(name, status_text, data.get("category", ""), info)

    console.print(table2)
    console.print()
