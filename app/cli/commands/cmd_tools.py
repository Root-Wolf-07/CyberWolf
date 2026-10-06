"""CYBERWOLF Security Tool Adapters CLI Command (V2).

Usage:
  cyberwolf tools list
"""

from rich.console import Console
from rich.table import Table
from app.tools.detector import get_tool_detector

console = Console()


def handle_tools_list():
    """Display comprehensive table of all supported security scanner adapters."""
    detector = get_tool_detector()
    report = detector.get_full_doctor_report()
    tools = report["security_tools"]

    console.print("\n[bold cyan]◈ SECURITY SCANNER ADAPTER STATUS ◈[/bold cyan]\n")
    table = Table(box=None)
    table.add_column("Tool", style="bold white", width=18)
    table.add_column("Status", width=14)
    table.add_column("Category", style="dim", width=34)
    table.add_column("Binary / Version", style="cyan", width=24)

    for name, data in tools.items():
        installed = data.get("installed", False)
        status_str = "[bold green]INSTALLED[/bold green]" if installed else "[bold yellow]MISSING[/bold yellow]"
        table.add_row(
            name,
            status_str,
            data.get("category", ""),
            data.get("version", "Not found")
        )

    console.print(table)
    console.print()
