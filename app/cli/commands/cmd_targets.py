"""CYBERWOLF Target Management CLI Commands (V2).

Usage:
  cyberwolf target list
  cyberwolf target add <target> [--authorized] [--scope SCOPE]
"""

from rich.console import Console
from rich.table import Table
from app.services.target_service import get_target_service

console = Console()


def handle_targets(action: str = "list", target: str = None,
                   authorized: bool = True, scope: str = "lab-network"):
    """Handle targets commands."""
    service = get_target_service()

    if action == "add":
        if not target:
            console.print("[red]Error: Target address or hostname required. Example: cyberwolf target add 192.168.1.100 --authorized[/red]")
            return

        try:
            result = service.add_target(target, authorized=authorized, scope_id=scope)
            console.print(f"[bold green]✓ Target successfully added to authorized scope:[/bold green] {result['target']} (Scope: {result['scope_id']})")
        except Exception as e:
            console.print(f"[bold red]Target enrollment error:[/bold red] {e}")

    else:  # list
        targets = service.list_targets()
        console.print("\n[bold cyan]◈ AUTHORIZED TARGET SCOPES ◈[/bold cyan]\n")
        table = Table(box=None)
        table.add_column("Target", style="bold white", width=26)
        table.add_column("Scope ID", style="cyan", width=18)
        table.add_column("Scope Name", style="dim", width=28)
        table.add_column("Risk Level", width=12)

        for t in targets:
            rl = t.get("risk_level", "low").upper()
            color = "green" if rl == "LOW" else "yellow" if rl == "MEDIUM" else "red"
            table.add_row(t["target"], t["scope_id"], t["scope_name"], f"[{color}]{rl}[/{color}]")

        console.print(table)
        console.print(f"\n[dim]Total authorized target patterns: {len(targets)}[/dim]\n")
