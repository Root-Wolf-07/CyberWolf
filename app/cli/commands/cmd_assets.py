"""CYBERWOLF Asset Inventory CLI Commands (V2).

Usage:
  cyberwolf assets list
  cyberwolf assets show <asset_id>
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from app.services.asset_service import get_asset_service

console = Console()


def handle_assets(action: str = "list", asset_id: str = None):
    """Handle asset inventory commands."""
    service = get_asset_service()

    if action == "show" and asset_id:
        try:
            aid = int(asset_id)
        except ValueError:
            console.print(f"[red]Error: Asset ID must be an integer, got '{asset_id}'.[/red]")
            return

        detail = service.get_asset_detail(aid)
        if not detail:
            console.print(f"[red]Asset with ID {aid} not found.[/red]")
            return

        asset = detail["asset"]
        console.print(f"\n[bold cyan]◈ ASSET DETAIL: {asset['target_identifier']} (ID: {asset['id']}) ◈[/bold cyan]\n")

        t = Text()
        t.append(f"Target:      {asset['target_identifier']}\n", style="bold white")
        t.append(f"Type:        {asset.get('asset_type', 'ip')} | Risk Level: {asset.get('risk_level', 'LOW')}\n", style="bold yellow")
        t.append(f"IP:          {asset.get('ip_address') or 'N/A'}\n", style="cyan")
        t.append(f"Hostname:    {asset.get('hostname') or 'N/A'}\n", style="white")
        t.append(f"OS:          {asset.get('operating_system') or 'N/A'}\n", style="dim")
        t.append(f"Risk Score:  {asset.get('risk_score', 0.0)}/10.0\n", style="magenta")
        t.append(f"First Seen:  {asset.get('first_seen')}\n", style="dim")
        t.append(f"Last Scan:   {asset.get('last_scanned')}\n", style="dim")

        console.print(Panel(t, title="[bold]Asset Profile[/bold]", border_style="cyan"))

        # Associated Findings
        findings = detail.get("findings", [])
        console.print(f"\n[bold white]Associated Security Findings ({len(findings)}):[/bold white]")
        for f in findings:
            sev = f.get("severity", "INFO")
            color = "red" if sev in ["CRITICAL", "HIGH"] else "yellow" if sev == "MEDIUM" else "cyan"
            console.print(f"  • [{color}][{sev}][/{color}] {f.get('title') or f.get('vulnerability')} (ID: {f.get('id')})")
        console.print()

    else:  # list
        assets = service.list_assets()
        console.print(f"\n[bold cyan]◈ ASSET INVENTORY ({len(assets)}) ◈[/bold cyan]\n")
        table = Table(box=None)
        table.add_column("ID", style="dim", width=6)
        table.add_column("Target Identifier", style="bold white", width=28)
        table.add_column("Type", style="cyan", width=10)
        table.add_column("IP Address", style="dim", width=18)
        table.add_column("Risk Level", width=12)
        table.add_column("Risk Score", width=12)
        table.add_column("Last Scanned", style="dim", width=20)

        for a in assets:
            rl = (a.get("risk_level") or "LOW").upper()
            color = "red" if rl in ["CRITICAL", "HIGH"] else "yellow" if rl == "MEDIUM" else "green"
            table.add_row(
                str(a["id"]),
                a["target_identifier"],
                a.get("asset_type", "ip"),
                a.get("ip_address") or "N/A",
                f"[{color}]{rl}[/{color}]",
                f"{a.get('risk_score', 0.0):.1f}/10.0",
                str(a.get("last_scanned") or "Never")[:19]
            )

        console.print(table)
        console.print("\n[dim]To inspect an asset, run: cyberwolf assets show <ID>[/dim]\n")
