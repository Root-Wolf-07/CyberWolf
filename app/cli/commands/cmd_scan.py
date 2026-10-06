"""CYBERWOLF Scan Orchestration CLI Commands (V2).

Usage:
  cyberwolf scan <target> [--ports PORTS] [--profile fast|service|comprehensive]
  cyberwolf scan list
  cyberwolf scan show <scan_id>
  cyberwolf scan cancel <scan_id>
  cyberwolf scan network --target <target> [--ports PORTS]
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import Optional

from app.services.scan_service import get_scan_service
from app.cli.formatter import display_findings_table
from app.ai.orchestrator import get_ai_orchestrator
from app.core.exceptions import CyberWolfError

console = Console()


def handle_scan_target(target: str, ports: Optional[str] = None,
                       profile: str = "fast", scan_type: str = "network",
                       interactive_auth: bool = True):
    """Execute scan using unified ScanService pipeline."""
    if not target:
        console.print("[red]Error: Target required. Example: cyberwolf scan 127.0.0.1[/red]")
        return

    service = get_scan_service()
    console.print(f"\n[bold cyan]◈ STARTING CYBERWOLF V2 ASSESSMENT: {target} ◈[/bold cyan]")

    try:
        results = service.start_scan(
            target=target,
            scan_type=scan_type,
            options={"ports": ports, "profile": profile},
            interactive_auth=interactive_auth
        )
    except CyberWolfError as e:
        console.print(f"\n[bold red]{e}[/bold red]\n")
        return
    except Exception as e:
        console.print(f"\n[bold red]Scan failed unexpectedly: {e}[/bold red]\n")
        return

    scan_id = results.get("scan_id")
    duration = results.get("duration_seconds", 0)
    tools = ", ".join(results.get("tools_executed", []))
    findings_cnt = results.get("findings_count", 0)
    risk_score = results.get("asset_risk_score", 0.0)

    # Summary Panel
    t = Text()
    t.append(f"Scan ID:          {scan_id}\n", style="bold cyan")
    t.append(f"Target:           {target}\n", style="bold white")
    t.append(f"Execution Time:   {duration} seconds\n", style="dim")
    t.append(f"Tools Executed:   {tools}\n", style="white")
    t.append(f"Findings Found:   {findings_cnt}\n", style="bold yellow")
    t.append(f"Target Risk Score:{risk_score}/10.0\n", style="bold magenta")
    if results.get("reports"):
        t.append("\nDeliverables Generated:\n", style="bold white")
        for fmt, p in results["reports"].items():
            t.append(f" • {fmt}: {p}\n", style="cyan")

    console.print(Panel(t, title="[bold green]ASSESSMENT COMPLETED[/bold green]", border_style="green"))
    console.print()


def handle_scan_network(target: str, ports: Optional[str] = None, interactive_auth: bool = True):
    """Backward compatible handler for 'cyberwolf scan network --target ...'."""
    handle_scan_target(target=target, ports=ports, scan_type="network", interactive_auth=interactive_auth)


def handle_scan_list(limit: int = 20):
    """List recent scan sessions."""
    service = get_scan_service()
    scans = service.list_scans(limit=limit)

    console.print(f"\n[bold cyan]◈ RECENT SECURITY ASSESSMENT SCANS ({len(scans)}) ◈[/bold cyan]\n")
    table = Table(box=None)
    table.add_column("Scan ID", style="bold cyan", width=26)
    table.add_column("Type", width=12)
    table.add_column("Target", style="bold white", width=22)
    table.add_column("Status", width=12)
    table.add_column("Findings", width=10)
    table.add_column("Started", style="dim", width=20)

    for s in scans:
        status_str = s.get("status", "COMPLETED")
        status_color = "green" if status_str == "COMPLETED" else "yellow" if status_str == "RUNNING" else "red"
        table.add_row(
            s["id"],
            s.get("scan_type", "network"),
            s.get("target", "N/A"),
            f"[{status_color}]{status_str}[/{status_color}]",
            str(s.get("findings_count", 0)),
            str(s.get("start_time", ""))[:19]
        )

    console.print(table)
    console.print("\n[dim]To view details of a scan: cyberwolf scan show <SCAN_ID>[/dim]\n")


def handle_scan_show(scan_id: str):
    """Show details of a specific scan session."""
    service = get_scan_service()
    scan = service.get_scan(scan_id)
    if not scan:
        console.print(f"[red]Scan with ID '{scan_id}' not found.[/red]")
        return

    console.print(f"\n[bold cyan]◈ SCAN SESSION: {scan['id']} ◈[/bold cyan]\n")
    t = Text()
    t.append(f"Target:       {scan.get('target')}\n", style="bold white")
    t.append(f"Type:         {scan.get('scan_type')} | Mode: {scan.get('mode')}\n", style="cyan")
    t.append(f"Status:       {scan.get('status')}\n", style="bold green" if scan.get('status') == "COMPLETED" else "yellow")
    t.append(f"Started:      {scan.get('start_time')}\n", style="dim")
    t.append(f"Ended:        {scan.get('end_time')}\n", style="dim")
    t.append(f"Findings:     {scan.get('findings_count', 0)} total "
             f"(Critical: {scan.get('critical_count', 0)}, High: {scan.get('high_count', 0)}, "
             f"Med: {scan.get('medium_count', 0)}, Low: {scan.get('low_count', 0)})\n", style="yellow")
    if scan.get("tools_executed"):
        t.append(f"Tools:        {', '.join(scan.get('tools_executed', []))}\n", style="dim")

    console.print(Panel(t, title="[bold]Session Details[/bold]", border_style="cyan"))
    console.print()


def handle_scan_cancel(scan_id: str):
    """Cancel a running scan."""
    service = get_scan_service()
    if service.cancel_scan(scan_id):
        console.print(f"[bold green]✓ Scan '{scan_id}' cancelled successfully.[/bold green]")
    else:
        console.print(f"[yellow]Could not cancel scan '{scan_id}' (not found or already completed).[/yellow]")
