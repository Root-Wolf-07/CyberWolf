"""CYBERWOLF Finding Inspection & Detail CLI Commands (V2).

Usage:
  cyberwolf findings list [--target] [--severity] [--status]
  cyberwolf findings show <finding_id>
  cyberwolf findings explain <finding_id>
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from app.services.finding_service import get_finding_service

console = Console()


def handle_findings(action: str = "list", finding_id: str = None,
                    target: str = None, severity: str = None,
                    status: str = None, cve: str = None):
    """Router for finding listing, detail, and explanation commands."""
    service = get_finding_service()

    if action == "show" or (action == "list" and finding_id):
        fid = finding_id or action
        detail = service.get_finding_detail(fid)
        if not detail:
            console.print(f"[red]Finding with ID '{fid}' not found in database.[/red]")
            return

        fnd = detail["finding"]
        expl = detail["explanation"]
        obs = expl.get("observed_facts", {})
        sec = expl.get("security_analysis", {})
        act = expl.get("actionable_guidance", {})

        console.print(f"\n[bold cyan]◈ FINDING DETAIL: {fnd['id']} ◈[/bold cyan]\n")

        # Summary Panel
        t = Text()
        t.append(f"Title:         {fnd.get('title') or fnd.get('vulnerability')}\n", style="bold white")
        t.append(f"Severity:      {fnd.get('severity')} | Risk Score: {fnd.get('risk_score', 'N/A')}/10.0\n", style="bold yellow")
        port_suffix = f" (Port {fnd.get('port')}/{fnd.get('protocol')})" if fnd.get('port') else ""
        t.append(f"Target:        {fnd.get('target')}{port_suffix}\n", style="white")
        if fnd.get("cve"):
            t.append(f"CVE:           {fnd.get('cve')}\n", style="magenta")
        if fnd.get("cwe"):
            t.append(f"CWE:           {fnd.get('cwe')}\n", style="dim magenta")
        t.append(f"Sources:       {', '.join(fnd.get('source_tools', [fnd.get('source_tool')]))}\n", style="dim")

        console.print(Panel(t, title="[bold]Metadata[/bold]", border_style="cyan"))

        # Technical Analysis
        analysis_text = f"• Why Dangerous: {sec.get('why_dangerous')}\n• Likely Impact: {sec.get('likely_impact')}"
        console.print(Panel(analysis_text, title="[bold]Technical Analysis & Impact[/bold]", border_style="yellow"))

        # Evidence
        console.print(Panel(fnd.get("evidence", "No evidence"), title="[bold]Observed Evidence[/bold]", border_style="green"))

        # Actionable Remediation
        rem_text = f"• Action: {act.get('what_should_be_fixed')}\n• Verification: {act.get('how_to_verify')}"
        console.print(Panel(rem_text, title="[bold]Actionable Remediation Roadmap[/bold]", border_style="blue"))
        console.print()

    elif action == "explain":
        if not finding_id:
            console.print("[red]Error: Finding ID required. Example: cyberwolf findings explain CW-NET-0001[/red]")
            return
        expl = service.explain_finding(finding_id, use_ai=True)
        if not expl:
            console.print(f"[red]Finding '{finding_id}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]◈ 6-POINT REMEDIATION ADVISOR: {finding_id} ◈[/bold cyan]\n")
        obs = expl.get("observed_facts", {})
        sec = expl.get("security_analysis", {})
        act = expl.get("actionable_guidance", {})

        console.print(f"[bold white]1. What was detected:[/bold white] {obs.get('what_was_detected')}")
        console.print(f"[bold white]2. Why is it dangerous:[/bold white] {sec.get('why_dangerous')}")
        console.print(f"[bold white]3. Evidence:[/bold white] {obs.get('evidence')}")
        console.print(f"[bold white]4. Likely impact:[/bold white] {sec.get('likely_impact')}")
        console.print(f"[bold white]5. What should be fixed:[/bold white] {act.get('what_should_be_fixed')}")
        console.print(f"[bold white]6. How to verify:[/bold white] {act.get('how_to_verify')}\n")

    else:  # list
        findings = service.list_findings(target=target, severity=severity, status=status, cve=cve)
        console.print(f"\n[bold cyan]◈ SECURITY FINDINGS INVENTORY ({len(findings)}) ◈[/bold cyan]\n")
        table = Table(box=None)
        table.add_column("ID", style="bold cyan", width=18)
        table.add_column("Severity", width=12)
        table.add_column("Title / Vulnerability", style="bold white", width=34)
        table.add_column("Target", style="dim", width=22)
        table.add_column("Tool", style="dim", width=14)
        table.add_column("Status", width=12)

        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            sev_color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "dim white"
            }.get(sev, "white")

            title_display = (f.get("title") or f.get("vulnerability") or "")[:32]
            target_display = f.get("target", "")[:20]
            table.add_row(
                f["id"],
                f"[{sev_color}]{sev}[/{sev_color}]",
                title_display,
                target_display,
                f.get("source_tool", "CYBERWOLF"),
                f.get("status", "OPEN")
            )

        console.print(table)
        console.print(f"\n[dim]To inspect a specific finding, run: cyberwolf findings show <FINDING_ID>[/dim]\n")
