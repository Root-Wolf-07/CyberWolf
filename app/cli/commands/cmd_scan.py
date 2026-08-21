"""CYBERWOLF Network Scan Command."""

from rich.console import Console
from rich.panel import Panel
from app.scanners.network_scanner import NetworkScanner
from app.security.authorization import AuthorizationEngine
from app.security.policies import PolicyEngine
from app.ai.orchestrator import get_ai_orchestrator
from app.cli.formatter import display_findings_table

console = Console()

def handle_scan_network(target: str, ports: str = None, interactive_auth: bool = True):
    """Execute network scan on authorized target."""
    if not target:
        console.print("[red]Error: Target required. Example: cyberwolf scan network --target 127.0.0.1[/red]")
        return

    auth_engine = AuthorizationEngine()
    policy_engine = PolicyEngine()

    allowed, p_msg = policy_engine.validate_action("port_scan")
    if not allowed:
        console.print(f"[bold red]Policy Violation:[/bold red] {p_msg}")
        return

    if interactive_auth:
        if not auth_engine.require_authorization_interactive(target, "network_scan"):
            console.print("[red]Operation aborted: Target not authorized.[/red]")
            return

    console.print(f"\n[bold cyan]◈ SCANNING TARGET NETWORK: {target} ◈[/bold cyan]")
    scanner = NetworkScanner()
    results = scanner.scan(target, port_spec=ports)

    # Display Hosts & Ports
    for h in results.get("hosts", []):
        hostname_str = f" ({h.get('hostname')})" if h.get('hostname') else ""
        console.print(f"\n[bold green]Host Discovered:[/bold green] {h['ip']}{hostname_str}")
        if h.get("ports"):
            for p in h["ports"]:
                banner_str = f" - {p['banner']}" if p.get("banner") else ""
                console.print(f"  [cyan]Port {p['port']}/{p['protocol']}[/cyan]: [bold]{p['state'].upper()}[/bold] ({p['service']}){banner_str}")
        else:
            console.print("  [dim]No open ports discovered in target range.[/dim]")

    # Display Findings
    if results.get("findings"):
        console.print()
        display_findings_table(results["findings"], title="NETWORK EXPOSURE FINDINGS")

    # AI Analysis
    console.print("\n[bold magenta]◈ CYBERWOLF AI ANALYSIS ◈[/bold magenta]")
    ai = get_ai_orchestrator()
    analysis = ai.analyze_network_scan(target, results.get("hosts", []), scan_id=results.get("scan_id"))
    console.print(Panel(analysis, title="AI Security Analyst", border_style="magenta"))
    console.print()
