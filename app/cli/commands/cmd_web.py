"""CYBERWOLF Web Security Assessment Command."""

from rich.console import Console
from rich.panel import Panel
from app.scanners.web_scanner import WebScanner
from app.scanners.bug_analyzer import BugAnalyzer
from app.security.authorization import AuthorizationEngine
from app.cli.formatter import display_findings_table

console = Console()

def handle_web_assessment(target_url: str, interactive_auth: bool = True):
    """Execute web security and endpoint posture assessment."""
    if not target_url:
        console.print("[red]Error: Target URL required. Example: cyberwolf web --target https://example.local[/red]")
        return

    auth_engine = AuthorizationEngine()
    if interactive_auth and not auth_engine.require_authorization_interactive(target_url, "web_assessment"):
        console.print("[red]Operation aborted: Target not authorized.[/red]")
        return

    console.print(f"\n[bold cyan]◈ WEB SECURITY ASSESSMENT: {target_url} ◈[/bold cyan]\n")
    
    # 1. Web Header & TLS Scanner
    web_scanner = WebScanner()
    res = web_scanner.assess_url(target_url)

    if not res.get("success"):
        console.print(f"[bold red]Web assessment failed:[/bold red] {res.get('error')}")
        return

    console.print(f"[bold white]Server Banner:[/bold white] [cyan]{res.get('server')}[/cyan]")
    tls = res.get("tls_info", {})
    if tls.get("version"):
        console.print(f"[bold white]TLS Protocol:[/bold white] [green]{tls.get('version')}[/green] | Cipher: {tls.get('cipher')} ({tls.get('bits')} bits)")

    # 2. Sensitive Path & Misconfiguration Discovery
    console.print("\n[dim]Inspecting sensitive paths and common endpoint misconfigurations...[/dim]")
    bug_analyzer = BugAnalyzer()
    bug_res = bug_analyzer.analyze(target_url)

    all_findings = res.get("findings", []) + bug_res.get("findings", [])
    display_findings_table(all_findings, title="WEB SECURITY & MISCONFIGURATION FINDINGS")
