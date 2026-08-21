"""CYBERWOLF Vulnerability Assessment Command."""

from rich.console import Console
from rich.panel import Panel
from app.scanners.vuln_scanner import VulnerabilityScanner
from app.security.authorization import AuthorizationEngine
from app.cli.formatter import display_findings_table
from app.ai.orchestrator import get_ai_orchestrator

console = Console()

def handle_vuln_scan(target: str, severity: str = None, interactive_auth: bool = True):
    """Execute vulnerability scan on authorized target."""
    if not target:
        console.print("[red]Error: Target required. Example: cyberwolf vuln --target 127.0.0.1[/red]")
        return

    auth_engine = AuthorizationEngine()
    if interactive_auth and not auth_engine.require_authorization_interactive(target, "vuln_scan"):
        console.print("[red]Operation aborted: Target not authorized.[/red]")
        return

    console.print(f"\n[bold cyan]◈ RUNNING VULNERABILITY ASSESSMENT: {target} ◈[/bold cyan]")
    scanner = VulnerabilityScanner()
    results = scanner.scan(target, severity_filter=severity)

    findings = results.get("findings", [])
    display_findings_table(findings, title="VULNERABILITY ASSESSMENT RESULTS")

    if findings:
        console.print("\n[bold magenta]◈ CYBERWOLF AI VULNERABILITY TRIAGE ◈[/bold magenta]")
        ai = get_ai_orchestrator()
        top_finding = findings[0]
        analysis = ai.analyze_vulnerability_finding(top_finding, scan_id=results.get("scan_id"))
        console.print(Panel(analysis, title=f"AI Analyst: {top_finding.get('vulnerability')}", border_style="magenta"))
        console.print()
