"""CYBERWOLF SQL Injection Testing Command (cyberwolf sql-test)."""

from rich.console import Console
from rich.panel import Panel
from app.scanners.sqli_scanner import SQLiScanner
from app.security.authorization import AuthorizationEngine
from app.cli.formatter import display_findings_table
from app.ai.orchestrator import get_ai_orchestrator

console = Console()

def handle_sql_test(target_url: str, param: str = None, interactive_auth: bool = True):
    """Execute non-destructive SQL injection assessment."""
    if not target_url:
        console.print("[red]Error: Target URL required. Example: cyberwolf sql-test --target http://testphp.vulnweb.com/listproducts.php?cat=1[/red]")
        return

    auth_engine = AuthorizationEngine()
    if interactive_auth and not auth_engine.require_authorization_interactive(target_url, "sql_test"):
        console.print("[red]Operation aborted: Target not authorized.[/red]")
        return

    console.print(f"\n[bold cyan]◈ NON-DESTRUCTIVE SQL INJECTION ASSESSMENT ◈[/bold cyan]")
    console.print(f"[bold white]Target:[/bold white] {target_url}\n")

    scanner = SQLiScanner()
    res = scanner.test_endpoint(target_url, param_name=param)

    if not res.get("success"):
        console.print(f"[bold red]SQLi Test Failed:[/bold red] {res.get('error')}")
        return

    console.print(f"[bold white]Tested Parameters:[/bold white] {', '.join(res.get('tested_parameters', [])) or 'None'}")
    
    findings = res.get("findings", [])
    display_findings_table(findings, title="SQL INJECTION TEST RESULTS")

    if findings:
        console.print("\n[bold magenta]◈ CYBERWOLF AI SQL SECURITY ANALYSIS ◈[/bold magenta]")
        ai = get_ai_orchestrator()
        top_finding = findings[0]
        analysis = ai.analyze_sql_injection(target_url, top_finding.get("port") or "id", top_finding.get("evidence", ""))
        console.print(Panel(analysis, title="AI SQL Security Specialist", border_style="magenta"))
        console.print()
    else:
        console.print("[bold green]✔ No SQL injection vulnerabilities identified across tested heuristic vectors.[/bold green]\n")
