"""CYBERWOLF Demonstration Showcase Command (cyberwolf demo)."""

from rich.console import Console
from rich.panel import Panel
from app.demo.demo_runner import DemoRunner
from app.cli.formatter import display_findings_table
from app.database.operations import get_all_findings

console = Console()

def handle_demo():
    """Execute complete simulated security assessment showcase."""
    console.print("\n[bold cyan]◈ EXECUTING CYBERWOLF SAFE DEMONSTRATION ◈[/bold cyan]")
    console.print("[dim]Simulating multi-vector assessment (Nmap, Nuclei, Web, SQLi, Telemetry)...[/dim]\n")

    runner = DemoRunner()
    res = runner.run_demo()

    findings = get_all_findings(target=res["target"])
    display_findings_table(findings, title="SIMULATED DEMO FINDINGS")

    console.print("[bold magenta]◈ AI EXECUTIVE ANALYSIS ◈[/bold magenta]")
    console.print(Panel(res["ai_analysis"], title="CYBERWOLF AI Command Intelligence", border_style="magenta"))
    console.print()

    console.print("[bold green]✔ Multi-format demo reports generated in reports/ directory:[/bold green]")
    for fmt, path in res["reports"].items():
        console.print(f" • [bold white]{fmt}:[/bold white] [cyan]{path}[/cyan]")
    console.print("\n[bold green]◈ DEMO ASSESSMENT SUCCESSFULLY COMPLETED ◈[/bold green]\n")
