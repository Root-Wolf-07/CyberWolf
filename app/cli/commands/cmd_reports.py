"""CYBERWOLF Security Reports Command."""

from rich.console import Console
from rich.table import Table
from app.reports.generator import ReportGenerator
from app.database.db_manager import get_db
from app.database.operations import get_all_findings

console = Console()

def handle_reports(action: str = "list", target: str = None):
    """Manage and generate security assessment reports."""
    generator = ReportGenerator()

    if action == "generate":
        target_str = target or "All Assessed Targets"
        console.print(f"\n[bold cyan]◈ GENERATING MULTI-FORMAT SECURITY REPORTS FOR: {target_str} ◈[/bold cyan]")
        files = generator.generate_all_formats(target=target_str)
        console.print("[bold green]✔ Reports generated successfully:[/bold green]")
        for fmt, path in files.items():
            console.print(f" • [bold white]{fmt}:[/bold white] [cyan]{path}[/cyan]")
        console.print()
    else:
        # List generated reports from DB
        db = get_db()
        with db.get_connection() as conn:
            rows = conn.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 15").fetchall()

        if not rows:
            console.print("\n[dim]No reports generated yet. Run 'cyberwolf reports generate --target <target>' or 'cyberwolf demo'.[/dim]\n")
            return

        table = Table(title="◈ GENERATED SECURITY REPORTS ◈", border_style="cyan")
        table.add_column("Report ID", style="bold cyan")
        table.add_column("Target", style="white")
        table.add_column("Findings", justify="center", style="bold red")
        table.add_column("File Path", style="dim")
        table.add_column("Date", style="dim")

        for r in rows:
            table.add_row(r["id"], r["target"], str(r["findings_count"]), r["file_path"], r["created_at"])

        console.print(table)
        console.print()
