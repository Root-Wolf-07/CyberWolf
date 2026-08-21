"""CYBERWOLF Database Management Command."""

import json
from rich.console import Console
from rich.table import Table
from app.database.operations import get_database_status, search_database, export_database_json
from app.database.db_manager import get_db

console = Console()

def handle_database(action: str = "status", term: str = None):
    """Execute database status, backup, export, or search."""
    db = get_db()

    if action == "status":
        stats = get_database_status()
        console.print("\n[bold cyan]◈ CYBERWOLF DATABASE DIAGNOSTICS ◈[/bold cyan]\n")
        table = Table(border_style="cyan")
        table.add_column("Property", style="bold white")
        table.add_column("Value", style="cyan")
        for k, v in stats.items():
            table.add_row(k.replace("_", " ").title(), str(v))
        console.print(table)
        console.print()

    elif action == "backup":
        console.print("\n[bold cyan]◈ CREATING LOCAL DATABASE BACKUP ◈[/bold cyan]")
        backup_path = db.backup_database()
        console.print(f"[bold green]✔ Backup successfully created at:[/bold green] [cyan]{backup_path}[/cyan]\n")

    elif action == "export":
        console.print("\n[bold cyan]◈ EXPORTING LOCAL DATABASE TO JSON ◈[/bold cyan]")
        data = export_database_json()
        export_file = db.db_path.parent / "cyberwolf_export.json"
        with open(export_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        console.print(f"[bold green]✔ Data exported to:[/bold green] [cyan]{export_file}[/cyan]\n")

    elif action == "search":
        if not term:
            console.print("[red]Error: Search term required. Example: cyberwolf database search log4j[/red]")
            return
        console.print(f"\n[bold cyan]◈ SEARCHING DATABASE FOR: '{term}' ◈[/bold cyan]\n")
        results = search_database(term)
        findings = results.get("findings", [])
        if findings:
            console.print(f"[bold green]Found {len(findings)} matching findings:[/bold green]")
            for f in findings:
                console.print(f" • [[bold red]{f.get('severity')}[/bold red]] {f.get('vulnerability')} ({f.get('target')})")
        else:
            console.print("[yellow]No database records matched your search query.[/yellow]")
        console.print()
