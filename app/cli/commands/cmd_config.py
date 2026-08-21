"""CYBERWOLF Configuration Command."""

import yaml
from rich.console import Console
from rich.panel import Panel
from app.core.config import get_config

console = Console()

def handle_config(action: str = "show", mode: str = None):
    """View configuration or update active security mode."""
    config = get_config()

    if action == "set-mode":
        if not mode:
            console.print("[red]Error: Mode required. Options: PASSIVE, SAFE_SCAN, ACTIVE_SCAN, AUTHORIZED_PENTEST, LAB_MODE[/red]")
            return
        if config.set_active_mode(mode.upper()):
            console.print(f"[bold green]✔ Security mode updated to:[/bold green] [bold cyan]{mode.upper()}[/bold cyan]\n")
        else:
            console.print(f"[bold red]Invalid mode '{mode}'.[/bold red] Choose from: PASSIVE, SAFE_SCAN, ACTIVE_SCAN, AUTHORIZED_PENTEST, LAB_MODE\n")
    else:
        # Show configuration
        console.print("\n[bold cyan]◈ ACTIVE CYBERWOLF CONFIGURATION ◈[/bold cyan]\n")
        cfg_str = yaml.dump(config.config, default_flow_style=False)
        console.print(Panel(cfg_str, title="config.yaml", border_style="cyan"))
        console.print()
