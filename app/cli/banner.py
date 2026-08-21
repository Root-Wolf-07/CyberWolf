"""CYBERWOLF ASCII Banner and Terminal Branding."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from app.core.config import get_config
from app.core.platform_adapter import get_platform_adapter
from app.ai.ollama_client import get_ollama_client

WOLF_ASCII = r"""
                      __
                    /   \
                   /  _  \
                  /  / \  \
                 /  /   \  \
                /  /     \  \
               /  /  /\_  \  \
              /  /  /  /   \  \
             /  /__/  /     \  \
            /  ___   /       \  \
           /  /  /  /         \  \
          /  /  /  /           \  \
         /__/  /__/             \__\
            \  \   /|     |\   /  /
             \  \ / |     | \ /  /
              \  V  |  _  |  V  /
               \    | / \ |    /
                \   |/   \|   /
                 \           /
                  \  .---.  /
                   \ | W | /
                    \| O |/
                     | L |
                     | F |
                     '---'
"""

WOLF_HEADER_BANNER = r"""
================================================================================

                           C Y B E R W O L F

           HUNT THREATS  •  FIND WEAKNESSES  •  DEFEND EVERYTHING

                        [ WOLF SECURITY ENGINE ]

================================================================================
"""

def print_banner(console: Console = None):
    """Render the official CYBERWOLF startup banner and system status block."""
    if console is None:
        console = Console()

    config = get_config()
    platform = get_platform_adapter()
    ollama = get_ollama_client()

    ai_model = ollama.get_active_model() or "Gemma (Offline)"
    ai_status = "Ollama / " + ai_model if ollama.is_online() else "Ollama (Offline - Start with 'ollama serve')"
    
    console.print(f"[bold cyan]{WOLF_HEADER_BANNER}[/bold cyan]")
    
    status_text = Text()
    status_text.append(" AI Engine : ", style="bold white")
    status_text.append(f"{ai_status}\n", style="cyan" if ollama.is_online() else "yellow")
    
    status_text.append(" Database  : ", style="bold white")
    status_text.append(f"Local SQLite ({config.get_db_path()})\n", style="green")
    
    status_text.append(" Security  : ", style="bold white")
    status_text.append(f"Mode: {config.get_active_mode()} | Strict Scope Verification: ON\n", style="bold green")
    
    status_text.append(" Host OS   : ", style="bold white")
    status_text.append(f"{platform.get_os_display_name()} | Python {platform.python_version}\n", style="white")

    status_text.append(" Status    : ", style="bold white")
    status_text.append("OPERATIONAL & ARMED\n", style="bold green")

    panel = Panel(
        status_text,
        title="[bold red]◈ CYBERWOLF COMMAND & CONTROL ◈[/bold red]",
        border_style="cyan",
        expand=False
    )
    console.print(panel)
    console.print()
