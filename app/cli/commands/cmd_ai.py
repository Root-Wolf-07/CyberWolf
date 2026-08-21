"""CYBERWOLF AI Assistant Command."""

from rich.console import Console
from rich.panel import Panel
from app.ai.orchestrator import get_ai_orchestrator
from app.ai.ollama_client import get_ollama_client

console = Console()

def handle_ai_prompt(prompt: str):
    """Execute AI query using local Ollama model."""
    if not prompt:
        console.print("[red]Error: Please specify a question or security query. Example: cyberwolf ai 'How to harden SSH?'[/red]")
        return

    console.print(f"\n[bold magenta]◈ CONSULTING CYBERWOLF AI ASSISTANT ◈[/bold magenta]")
    console.print(f"[dim]Query: {prompt}[/dim]\n")

    ai = get_ai_orchestrator()
    response = ai.query_assistant(prompt)
    console.print(Panel(response, title="CYBERWOLF AI Security Intelligence", border_style="magenta"))
    console.print()
