"""CYBERWOLF Security Policy CLI Command (V2).

Usage:
  cyberwolf policy show
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from app.security.policies import PolicyEngine
from app.core.config import get_config

console = Console()


def handle_policy_show():
    """Display currently enforced security policy parameters and restrictions."""
    config = get_config()
    policy_engine = PolicyEngine()
    policy = policy_engine.get_active_policy()

    console.print("\n[bold cyan]◈ CYBERWOLF SECURITY POLICY PROFILE ◈[/bold cyan]\n")

    t = Text()
    t.append(f"Active Mode:               {policy.name}\n", style="bold green")
    t.append(f"Allow Network Scans:       {policy.allow_network_scan}\n", style="white")
    t.append(f"Allow Web Scans:           {policy.allow_web_scan}\n", style="white")
    t.append(f"Allow Packet Capture:      {policy.allow_packet_capture}\n", style="white")
    t.append(f"Allow Bruteforce:          {policy.allow_bruteforce}\n", style="yellow" if policy.allow_bruteforce else "dim")
    t.append(f"Allow Destructive Testing: {policy.allow_destructive}\n", style="red" if policy.allow_destructive else "green")
    t.append(f"Max Scan Duration:         {policy.max_scan_duration} seconds\n", style="white")
    t.append(f"Allowed Scanners:          {', '.join(policy.allowed_tools)}\n", style="cyan")
    t.append(f"Rate Limit Delay:          {policy.rate_limit_delay_ms} ms\n", style="dim")

    panel = Panel(t, title="[bold]Active Enforcement Rules[/bold]", border_style="cyan")
    console.print(panel)
    console.print()
