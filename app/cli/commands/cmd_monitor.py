"""CYBERWOLF Network Traffic & DDoS Monitoring Commands."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from app.monitors.traffic_monitor import TrafficMonitor
from app.monitors.ddos_detector import DDoSDetector
from app.ai.orchestrator import get_ai_orchestrator

console = Console()

def handle_traffic_monitor(duration: int = 5):
    """Execute live packet traffic inspection."""
    console.print(f"\n[bold cyan]◈ CYBERWOLF NETWORK TRAFFIC MONITOR ◈[/bold cyan]")
    console.print(f"[dim]Sampling network packet telemetry for {duration} seconds...[/dim]\n")

    monitor = TrafficMonitor()
    snapshot = monitor.capture_snapshot(duration_sec=duration)

    table = Table(title="◈ TRAFFIC TELEMETRY SUMMARY ◈", border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", style="cyan")

    table.add_row("Engine", snapshot.get("engine", "Native"))
    table.add_row("Packets Captured", str(snapshot.get("packet_count", 0)))
    table.add_row("Total Data Volume", f"{snapshot.get('total_bytes', 0)} bytes")
    table.add_row("Packet Rate", f"{snapshot.get('packets_per_second', 0)} pps")
    table.add_row("Anomaly Score", f"{snapshot.get('anomaly_score', 0)}/100")
    table.add_row("Confidence", snapshot.get("confidence", "LOW"))
    console.print(table)

    if snapshot.get("protocol_distribution"):
        console.print("\n[bold white]Protocol Distribution:[/bold white]")
        for proto, count in snapshot["protocol_distribution"].items():
            console.print(f" • [cyan]{proto}[/cyan]: {count} packets")

    if snapshot.get("anomaly_reasons"):
        console.print("\n[bold yellow]Observations / Anomalies:[/bold yellow]")
        for r in snapshot["anomaly_reasons"]:
            console.print(f" [!] {r}")
    console.print()

def handle_ddos_monitor(duration: int = 5):
    """Execute defensive DDoS and traffic anomaly assessment."""
    console.print(f"\n[bold cyan]◈ CYBERWOLF DEFENSIVE DDOS / TRAFFIC MONITOR ◈[/bold cyan]\n")
    
    detector = DDoSDetector()
    report = detector.evaluate_live_traffic(duration_sec=duration)

    score = report.get("anomaly_score", 0)
    score_style = "bold red" if score >= 70 else ("bold yellow" if score >= 35 else "bold green")

    t = Text()
    t.append("Traffic:        ", style="bold white")
    t.append(f"{report.get('traffic_mbps')} Mbps\n", style="cyan")
    t.append("Normal avg:     ", style="dim")
    t.append(f"{report.get('normal_avg_mbps')} Mbps\n\n", style="dim")

    t.append("Packets Rate:   ", style="bold white")
    t.append(f"{report.get('pps')} pps\n", style="cyan")
    t.append("Normal avg:     ", style="dim")
    t.append(f"{report.get('normal_avg_pps')} pps\n\n", style="dim")

    t.append("Connections:    ", style="bold white")
    t.append(f"{report.get('connections')}\n", style="cyan")
    t.append("Normal avg:     ", style="dim")
    t.append(f"{report.get('normal_avg_connections')}\n\n", style="dim")

    t.append("Anomaly Score:  ", style="bold white")
    t.append(f"{score}/100\n\n", style=score_style)

    t.append("Status:         ", style="bold white")
    t.append(f"{report.get('status')}\n", style=score_style)
    t.append("Possible cause: ", style="bold white")
    t.append(f"{report.get('possible_cause')}\n", style="white")
    t.append("Action:         ", style="bold white")
    t.append(f"{report.get('action')}\n", style="green")

    panel = Panel(t, title="◈ DDOS / DOS TELEMETRY RADAR ◈", border_style="red" if score >= 70 else "cyan")
    console.print(panel)
    console.print()
