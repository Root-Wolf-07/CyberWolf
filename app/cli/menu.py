"""CYBERWOLF Interactive Menu Subsystem (14 Operations)."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

MENU_OPERATIONS = [
    ("[1]", "Network Scanning", "Host discovery, port scanning, service and version detection"),
    ("[2]", "Vulnerability Testing", "Automated CVE/CWE vulnerability assessment & Nuclei integration"),
    ("[3]", "Penetration Testing", "Controlled, authorized penetration testing & validation workflows"),
    ("[4]", "Bug Discovery", "Misconfigurations, exposed debug files, secret leaks & sensitive paths"),
    ("[5]", "SQL Injection Testing", "Non-destructive safe parameter heuristic SQLi detection"),
    ("[6]", "Web Security Assessment", "HTTP/HTTPS headers, TLS configuration, and web attack surfaces"),
    ("[7]", "Server Security Assessment", "Exposed administrative services, banner analysis & OS risks"),
    ("[8]", "Network Traffic Monitoring", "Real-time packet inspection, protocol distribution & anomaly flow"),
    ("[9]", "DDoS/DoS Detection & Monitoring", "Defensive telemetry, traffic surge monitoring & DoS pattern analysis"),
    ("[10]", "Security Reports", "Generate multi-format executive reports (TXT, JSON, HTML, CSV)"),
    ("[11]", "AI Security Assistant", "Local Gemma/Ollama AI security analyst & interactive advisor"),
    ("[12]", "Database / Knowledge Base", "SQLite database status, search, backup, export & local RAG"),
    ("[13]", "Configuration", "System settings, safe mode selection, target scopes & policies"),
    ("[14]", "Exit", "Safely shutdown CYBERWOLF command center")
]

def display_menu():
    """Render the 14 core operations menu."""
    table = Table(
        title="◈ CYBERWOLF CORE OPERATIONS ◈",
        border_style="cyan",
        header_style="bold cyan",
        show_header=True
    )
    table.add_column("No.", style="bold cyan", justify="center", width=6)
    table.add_column("Operation Module", style="bold white", width=34)
    table.add_column("Capabilities & Scope", style="dim", min_width=45)

    for num, title, desc in MENU_OPERATIONS:
        table.add_row(num, title, desc)

    console.print(table)
    console.print()
