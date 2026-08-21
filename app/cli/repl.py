"""CYBERWOLF Interactive Terminal REPL & Command Router."""

import shlex
import sys
from rich.console import Console
from app.cli.banner import print_banner
from app.cli.menu import display_menu
from app.cli.commands import (
    handle_doctor, handle_status, handle_scan_network,
    handle_vuln_scan, handle_pentest, handle_web_assessment,
    handle_sql_test, handle_traffic_monitor, handle_ddos_monitor,
    handle_reports, handle_ai_prompt, handle_database,
    handle_config, handle_demo, handle_lab
)

console = Console()

def run_interactive_repl():
    """Launch the interactive CYBERWOLF command shell."""
    print_banner(console)
    display_menu()

    while True:
        try:
            cmd_line = input("cyberwolf> ").strip()
            if not cmd_line:
                continue

            # Check menu numbers 1-14
            if cmd_line in ["1", "network", "scan"]:
                target = input("Enter target IP / Hostname (default 127.0.0.1): ").strip() or "127.0.0.1"
                ports = input("Enter port range (optional, e.g. 1-1000): ").strip() or None
                handle_scan_network(target, ports=ports)

            elif cmd_line in ["2", "vuln"]:
                target = input("Enter target host / URL (default 127.0.0.1): ").strip() or "127.0.0.1"
                handle_vuln_scan(target)

            elif cmd_line in ["3", "pentest"]:
                target = input("Enter authorized pentest target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
                handle_pentest(target)

            elif cmd_line in ["4", "bug", "bugs"]:
                target = input("Enter target URL for misconfiguration discovery (e.g. http://127.0.0.1:8080): ").strip() or "http://127.0.0.1"
                handle_web_assessment(target)

            elif cmd_line in ["5", "sql", "sql-test"]:
                target = input("Enter target URL (e.g. http://testphp.vulnweb.com/artists.php?artist=1): ").strip()
                if target:
                    handle_sql_test(target)
                else:
                    console.print("[red]Target URL required for SQL testing.[/red]")

            elif cmd_line in ["6", "web"]:
                target = input("Enter target URL (e.g. https://example.local): ").strip() or "http://127.0.0.1"
                handle_web_assessment(target)

            elif cmd_line in ["7", "server"]:
                target = input("Enter server IP / Hostname: ").strip() or "127.0.0.1"
                handle_scan_network(target)

            elif cmd_line in ["8", "monitor", "traffic"]:
                handle_traffic_monitor(duration=5)

            elif cmd_line in ["9", "ddos", "ddos-monitor"]:
                handle_ddos_monitor(duration=5)

            elif cmd_line in ["10", "reports", "report"]:
                action = input("Reports action (list / generate) [default: list]: ").strip().lower() or "list"
                if action == "generate":
                    tgt = input("Enter target for report (optional): ").strip() or None
                    handle_reports(action="generate", target=tgt)
                else:
                    handle_reports(action="list")

            elif cmd_line in ["11", "ai"]:
                prompt = input("Enter security query or question for CYBERWOLF AI: ").strip()
                if prompt:
                    handle_ai_prompt(prompt)

            elif cmd_line in ["12", "database", "db"]:
                action = input("Database action (status / backup / export / search) [default: status]: ").strip().lower() or "status"
                if action == "search":
                    term = input("Enter search term: ").strip()
                    handle_database("search", term=term)
                else:
                    handle_database(action)

            elif cmd_line in ["13", "config"]:
                action = input("Config action (show / set-mode) [default: show]: ").strip().lower() or "show"
                if action == "set-mode":
                    mode = input("Enter mode (PASSIVE / SAFE_SCAN / ACTIVE_SCAN / AUTHORIZED_PENTEST / LAB_MODE): ").strip().upper()
                    handle_config("set-mode", mode=mode)
                else:
                    handle_config("show")

            elif cmd_line in ["14", "exit", "quit", "q"]:
                console.print("\n[bold red]◈ SHUTTING DOWN CYBERWOLF COMMAND CENTER. DEFEND EVERYTHING. ◈[/bold red]\n")
                sys.exit(0)

            elif cmd_line in ["menu", "help", "?"]:
                display_menu()

            elif cmd_line == "doctor":
                handle_doctor()

            elif cmd_line == "status":
                handle_status()

            elif cmd_line == "demo":
                handle_demo()

            elif cmd_line == "lab":
                handle_lab("status")

            else:
                # Custom argument string parsing
                tokens = shlex.split(cmd_line)
                if tokens[0] == "scan" and len(tokens) > 1:
                    handle_scan_network(tokens[-1])
                elif tokens[0] == "ai" and len(tokens) > 1:
                    handle_ai_prompt(" ".join(tokens[1:]))
                else:
                    console.print(f"[yellow]Unknown command '{cmd_line}'. Type 'menu' or 'help' to see options.[/yellow]")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Use option 14 or type 'exit' to quit.[/dim]")
