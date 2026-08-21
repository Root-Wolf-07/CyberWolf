"""CYBERWOLF Main Application Entrypoint & CLI Parser."""

import sys
import argparse
import warnings
warnings.filterwarnings("ignore")
from app.cli.repl import run_interactive_repl
from app.cli.commands import (
    handle_doctor, handle_status, handle_scan_network,
    handle_vuln_scan, handle_pentest, handle_web_assessment,
    handle_sql_test, handle_traffic_monitor, handle_ddos_monitor,
    handle_reports, handle_ai_prompt, handle_database,
    handle_config, handle_demo, handle_lab
)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberwolf",
        description="CYBERWOLF — Local AI Cybersecurity Security Command Center"
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # doctor
    subparsers.add_parser("doctor", help="Run system and security tool diagnostics")

    # status
    subparsers.add_parser("status", help="Display operational status")

    # demo
    subparsers.add_parser("demo", help="Run safe simulated security assessment showcase")

    # scan
    scan_p = subparsers.add_parser("scan", help="Network & Port Scanning")
    scan_sub = scan_p.add_subparsers(dest="scan_type")
    net_p = scan_sub.add_parser("network", help="Scan network targets")
    net_p.add_argument("--target", "-t", type=str, required=True, help="Target IP / CIDR / Hostname")
    net_p.add_argument("--ports", "-p", type=str, help="Port range or comma-separated list")

    # vuln
    vuln_p = subparsers.add_parser("vuln", help="Vulnerability assessment")
    vuln_p.add_argument("--target", "-t", type=str, required=True, help="Target IP / Hostname / URL")
    vuln_p.add_argument("--severity", "-s", type=str, help="Filter severity (critical, high, medium, low)")

    # pentest
    pentest_p = subparsers.add_parser("pentest", help="Authorized penetration testing workflow")
    pentest_p.add_argument("--target", "-t", type=str, required=True, help="Target host")

    # web
    web_p = subparsers.add_parser("web", help="Web application security assessment")
    web_p.add_argument("--target", "-t", type=str, required=True, help="Target URL")

    # sql-test
    sql_p = subparsers.add_parser("sql-test", help="Non-destructive SQL injection assessment")
    sql_p.add_argument("--target", "-t", type=str, required=True, help="Target URL")
    sql_p.add_argument("--param", "-p", type=str, help="Specific parameter name")

    # monitor
    mon_p = subparsers.add_parser("monitor", help="Network packet traffic monitor")
    mon_p.add_argument("--duration", "-d", type=int, default=5, help="Capture duration in seconds")

    # ddos-monitor
    ddos_p = subparsers.add_parser("ddos-monitor", help="Defensive DDoS & traffic anomaly radar")
    ddos_p.add_argument("--duration", "-d", type=int, default=5, help="Inspection duration in seconds")

    # reports
    rep_p = subparsers.add_parser("reports", help="Generate or list security reports")
    rep_p.add_argument("action", nargs="?", default="list", choices=["list", "generate"])
    rep_p.add_argument("--target", "-t", type=str, help="Target name for report")

    # ai
    ai_p = subparsers.add_parser("ai", help="Query local AI security assistant")
    ai_p.add_argument("prompt", nargs="+", help="Security question or prompt")

    # database
    db_p = subparsers.add_parser("database", help="Manage SQLite knowledge database")
    db_p.add_argument("action", nargs="?", default="status", choices=["status", "backup", "export", "search"])
    db_p.add_argument("term", nargs="?", help="Search term (for search action)")

    # config
    cfg_p = subparsers.add_parser("config", help="View or update configuration")
    cfg_p.add_argument("action", nargs="?", default="show", choices=["show", "set-mode"])
    cfg_p.add_argument("mode", nargs="?", help="Mode to set (PASSIVE, SAFE_SCAN, ACTIVE_SCAN, etc.)")

    # lab
    lab_p = subparsers.add_parser("lab", help="Security lab environment")
    lab_p.add_argument("action", nargs="?", default="status", choices=["status", "scan"])

    return parser

def main():
    """Main execution router."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        # Launch interactive REPL when no arguments are provided
        run_interactive_repl()
        return

    if args.command == "doctor":
        handle_doctor()
    elif args.command == "status":
        handle_status()
    elif args.command == "demo":
        handle_demo()
    elif args.command == "scan":
        if getattr(args, "scan_type", None) == "network" or getattr(args, "target", None):
            handle_scan_network(args.target, ports=getattr(args, "ports", None))
        else:
            handle_scan_network(args.target)
    elif args.command == "vuln":
        handle_vuln_scan(args.target, severity=args.severity)
    elif args.command == "pentest":
        handle_pentest(args.target)
    elif args.command == "web":
        handle_web_assessment(args.target)
    elif args.command == "sql-test":
        handle_sql_test(args.target, param=args.param)
    elif args.command == "monitor":
        handle_traffic_monitor(duration=args.duration)
    elif args.command == "ddos-monitor":
        handle_ddos_monitor(duration=args.duration)
    elif args.command == "reports":
        handle_reports(action=args.action, target=args.target)
    elif args.command == "ai":
        prompt_text = " ".join(args.prompt)
        handle_ai_prompt(prompt_text)
    elif args.command == "database":
        handle_database(action=args.action, term=args.term)
    elif args.command == "config":
        handle_config(action=args.action, mode=args.mode)
    elif args.command == "lab":
        handle_lab(action=args.action)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
