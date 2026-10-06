"""CYBERWOLF V2 — Main Application Entrypoint & CLI Parser.

Orchestrates authorized security tools, normalizes results, correlates findings,
calculates risk, preserves evidence, and generates professional security deliverables.
"""

import sys
import argparse
import warnings
warnings.filterwarnings("ignore")

from app.cli.repl import run_interactive_repl
from app.cli.commands import (
    handle_doctor,
    handle_status,
    handle_scan_network,
    handle_scan_target,
    handle_scan_list,
    handle_scan_show,
    handle_scan_cancel,
    handle_vuln_scan,
    handle_pentest,
    handle_web_assessment,
    handle_sql_test,
    handle_traffic_monitor,
    handle_ddos_monitor,
    handle_reports,
    handle_ai_prompt,
    handle_database,
    handle_config,
    handle_demo,
    handle_lab,
    handle_targets,
    handle_findings,
    handle_assets,
    handle_tools_list,
    handle_policy_show,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the unified CyberWolf V2 CLI parser."""
    parser = argparse.ArgumentParser(
        prog="cyberwolf",
        description="CYBERWOLF V2 — Modular Cybersecurity Assessment & Intelligence Platform"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="CyberWolf 2.0.0",
        help="Display CyberWolf platform version"
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # doctor
    subparsers.add_parser("doctor", help="Run comprehensive system, tool, and database diagnostics")

    # status
    subparsers.add_parser("status", help="Display operational status and sensor summary")

    # demo
    subparsers.add_parser("demo", help="Run safe simulated security assessment showcase (DEMO MODE)")

    # targets / target
    for t_cmd in ["target", "targets"]:
        tp = subparsers.add_parser(t_cmd, help="Authorized target and scope management")
        tp.add_argument("action", nargs="?", default="list", choices=["list", "add"], help="Action: list or add")
        tp.add_argument("target_name", nargs="?", default=None, help="Target IP / Hostname / CIDR (for add)")
        tp.add_argument("--authorized", action="store_true", default=True, help="Explicitly mark target as authorized")
        tp.add_argument("--scope", default="lab-network", help="Scope identifier or tag")

    # scan
    scan_p = subparsers.add_parser("scan", help="Security assessment and port scanning engine")
    scan_p.add_argument("scan_action", nargs="?", default=None, help="Action (list, show, cancel, network) or target IP/host")
    scan_p.add_argument("scan_arg", nargs="?", default=None, help="Secondary argument (scan ID or target)")
    scan_p.add_argument("--target", "-t", type=str, help="Target IP / CIDR / Hostname")
    scan_p.add_argument("--ports", "-p", type=str, help="Port range or comma-separated list (e.g. 80,443,8080)")
    scan_p.add_argument("--profile", choices=["fast", "service", "comprehensive"], default="fast", help="Scan profile")

    # findings / finding
    for f_cmd in ["findings", "finding"]:
        fp = subparsers.add_parser(f_cmd, help="Vulnerability findings inventory and analysis")
        fp.add_argument("action", nargs="?", default="list", help="Action: list, show <id>, or explain <id>")
        fp.add_argument("finding_id", nargs="?", default=None, help="Finding ID (e.g. CW-NET-0001)")
        fp.add_argument("--target", "-t", type=str, help="Filter by target host")
        fp.add_argument("--severity", "-s", type=str, help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
        fp.add_argument("--status", type=str, help="Filter by status (OPEN, CONFIRMED, RESOLVED, etc.)")
        fp.add_argument("--cve", type=str, help="Filter by CVE identifier")

    # assets / asset
    for a_cmd in ["assets", "asset"]:
        ap = subparsers.add_parser(a_cmd, help="Discovered asset inventory and profiles")
        ap.add_argument("action", nargs="?", default="list", help="Action: list or show <id>")
        ap.add_argument("asset_id", nargs="?", default=None, help="Asset numeric ID")

    # tools / tool
    for tl_cmd in ["tools", "tool"]:
        tl_p = subparsers.add_parser(tl_cmd, help="Security tool adapter status and availability")
        tl_p.add_argument("action", nargs="?", default="list", choices=["list"], help="Action: list")

    # policy / policies
    for pol_cmd in ["policy", "policies"]:
        pol_p = subparsers.add_parser(pol_cmd, help="Security policy and rule profile inspection")
        pol_p.add_argument("action", nargs="?", default="show", choices=["show"], help="Action: show")

    # reports / report
    for rep_cmd in ["report", "reports"]:
        rep_p = subparsers.add_parser(rep_cmd, help="Generate or inspect multi-format security deliverables")
        rep_p.add_argument("action", nargs="?", default="list", choices=["list", "generate"], help="Action: list or generate")
        rep_p.add_argument("--target", "-t", type=str, help="Target name for report")
        rep_p.add_argument("--scan", type=str, help="Scan ID to generate reports for")
        rep_p.add_argument("--format", "-f", choices=["json", "csv", "html", "pdf", "txt"], help="Specific report format")

    # database
    db_p = subparsers.add_parser("database", help="Manage SQLite knowledge and evidence database")
    db_p.add_argument("action", nargs="?", default="status", choices=["status", "backup", "export", "search"], help="Action")
    db_p.add_argument("term", nargs="?", help="Search term (for search action)")

    # dashboard / serve
    for s_cmd in ["dashboard", "serve"]:
        srv_p = subparsers.add_parser(s_cmd, help="Launch CyberWolf Local Analyst Workstation & REST API")
        srv_p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
        srv_p.add_argument("--port", "-p", type=int, default=8080, help="Bind port (default: 8080)")

    # config
    cfg_p = subparsers.add_parser("config", help="View or update system configuration")
    cfg_p.add_argument("action", nargs="?", default="show", choices=["show", "set-mode"], help="Action: show or set-mode")
    cfg_p.add_argument("mode", nargs="?", help="Security mode (PASSIVE, SAFE_SCAN, ACTIVE_SCAN, CTF_AGGRESSIVE, LAB_MODE)")

    # Backward-compatible commands:
    # vuln
    vuln_p = subparsers.add_parser("vuln", help="Vulnerability assessment workflow")
    vuln_p.add_argument("--target", "-t", type=str, required=True, help="Target IP / Hostname / URL")
    vuln_p.add_argument("--severity", "-s", type=str, help="Filter severity (critical, high, medium, low)")

    # pentest
    pentest_p = subparsers.add_parser("pentest", help="Authorized penetration testing workflow")
    pentest_p.add_argument("--target", "-t", type=str, required=True, help="Target host")

    # web
    web_p = subparsers.add_parser("web", help="Web security scanner or launch dashboard server")
    web_p.add_argument("--target", "-t", type=str, help="Target URL for security assessment")
    web_p.add_argument("--serve", action="store_true", help="Launch web workstation server")
    web_p.add_argument("--port", "-p", type=int, default=8080, help="Bind port for server (default: 8080)")
    web_p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")

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

    # ai
    ai_p = subparsers.add_parser("ai", help="Query local AI security assistant")
    ai_p.add_argument("prompt", nargs="+", help="Security question or prompt")

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

    cmd = args.command

    if cmd == "doctor":
        handle_doctor()
    elif cmd == "status":
        handle_status()
    elif cmd == "demo":
        handle_demo()

    elif cmd in ["target", "targets"]:
        action = args.action
        target_name = args.target_name
        # Support 'cyberwolf target add 192.168.1.1' or 'cyberwolf target list'
        if action == "add":
            handle_targets(action="add", target=target_name, authorized=args.authorized, scope=args.scope)
        else:
            handle_targets(action="list")

    elif cmd == "scan":
        action = args.scan_action
        arg = args.scan_arg

        if not action and not args.target:
            handle_scan_list()
        elif action == "list":
            handle_scan_list()
        elif action == "show":
            if not arg:
                print("Error: Scan ID required. Example: cyberwolf scan show CW-SCN-20261006-001")
            else:
                handle_scan_show(arg)
        elif action == "cancel":
            if not arg:
                print("Error: Scan ID required. Example: cyberwolf scan cancel CW-SCN-20261006-001")
            else:
                handle_scan_cancel(arg)
        elif action == "network":
            target = args.target or arg
            if not target:
                print("Error: Target required. Example: cyberwolf scan network --target 127.0.0.1")
            else:
                handle_scan_network(target, ports=args.ports)
        else:
            # Action is the target itself (e.g. cyberwolf scan 127.0.0.1)
            target = args.target or action
            handle_scan_target(target=target, ports=args.ports, profile=args.profile)

    elif cmd in ["findings", "finding"]:
        action = args.action
        fid = args.finding_id
        if action == "show":
            handle_findings(action="show", finding_id=fid)
        elif action == "explain":
            handle_findings(action="explain", finding_id=fid)
        elif action and action.startswith("CW-"):
            # Direct ID shorthand: cyberwolf findings CW-NET-0001
            handle_findings(action="show", finding_id=action)
        else:
            handle_findings(action="list", target=args.target, severity=args.severity, status=args.status, cve=args.cve)

    elif cmd in ["assets", "asset"]:
        action = args.action
        aid = args.asset_id
        if action == "show":
            handle_assets(action="show", asset_id=aid)
        elif action and action.isdigit():
            # Shorthand: cyberwolf assets 1
            handle_assets(action="show", asset_id=action)
        else:
            handle_assets(action="list")

    elif cmd in ["tools", "tool"]:
        handle_tools_list()

    elif cmd in ["policy", "policies"]:
        handle_policy_show()

    elif cmd in ["report", "reports"]:
        handle_reports(action=args.action, target=args.target, scan_id=args.scan, report_format=args.format)

    elif cmd in ["dashboard", "serve"]:
        from app.web.server import start_web_server
        print(f"\n[+] Launching CYBERWOLF V2 Analyst Workstation on http://{args.host}:{args.port}")
        print("[+] Press Ctrl+C to stop.\n")
        start_web_server(host=args.host, port=args.port, blocking=True)

    elif cmd == "database":
        handle_database(action=args.action, term=args.term)

    elif cmd == "config":
        handle_config(action=args.action, mode=args.mode)

    elif cmd == "vuln":
        handle_vuln_scan(args.target, severity=args.severity)

    elif cmd == "pentest":
        handle_pentest(args.target)

    elif cmd == "web":
        if getattr(args, "serve", False) or not args.target:
            from app.web.server import start_web_server
            print(f"\n[+] Launching CYBERWOLF V2 Analyst Workstation on http://{args.host}:{args.port}")
            print("[+] Press Ctrl+C to stop.\n")
            start_web_server(host=args.host, port=args.port, blocking=True)
        else:
            handle_web_assessment(args.target)

    elif cmd == "sql-test":
        handle_sql_test(args.target, param=args.param)

    elif cmd == "monitor":
        handle_traffic_monitor(duration=args.duration)

    elif cmd == "ddos-monitor":
        handle_ddos_monitor(duration=args.duration)

    elif cmd == "ai":
        prompt_text = " ".join(args.prompt)
        handle_ai_prompt(prompt_text)

    elif cmd == "lab":
        handle_lab(action=args.action)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
