"""CYBERWOLF CLI Subcommands Package (V2)."""

from app.cli.commands.cmd_doctor import handle_doctor, handle_status
from app.cli.commands.cmd_scan import (
    handle_scan_network,
    handle_scan_target,
    handle_scan_list,
    handle_scan_show,
    handle_scan_cancel
)
from app.cli.commands.cmd_vuln import handle_vuln_scan
from app.cli.commands.cmd_pentest import handle_pentest
from app.cli.commands.cmd_web import handle_web_assessment
from app.cli.commands.cmd_sql import handle_sql_test
from app.cli.commands.cmd_monitor import handle_traffic_monitor, handle_ddos_monitor
from app.cli.commands.cmd_reports import handle_reports
from app.cli.commands.cmd_ai import handle_ai_prompt
from app.cli.commands.cmd_database import handle_database
from app.cli.commands.cmd_config import handle_config
from app.cli.commands.cmd_demo import handle_demo
from app.cli.commands.cmd_lab import handle_lab
from app.cli.commands.cmd_targets import handle_targets
from app.cli.commands.cmd_findings import handle_findings
from app.cli.commands.cmd_assets import handle_assets
from app.cli.commands.cmd_tools import handle_tools_list
from app.cli.commands.cmd_policy import handle_policy_show

__all__ = [
    "handle_doctor",
    "handle_status",
    "handle_scan_network",
    "handle_scan_target",
    "handle_scan_list",
    "handle_scan_show",
    "handle_scan_cancel",
    "handle_vuln_scan",
    "handle_pentest",
    "handle_web_assessment",
    "handle_sql_test",
    "handle_traffic_monitor",
    "handle_ddos_monitor",
    "handle_reports",
    "handle_ai_prompt",
    "handle_database",
    "handle_config",
    "handle_demo",
    "handle_lab",
    "handle_targets",
    "handle_findings",
    "handle_assets",
    "handle_tools_list",
    "handle_policy_show"
]
