"""Unit tests for CYBERWOLF CLI Argument Parsing & Command Routing."""

import pytest
from app.main import build_parser


def test_cli_parser_commands():
    """Verify all subcommands and parameters are defined in parser."""
    parser = build_parser()

    # doctor
    args = parser.parse_args(["doctor"])
    assert args.command == "doctor"

    # status
    args = parser.parse_args(["status"])
    assert args.command == "status"

    # target list
    args = parser.parse_args(["target", "list"])
    assert args.command == "target"
    assert args.action == "list"

    # target add
    args = parser.parse_args(["target", "add", "192.168.1.100"])
    assert args.command == "target"
    assert args.action == "add"
    assert args.target_name == "192.168.1.100"

    # scan positional
    args = parser.parse_args(["scan", "127.0.0.1", "--ports", "80,443"])
    assert args.command == "scan"
    assert args.scan_action == "127.0.0.1"
    assert args.ports == "80,443"

    # scan list
    args = parser.parse_args(["scan", "list"])
    assert args.command == "scan"
    assert args.scan_action == "list"

    # findings list
    args = parser.parse_args(["findings", "list", "--severity", "HIGH"])
    assert args.command == "findings"
    assert args.severity == "HIGH"

    # assets list
    args = parser.parse_args(["assets", "list"])
    assert args.command == "assets"

    # tools list
    args = parser.parse_args(["tools", "list"])
    assert args.command == "tools"

    # policy show
    args = parser.parse_args(["policy", "show"])
    assert args.command == "policy"

    # dashboard
    args = parser.parse_args(["dashboard", "--port", "9000"])
    assert args.command == "dashboard"
    assert args.port == 9000
