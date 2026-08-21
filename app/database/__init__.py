"""CYBERWOLF Database Subsystem."""
from app.database.db_manager import DatabaseManager, get_db
from app.database.models import Finding, HostRecord, PortRecord, ScanRecord
from app.database.operations import (
    create_scan, complete_scan, upsert_host, upsert_port,
    create_finding, get_all_findings, get_findings_summary,
    save_tool_output, save_ai_analysis, get_database_status,
    search_database, export_database_json
)

__all__ = [
    "DatabaseManager",
    "get_db",
    "Finding",
    "HostRecord",
    "PortRecord",
    "ScanRecord",
    "create_scan",
    "complete_scan",
    "upsert_host",
    "upsert_port",
    "create_finding",
    "get_all_findings",
    "get_findings_summary",
    "save_tool_output",
    "save_ai_analysis",
    "get_database_status",
    "search_database",
    "export_database_json"
]
