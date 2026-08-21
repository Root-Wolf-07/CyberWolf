"""CYBERWOLF Database Models and Dataclasses."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime

@dataclass
class HostRecord:
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    status: str = "UP"
    id: Optional[int] = None
    asset_id: Optional[int] = None

@dataclass
class PortRecord:
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    host_id: Optional[int] = None
    id: Optional[int] = None

@dataclass
class Finding:
    id: str
    target: str
    vulnerability: str
    severity: str # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    evidence: str
    confidence: str # 'HIGH', 'MEDIUM', 'LOW'
    source_tool: str
    port: Optional[int] = None
    protocol: str = "tcp"
    service: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    remediation: Optional[str] = None
    created_at: Optional[str] = None
    status: str = "OPEN"
    verified: bool = False

@dataclass
class ScanRecord:
    id: str
    scan_type: str
    target: str
    mode: str
    status: str = "RUNNING"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    findings_count: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)
