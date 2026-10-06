"""CYBERWOLF Canonical Domain Models & Data Schemas (V2).

Defines strongly-typed domain representations for:
- Asset
- Scan
- Finding
- Evidence
- ToolRun
- Report
- AuditEvent
- Policy
- HostRecord / PortRecord (backward compatibility)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
import json
import uuid


class SeverityLevel:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    ALL = [INFO, LOW, MEDIUM, HIGH, CRITICAL]

    @classmethod
    def normalize(cls, val: Optional[str]) -> str:
        if not val:
            return cls.INFO
        upper = val.strip().upper()
        return upper if upper in cls.ALL else cls.INFO


class ConfidenceLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"

    ALL = [LOW, MEDIUM, HIGH, CONFIRMED]

    @classmethod
    def normalize(cls, val: Optional[str]) -> str:
        if not val:
            return cls.MEDIUM
        upper = val.strip().upper()
        return upper if upper in cls.ALL else cls.MEDIUM


class FindingStatus:
    NEW = "NEW"
    OPEN = "OPEN"  # Backward compatibility
    TRIAGED = "TRIAGED"
    CONFIRMED = "CONFIRMED"
    REMEDIATION_REQUIRED = "REMEDIATION_REQUIRED"
    RETEST_PENDING = "RETEST_PENDING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DUPLICATE = "DUPLICATE"
    ACCEPTED_RISK = "ACCEPTED_RISK"

    ALL = [
        NEW, OPEN, TRIAGED, CONFIRMED, REMEDIATION_REQUIRED,
        RETEST_PENDING, RESOLVED, FALSE_POSITIVE, DUPLICATE, ACCEPTED_RISK
    ]

    @classmethod
    def normalize(cls, val: Optional[str]) -> str:
        if not val:
            return cls.OPEN
        upper = val.strip().upper().replace(" ", "_")
        return upper if upper in cls.ALL else cls.OPEN


class EvidenceType:
    NETWORK_SCAN = "NETWORK_SCAN"
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    SERVICE_DETECTION = "SERVICE_DETECTION"
    CONFIGURATION = "CONFIGURATION"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    PACKET_METADATA = "PACKET_METADATA"
    SOURCE_CODE = "SOURCE_CODE"
    MANUAL_OBSERVATION = "MANUAL_OBSERVATION"

    ALL = [
        NETWORK_SCAN, HTTP_REQUEST, HTTP_RESPONSE, SERVICE_DETECTION,
        CONFIGURATION, TOOL_OUTPUT, PACKET_METADATA, SOURCE_CODE, MANUAL_OBSERVATION
    ]


class RetestResult:
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    PENDING = "PENDING"

    ALL = [PASS, FAIL, INCONCLUSIVE, PENDING]


class ExploitabilityLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"

    ALL = [LOW, MEDIUM, HIGH, CONFIRMED]


class ScanStatus:
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"

    ALL = [QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED, PARTIAL]

    @classmethod
    def normalize(cls, val: Optional[str]) -> str:
        if not val:
            return cls.RUNNING
        upper = val.strip().upper()
        return upper if upper in cls.ALL else cls.RUNNING


@dataclass
class Asset:
    """Represents a discovered network or web asset."""
    asset_id: str
    target_identifier: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    operating_system: Optional[str] = None
    device_type: Optional[str] = None
    asset_type: str = "ip"  # 'ip', 'cidr', 'domain', 'url'
    open_ports: List[int] = field(default_factory=list)
    discovered_services: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    description: Optional[str] = None
    id: Optional[int] = None

    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = self.first_seen

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostRecord:
    """Backward-compatible host record representation."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    status: str = "UP"
    id: Optional[int] = None
    asset_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PortRecord:
    """Backward-compatible port record representation."""
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    host_id: Optional[int] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Canonical internal data model for all security findings (BDIE V2)."""
    id: str
    target: str
    vulnerability: str = ""
    title: str = ""
    description: str = ""
    severity: str = SeverityLevel.INFO
    confidence: str = ConfidenceLevel.HIGH
    category: str = "general"
    asset_id: Optional[int] = None
    host: Optional[str] = None
    host_id: Optional[int] = None
    port: Optional[int] = None
    protocol: str = "tcp"
    service: Optional[str] = None
    service_version: Optional[str] = None
    cve: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    owasp_category: Optional[str] = None
    cvss: Optional[float] = None
    evidence: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    source_tool: str = ""
    source_tools: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    resolved_at: Optional[str] = None
    last_verified: Optional[str] = None
    verified: bool = False
    status: str = FindingStatus.OPEN
    # BDIE Exact Location
    url: Optional[str] = None
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    component: Optional[str] = None
    technology: Optional[str] = None
    config_area: Optional[str] = None
    config_setting: Optional[str] = None
    config_observed: Optional[str] = None
    config_expected: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    source_function: Optional[str] = None
    source_commit: Optional[str] = None
    # BDIE Investigation & Behavior
    observed_behavior: Optional[str] = None
    verified_behavior: Optional[str] = None
    potential_impact: Optional[str] = None
    exploitability: Optional[str] = None
    exploitability_level: Optional[str] = None
    exploit_prerequisites: Optional[str] = None
    exploit_limitations: Optional[str] = None
    # BDIE Retest & Traceability
    retest_status: Optional[str] = None
    retest_result: Optional[str] = None
    verification_procedure: Optional[str] = None
    scan_id: Optional[str] = None
    tool_run_id: Optional[str] = None

    def __post_init__(self):
        if self.exploitability_level and not self.exploitability:
            self.exploitability = self.exploitability_level
        elif self.exploitability and not self.exploitability_level:
            self.exploitability_level = self.exploitability
        # Synchronize title and vulnerability fields for full backward compatibility
        if not self.title and self.vulnerability:
            self.title = self.vulnerability
        elif not self.vulnerability and self.title:
            self.vulnerability = self.title
        elif not self.title and not self.vulnerability:
            self.title = "Security Finding"
            self.vulnerability = self.title

        if not self.description:
            self.description = self.evidence or self.title

        # Synchronize source tool & list
        if self.source_tool and not self.source_tools:
            self.source_tools = [self.source_tool]
        elif self.source_tools and not self.source_tool:
            self.source_tool = self.source_tools[0]
        elif not self.source_tool and not self.source_tools:
            self.source_tool = "CYBERWOLF Engine"
            self.source_tools = [self.source_tool]

        # Normalize CVE representation
        if self.cve and not self.cve_ids:
            self.cve_ids = [c.strip() for c in self.cve.split(",") if c.strip()]
        elif self.cve_ids and not self.cve:
            self.cve = ", ".join(self.cve_ids)

        # Normalize CWE representation
        if self.cwe and not self.cwe_ids:
            self.cwe_ids = [c.strip() for c in self.cwe.split(",") if c.strip()]
        elif self.cwe_ids and not self.cwe:
            self.cwe = ", ".join(self.cwe_ids)

        # Infer host if omitted
        if not self.host and self.target:
            self.host = self.target

        # Timestamps
        now_iso = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = now_iso
        if not self.first_seen:
            self.first_seen = self.created_at
        if not self.last_seen:
            self.last_seen = now_iso
        if not self.updated_at:
            self.updated_at = self.last_seen

        # Default observed behavior if not specified
        if not self.observed_behavior and self.evidence:
            self.observed_behavior = self.evidence

        # Normalization
        self.severity = SeverityLevel.normalize(self.severity)
        self.confidence = ConfidenceLevel.normalize(self.confidence)
        self.status = FindingStatus.normalize(self.status)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["vulnerability"] = self.vulnerability
        d["title"] = self.title
        d["cve"] = self.cve
        d["cwe"] = self.cwe
        d["source_tool"] = self.source_tool
        return d

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)


@dataclass
class Evidence:
    """Structured, cryptographically verifiable evidence model (BDIE V2)."""
    id: str
    target: str
    tool_name: str
    output_excerpt: str
    command_used: Optional[str] = None
    finding_id: Optional[str] = None
    scan_id: Optional[str] = None
    timestamp: Optional[str] = None
    raw_result_path: Optional[str] = None
    packet_metadata: Dict[str, Any] = field(default_factory=dict)
    http_metadata: Dict[str, Any] = field(default_factory=dict)
    scanner_result: Dict[str, Any] = field(default_factory=dict)
    hash_sha256: Optional[str] = None
    evidence_type: str = EvidenceType.TOOL_OUTPUT
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    observed_data: Dict[str, Any] = field(default_factory=dict)
    tool_run_id: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingRetest:
    """Record of a safe, authorized vulnerability re-test verification."""
    id: str
    finding_id: str
    scan_id: Optional[str] = None
    evidence_id: Optional[str] = None
    test_type: str = "PROBE_REVERIFICATION"
    result: str = RetestResult.PENDING  # PASS, FAIL, INCONCLUSIVE
    details: str = ""
    retested_by: str = "CYBERWOLF BDIE"
    timestamp: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        self.result = self.result.upper() if self.result else RetestResult.PENDING

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingStatusHistory:
    """Audit log entry for finding status transitions."""
    id: Optional[int]
    finding_id: str
    old_status: str
    new_status: str
    reason: Optional[str] = None
    changed_by: str = "ANALYST"
    changed_at: Optional[str] = None

    def __post_init__(self):
        if not self.changed_at:
            self.changed_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolRun:
    """Record of an individual tool invocation within a scan."""
    id: str
    tool_name: str
    command_line: str
    exit_code: int = 0
    scan_id: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_sec: float = 0.0
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    raw_output_path: Optional[str] = None
    hash_sha256: Optional[str] = None
    status: str = "COMPLETED"  # 'COMPLETED', 'FAILED', 'TIMED_OUT'

    def __post_init__(self):
        if not self.start_time:
            self.start_time = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanRecord:
    """Session abstraction representing an end-to-end assessment run."""
    id: str
    scan_type: str
    target: str
    mode: str = "SAFE_SCAN"
    status: str = ScanStatus.RUNNING
    authorization_status: str = "AUTHORIZED"
    policy_applied: str = "SAFE_SCAN"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    tools_executed: List[str] = field(default_factory=list)
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    report_locations: Dict[str, str] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.start_time:
            self.start_time = datetime.now().isoformat()
        self.status = ScanStatus.normalize(self.status)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Scan alias for standard naming
Scan = ScanRecord


@dataclass
class ReportRecord:
    """Canonical model for generated security assessment reports."""
    id: str
    title: str
    report_format: str  # 'HTML', 'JSON', 'CSV', 'PDF', 'TXT', 'MULTI_FORMAT'
    file_path: str
    target: str
    scan_id: Optional[str] = None
    findings_count: int = 0
    summary_text: Optional[str] = None
    created_at: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


Report = ReportRecord


@dataclass
class AuditEvent:
    """Security event record for tamper-evident audit trails."""
    event_type: str
    user_action: str
    decision: str  # 'APPROVED', 'REJECTED', 'PROCEEDED', 'CONFIRMED'
    target: Optional[str] = None
    tool_name: Optional[str] = None
    mode: Optional[str] = None
    details: Optional[str] = None
    timestamp: Optional[str] = None
    id: Optional[int] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Policy:
    """Security assessment policy engine constraints."""
    name: str = "SAFE_SCAN"
    allow_network_scan: bool = True
    allow_web_scan: bool = True
    allow_packet_capture: bool = True
    allow_bruteforce: bool = False
    allow_destructive: bool = False
    max_scan_duration: int = 900
    allowed_tools: List[str] = field(default_factory=list)
    rate_limit_delay_ms: int = 50
    max_concurrent_connections: int = 20

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
