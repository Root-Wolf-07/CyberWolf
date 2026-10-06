"""CYBERWOLF Base Tool Adapter Interface (V2).

Defines the contract for all external security tool integrations:
- Availability detection
- Argument validation & safety checks
- Deterministic argument array construction (shell=False)
- Subprocess execution with resource & timeout controls
- Output parsing (textual, JSON, XML)
- Finding normalization to canonical Finding models
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from app.tools.detector import get_tool_detector
from app.tools.runner import ToolRunner
from app.database.models import Finding
from app.core.exceptions import ToolExecutionError, ToolNotFoundError, ValidationError
from app.core.logger import get_logger

logger = get_logger()


class BaseToolAdapter(ABC):
    """Abstract interface for all security tool adapters."""

    def __init__(self, tool_name: str, candidate_binaries: List[str]):
        self.name = tool_name
        self.tool_name = tool_name
        self.candidate_binaries = candidate_binaries
        self.detector = get_tool_detector()
        self.binary_path = self.detector.find_binary(candidate_binaries)

    def is_available(self) -> bool:
        """Check if binary is installed and executable on the host system."""
        if not self.binary_path:
            self.binary_path = self.detector.find_binary(self.candidate_binaries)
        return self.binary_path is not None

    def validate_arguments(self, target: str, options: Optional[Dict[str, Any]] = None) -> bool:
        """Validate input arguments before command construction.
        
        Subclasses can override to add tool-specific constraints.
        """
        if not target or not isinstance(target, str):
            raise ValidationError(f"Target cannot be empty for tool '{self.name}'.")
        return True

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Construct structured argument list for subprocess execution (NEVER raw shell string)."""
        pass

    def execute(self, target: str, options: Optional[Dict[str, Any]] = None,
                timeout: int = 60, scan_id: Optional[str] = None) -> Tuple[int, str, str]:
        """Validate arguments, construct command, and safely execute via ToolRunner."""
        if not self.is_available():
            raise ToolNotFoundError(
                f"Tool '{self.name}' is not installed or not in system PATH. "
                f"Candidate binaries: {self.candidate_binaries}"
            )

        opts = options or {}
        self.validate_arguments(target, opts)
        cmd = self.build_command(target, **opts)

        return ToolRunner.execute(
            cmd_args=cmd,
            timeout=timeout,
            target=target,
            tool_name=self.name,
            scan_id=scan_id
        )

    @abstractmethod
    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        """Parse raw CLI output (JSON, text, XML) into structured data dictionary."""
        pass

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        """Convert parsed tool results into a list of canonical Finding domain objects."""
        findings = []
        raw_findings = parsed_results.get("findings", [])
        for f in raw_findings:
            if isinstance(f, Finding):
                findings.append(f)
            elif isinstance(f, dict):
                findings.append(Finding(
                    id=f.get("id") or f"CW-{self.name.upper()[:4]}-{target[:8]}",
                    target=target,
                    title=f.get("vulnerability") or f.get("title", f"{self.name} Finding"),
                    vulnerability=f.get("vulnerability") or f.get("title", f"{self.name} Finding"),
                    severity=f.get("severity", "INFO"),
                    confidence=f.get("confidence", "HIGH"),
                    evidence=f.get("evidence", ""),
                    port=f.get("port"),
                    protocol=f.get("protocol", "tcp"),
                    service=f.get("service"),
                    cve=f.get("cve"),
                    cwe=f.get("cwe"),
                    remediation=f.get("remediation"),
                    source_tool=self.name,
                    source_tools=[self.name]
                ))
        return findings
