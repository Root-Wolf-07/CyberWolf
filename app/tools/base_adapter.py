"""CYBERWOLF Base Tool Adapter Interface."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from app.tools.detector import get_tool_detector

class BaseToolAdapter(ABC):
    """Abstract interface for all external and native security tool adapters."""
    
    def __init__(self, tool_name: str, candidate_binaries: List[str]):
        self.tool_name = tool_name
        self.candidate_binaries = candidate_binaries
        self.detector = get_tool_detector()
        self.binary_path = self.detector.find_binary(candidate_binaries)

    def is_available(self) -> bool:
        """Check if binary is installed and executable."""
        if not self.binary_path:
            self.binary_path = self.detector.find_binary(self.candidate_binaries)
        return self.binary_path is not None

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Construct structured argument list for subprocess execution."""
        pass

    @abstractmethod
    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        """Parse raw CLI output into normalized structured data and findings."""
        pass
