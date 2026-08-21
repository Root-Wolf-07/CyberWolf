"""CYBERWOLF Tools Discovery and Execution Package."""
from app.tools.detector import ToolDetector, get_tool_detector
from app.tools.base_adapter import BaseToolAdapter
from app.tools.runner import ToolRunner
from app.tools.adapters import (
    NmapAdapter, NucleiAdapter, NiktoAdapter, FfufAdapter,
    GobusterAdapter, TsharkAdapter, MetasploitAdapter, HydraAdapter
)

__all__ = [
    "ToolDetector",
    "get_tool_detector",
    "BaseToolAdapter",
    "ToolRunner",
    "NmapAdapter",
    "NucleiAdapter",
    "NiktoAdapter",
    "FfufAdapter",
    "GobusterAdapter",
    "TsharkAdapter",
    "MetasploitAdapter",
    "HydraAdapter"
]
