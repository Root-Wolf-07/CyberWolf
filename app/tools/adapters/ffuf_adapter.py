"""CYBERWOLF ffuf and Gobuster Web Fuzzing Adapters."""

import json
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter

class FfufAdapter(BaseToolAdapter):
    """Adapter for ffuf web fuzzer."""
    def __init__(self):
        super().__init__("ffuf", ["ffuf"])

    def build_command(self, target_url: str, wordlist: str, **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("ffuf binary not found.")
        # Target must contain FUZZ placeholder
        url = target_url if "FUZZ" in target_url else f"{target_url.rstrip('/')}/FUZZ"
        return [self.binary_path, "-u", url, "-w", wordlist, "-o", "-", "-of", "json", "-s"]

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        endpoints = []
        try:
            data = json.loads(raw_output)
            for res in data.get("results", []):
                endpoints.append({
                    "url": res.get("url"),
                    "status": res.get("status"),
                    "length": res.get("length"),
                    "words": res.get("words")
                })
        except Exception:
            pass
        return {"success": exit_code == 0, "endpoints": endpoints, "raw_output": raw_output}


class GobusterAdapter(BaseToolAdapter):
    """Adapter for Gobuster directory/vhost enumeration."""
    def __init__(self):
        super().__init__("Gobuster", ["gobuster"])

    def build_command(self, target_url: str, wordlist: str, mode: str = "dir", **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("gobuster binary not found.")
        return [self.binary_path, mode, "-u", target_url, "-w", wordlist, "-q"]

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        discovered = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line:
                discovered.append(line)
        return {"success": exit_code == 0, "discovered": discovered, "raw_output": raw_output}
