"""CYBERWOLF ffuf and Gobuster Web Fuzzing Adapters (V2).

Provides fast web directory and endpoint discovery:
- URL and wordlist validation (path traversal prevention)
- Safe argument list construction
- JSON output parsing
- Canonical Finding normalization
"""

import json
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter
from app.database.models import Finding
from app.security.sanitizer import sanitize_target
from app.core.exceptions import ToolNotFoundError, ValidationError


class FfufAdapter(BaseToolAdapter):
    """Adapter for ffuf web fuzzer."""

    def __init__(self):
        super().__init__("ffuf", ["ffuf"])

    def validate_arguments(self, target: str, options: Optional[Dict[str, Any]] = None) -> bool:
        super().validate_arguments(target, options)
        clean_target = sanitize_target(target)
        opts = options or {}
        if not opts.get("wordlist"):
            raise ValidationError("Wordlist path is required for ffuf.")
        wl_path = Path(str(opts["wordlist"])).resolve()
        if not wl_path.exists():
            raise ValidationError(f"Wordlist not found at {wl_path}")
        return True

    def build_command(self, target_url: str, wordlist: str, **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("ffuf binary not found on system PATH.")

        clean_url = sanitize_target(target_url)
        url = clean_url if "FUZZ" in clean_url else f"{clean_url.rstrip('/')}/FUZZ"
        wl = str(Path(wordlist).resolve())

        return [self.binary_path, "-u", url, "-w", wl, "-o", "-", "-of", "json", "-s"]

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
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

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        findings = []
        for ep in parsed_results.get("endpoints", []):
            status_code = ep.get("status")
            if status_code in [200, 301, 302, 401, 403]:
                finding_id = f"CW-FFUF-{uuid.uuid4().hex[:6].upper()}"
                url_str = (ep.get("url") or "").lower()
                if any(s in url_str for s in [".env", "config", "backup", "secret"]):
                    sev = "HIGH"
                elif any(s in url_str for s in ["admin", "login", "api"]):
                    sev = "MEDIUM"
                else:
                    sev = "LOW" if status_code == 200 else "INFO"
                findings.append(Finding(
                    id=finding_id,
                    target=target,
                    title=f"Discovered Endpoint: {ep.get('url')} (HTTP {status_code})",
                    vulnerability=f"Discovered Endpoint: {ep.get('url')}",
                    severity=sev,
                    confidence="HIGH",
                    category="information_disclosure",
                    evidence=f"Endpoint responded with HTTP {status_code}, length {ep.get('length')} bytes.",
                    source_tool="ffuf",
                    source_tools=["ffuf"],
                    remediation="Verify whether this endpoint should be publicly accessible."
                ))
        return findings


class GobusterAdapter(BaseToolAdapter):
    """Adapter for Gobuster directory/vhost enumeration."""

    def __init__(self):
        super().__init__("Gobuster", ["gobuster"])

    def validate_arguments(self, target: str, options: Optional[Dict[str, Any]] = None) -> bool:
        super().validate_arguments(target, options)
        clean_target = sanitize_target(target)
        opts = options or {}
        if not opts.get("wordlist"):
            raise ValidationError("Wordlist path is required for Gobuster.")
        return True

    def build_command(self, target_url: str, wordlist: str, mode: str = "dir", **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("gobuster binary not found on system PATH.")

        clean_url = sanitize_target(target_url)
        return [self.binary_path, mode, "-u", clean_url, "-w", wordlist, "-q"]

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        discovered = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line:
                discovered.append(line)
        return {"success": exit_code == 0, "discovered": discovered, "raw_output": raw_output}

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        findings = []
        for line in parsed_results.get("discovered", []):
            finding_id = f"CW-GOBU-{uuid.uuid4().hex[:6].upper()}"
            findings.append(Finding(
                id=finding_id,
                target=target,
                title=f"Gobuster Discovered Endpoint: {line}",
                vulnerability=f"Gobuster Discovered Endpoint: {line}",
                severity="INFO",
                confidence="HIGH",
                category="reconnaissance",
                evidence=f"Discovered path: {line}",
                source_tool="Gobuster",
                source_tools=["Gobuster"]
            ))
        return findings
