"""CYBERWOLF Network Packet Capture Adapters (TShark, Metasploit, Hydra) (V2).

Provides controlled network packet inspection and protocol analysis:
- Execution limits & parameter validation (duration, packet count caps)
- Structured argument list construction
- Field parsing and anomaly extraction
- Canonical Finding normalization
"""

import uuid
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter
from app.database.models import Finding
from app.core.exceptions import ToolNotFoundError, ValidationError


class TsharkAdapter(BaseToolAdapter):
    """Adapter for Wireshark tshark command line packet capture."""

    def __init__(self):
        super().__init__("tshark", ["tshark"])

    def validate_arguments(self, target: str, options: Optional[Dict[str, Any]] = None) -> bool:
        opts = options or {}
        duration = int(opts.get("duration", 10))
        if duration < 1 or duration > 300:
            raise ValidationError(f"TShark capture duration must be between 1 and 300 seconds, got {duration}.")
        packet_count = int(opts.get("packet_count", 100))
        if packet_count < 1 or packet_count > 10000:
            raise ValidationError(f"Packet count must be between 1 and 10000, got {packet_count}.")
        return True

    def build_command(self, interface: str = "any", duration: int = 10,
                      packet_count: int = 100, **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("tshark binary not found on system PATH.")

        clean_duration = min(max(int(duration), 1), 300)
        clean_count = min(max(int(packet_count), 1), 10000)

        return [
            self.binary_path, "-i", str(interface),
            "-a", f"duration:{clean_duration}",
            "-c", str(clean_count),
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len"
        ]

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        packets = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                packets.append({
                    "timestamp": parts[0],
                    "src": parts[1],
                    "dst": parts[2],
                    "protocol": parts[3].upper(),
                    "length": parts[4] if len(parts) > 4 else "0"
                })
            else:
                tokens = line.split()
                if len(tokens) >= 5:
                    proto = next((t for t in tokens if t.upper() in ["HTTP", "FTP", "TELNET", "DNS", "TCP", "UDP"]), "TCP")
                    packets.append({
                        "timestamp": tokens[1] if len(tokens) > 1 else "0",
                        "src": tokens[2] if len(tokens) > 2 else "127.0.0.1",
                        "dst": tokens[4] if len(tokens) > 4 else "127.0.0.1",
                        "protocol": proto.upper(),
                        "length": "64"
                    })
        return {"success": exit_code == 0, "packets": packets, "count": len(packets)}

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        findings = []
        packets = parsed_results.get("packets", [])
        # Check for unencrypted protocols in packet stream (e.g. Telnet, Plain HTTP, FTP)
        unencrypted = [p for p in packets if p.get("protocol") in ["TELNET", "FTP", "HTTP"]]
        if unencrypted:
            finding_id = f"CW-TSHARK-{uuid.uuid4().hex[:6].upper()}"
            sample = unencrypted[0]
            findings.append(Finding(
                id=finding_id,
                target=target,
                title=f"Unencrypted Protocol Observed in Traffic ({sample.get('protocol')})",
                vulnerability=f"Cleartext Network Traffic ({sample.get('protocol')})",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="network_traffic",
                evidence=f"Observed {len(unencrypted)} packets of cleartext protocol {sample.get('protocol')} between {sample.get('src')} and {sample.get('dst')}.",
                remediation="Migrate cleartext network services to encrypted protocols (TLS, SSH, SFTP).",
                source_tool="TShark",
                source_tools=["TShark"]
            ))
        return findings


class MetasploitAdapter(BaseToolAdapter):
    """Adapter for Metasploit Framework controlled verification."""

    def __init__(self):
        super().__init__("Metasploit", ["msfconsole"])

    def build_command(self, resource_script: str, **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("msfconsole not found on system PATH.")
        return [self.binary_path, "-q", "-r", str(resource_script)]

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        return {"success": exit_code == 0, "raw_output": raw_output}

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        return []


class HydraAdapter(BaseToolAdapter):
    """Adapter for THC-Hydra network logon tester."""

    def __init__(self):
        super().__init__("Hydra", ["hydra"])

    def build_command(self, target: str, service: str, userlist: str, passlist: str,
                      port: Optional[int] = None, **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("hydra binary not found on system PATH.")
        cmd = [self.binary_path, "-L", str(userlist), "-P", str(passlist)]
        if port:
            cmd.extend(["-s", str(port)])
        cmd.extend([str(target), str(service)])
        return cmd

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        valid_creds = []
        for line in raw_output.splitlines():
            if "[login:" in line or "host:" in line:
                valid_creds.append(line.strip())
        return {"success": exit_code == 0, "creds": valid_creds, "raw_output": raw_output}

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        findings = []
        creds = parsed_results.get("creds", [])
        if creds:
            findings.append(Finding(
                id=f"CW-HYDRA-{uuid.uuid4().hex[:6].upper()}",
                target=target,
                title="Weak / Default Credentials Identified",
                vulnerability="Weak Authentication Credentials",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="authentication",
                evidence=f"Credential match found during authorized logon verification.",
                remediation="Enforce strong passphrase complexity baselines and multi-factor authentication (MFA).",
                source_tool="Hydra",
                source_tools=["Hydra"]
            ))
        return findings
