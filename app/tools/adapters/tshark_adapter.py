"""CYBERWOLF Network & Penetration Adapters (tshark, Metasploit, Hydra)."""

from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter

class TsharkAdapter(BaseToolAdapter):
    """Adapter for Wireshark tshark command line packet capture."""
    def __init__(self):
        super().__init__("tshark", ["tshark"])

    def build_command(self, interface: str = "any", duration: int = 10, packet_count: int = 100, **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("tshark binary not found.")
        return [
            self.binary_path, "-i", interface,
            "-a", f"duration:{duration}",
            "-c", str(packet_count),
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len"
        ]

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        packets = []
        for line in raw_output.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                packets.append({
                    "timestamp": parts[0],
                    "src": parts[1],
                    "dst": parts[2],
                    "protocol": parts[3],
                    "length": parts[4] if len(parts) > 4 else "0"
                })
        return {"success": exit_code == 0, "packets": packets, "count": len(packets)}


class MetasploitAdapter(BaseToolAdapter):
    """Adapter for Metasploit Framework controlled verification."""
    def __init__(self):
        super().__init__("Metasploit", ["msfconsole"])

    def build_command(self, resource_script: str, **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("msfconsole not found.")
        return [self.binary_path, "-q", "-r", resource_script]

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        return {"success": exit_code == 0, "raw_output": raw_output}


class HydraAdapter(BaseToolAdapter):
    """Adapter for THC-Hydra network logon tester."""
    def __init__(self):
        super().__init__("Hydra", ["hydra"])

    def build_command(self, target: str, service: str, userlist: str, passlist: str, port: Optional[int] = None, **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("hydra binary not found.")
        cmd = [self.binary_path, "-L", userlist, "-P", passlist, "-s", str(port) if port else ""]
        cmd = [c for c in cmd if c]
        cmd.extend([target, service])
        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        valid_creds = []
        for line in raw_output.splitlines():
            if "[login:" in line or "host:" in line:
                valid_creds.append(line.strip())
        return {"success": exit_code == 0, "creds": valid_creds, "raw_output": raw_output}
