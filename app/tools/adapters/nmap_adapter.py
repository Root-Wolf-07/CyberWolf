"""CYBERWOLF Nmap Security Tool Adapter."""

import re
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter
from app.database.models import Finding

class NmapAdapter(BaseToolAdapter):
    """Adapter for Nmap network mapper."""
    def __init__(self):
        super().__init__("Nmap", ["nmap"])

    def build_command(self, target: str, ports: Optional[str] = None, scan_type: str = "fast", **kwargs) -> List[str]:
        if not self.is_available():
            raise FileNotFoundError("Nmap executable not found on system.")

        cmd = [self.binary_path]
        if scan_type == "fast":
            cmd.extend(["-F", "-T4"])
        elif scan_type == "service":
            cmd.extend(["-sV", "-T4"])
        elif scan_type == "comprehensive":
            cmd.extend(["-sV", "-sC", "-O", "-T4"])
        else:
            cmd.extend(["-T4"])

        if ports:
            cmd.extend(["-p", ports])
        
        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> Dict[str, Any]:
        """Parse Nmap textual output into structured host and port dictionaries."""
        hosts = []
        findings = []
        current_host = None
        
        # Regex patterns
        host_ip_re = re.compile(r'Nmap scan report for (?:([a-zA-Z0-9\.\-]+) \()?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-fA-F0-9:]+)\)?')
        port_re = re.compile(r'([0-9]+)/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?')

        for line in raw_output.splitlines():
            h_match = host_ip_re.search(line)
            if h_match:
                if current_host:
                    hosts.append(current_host)
                hostname = h_match.group(1)
                ip = h_match.group(2)
                current_host = {
                    "ip": ip,
                    "hostname": hostname,
                    "ports": []
                }
                continue

            if current_host:
                p_match = port_re.search(line)
                if p_match:
                    port_num = int(p_match.group(1))
                    proto = p_match.group(2)
                    state = p_match.group(3)
                    service = p_match.group(4)
                    version = (p_match.group(5) or "").strip()
                    
                    port_entry = {
                        "port": port_num,
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "version": version
                    }
                    current_host["ports"].append(port_entry)
                    
                    # Check for risky exposed ports
                    if state == "open" and port_num in [21, 23, 3389, 445, 1433, 3306, 5432, 27017, 6379, 8080]:
                        sev = "HIGH" if port_num in [21, 23, 445, 6379, 27017] else "MEDIUM"
                        findings.append({
                            "vulnerability": f"Exposed Sensitive Service ({service}) on Port {port_num}",
                            "severity": sev,
                            "confidence": "HIGH",
                            "evidence": f"Port {port_num}/{proto} is OPEN running {service} {version}",
                            "port": port_num,
                            "service": service,
                            "remediation": f"Restrict port {port_num} to authorized IP ranges via firewall or disable public listening."
                        })

        if current_host:
            hosts.append(current_host)

        return {
            "success": exit_code == 0,
            "hosts": hosts,
            "findings": findings,
            "raw_output": raw_output
        }
