"""CYBERWOLF Nmap Security Tool Adapter (V2).

Provides Nmap port scanning, service detection, and OS fingerprinting:
- Strict argument validation (ports, targets)
- Safe argument array construction
- Textual and structured output parsing
- Canonical Finding normalization
"""

import re
import uuid
from typing import Dict, List, Any, Optional
from app.tools.base_adapter import BaseToolAdapter
from app.database.models import Finding, SeverityLevel, ConfidenceLevel
from app.security.sanitizer import sanitize_target, sanitize_ports
from app.core.exceptions import ToolNotFoundError, ValidationError


class NmapAdapter(BaseToolAdapter):
    """Adapter for Nmap network mapper."""

    def __init__(self):
        super().__init__("Nmap", ["nmap"])

    def validate_arguments(self, target: str, options: Optional[Dict[str, Any]] = None) -> bool:
        """Validate target and optional port specifications."""
        super().validate_arguments(target, options)
        clean_target = sanitize_target(target)
        opts = options or {}
        if opts.get("ports"):
            sanitize_ports(str(opts["ports"]))
        return True

    def build_command(self, target: str, ports: Optional[str] = None,
                      scan_type: str = "fast", **kwargs) -> List[str]:
        if not self.is_available():
            raise ToolNotFoundError("Nmap executable not found on system PATH.")

        clean_target = sanitize_target(target)
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
            clean_ports = sanitize_ports(str(ports))
            cmd.extend(["-p", clean_ports])

        cmd.append(clean_target)
        return cmd

    def parse_output(self, raw_output: str, exit_code: int = 0) -> Dict[str, Any]:
        """Parse Nmap output (XML or standard text) into structured host and port dictionaries."""
        hosts = []
        findings_data = []

        if "<nmaprun" in raw_output:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(raw_output)
                for host_el in root.findall("host"):
                    addr_el = host_el.find("address")
                    ip = addr_el.get("addr") if addr_el is not None else "127.0.0.1"
                    h_info = {"ip": ip, "hostname": None, "ports": []}
                    for port_el in host_el.findall(".//port"):
                        port_id = int(port_el.get("portid"))
                        proto = port_el.get("protocol", "tcp")
                        svc_el = port_el.find("service")
                        svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                        prod = svc_el.get("product", "") if svc_el is not None else ""
                        ver = svc_el.get("version", "") if svc_el is not None else ""
                        h_info["ports"].append({
                            "port": port_id, "protocol": proto, "state": "open",
                            "service": svc_name, "version": f"{prod} {ver}".strip()
                        })
                    hosts.append(h_info)
                return {
                    "success": True,
                    "hosts": hosts,
                    "target": hosts[0]["ip"] if hosts else None,
                    "raw_output": raw_output
                }
            except Exception as e:
                logger.debug(f"XML parse fallback: {e}")

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

                    # Identify high-risk exposed services
                    if state == "open" and port_num in [21, 23, 3389, 445, 1433, 3306, 5432, 27017, 6379, 8080]:
                        sev = "HIGH" if port_num in [21, 23, 445, 6379, 27017] else "MEDIUM"
                        findings_data.append({
                            "vulnerability": f"Exposed Sensitive Service ({service}) on Port {port_num}",
                            "severity": sev,
                            "confidence": "HIGH",
                            "evidence": f"Port {port_num}/{proto} is OPEN running {service} {version}".strip(),
                            "port": port_num,
                            "protocol": proto,
                            "service": service,
                            "remediation": f"Restrict port {port_num} to authorized IP ranges via firewall or disable public listening."
                        })

        if current_host:
            hosts.append(current_host)

        return {
            "success": exit_code == 0,
            "hosts": hosts,
            "findings": findings_data,
            "raw_output": raw_output
        }

    def normalize_results(self, parsed_results: Dict[str, Any], target: str) -> List[Finding]:
        """Normalize parsed Nmap findings into canonical Finding models."""
        findings = []
        seen_ports = set()
        for f in parsed_results.get("findings", []):
            finding_id = f"CW-NMAP-{uuid.uuid4().hex[:6].upper()}"
            p = f.get("port")
            if p:
                seen_ports.add(p)
            findings.append(Finding(
                id=finding_id,
                target=target,
                title=f.get("vulnerability", "Exposed Port Finding"),
                vulnerability=f.get("vulnerability", "Exposed Port Finding"),
                severity=f.get("severity", "MEDIUM"),
                confidence="HIGH",
                category="network_exposure",
                evidence=f.get("evidence", ""),
                port=f.get("port"),
                protocol=f.get("protocol", "tcp"),
                service=f.get("service"),
                remediation=f.get("remediation"),
                source_tool="Nmap",
                source_tools=["Nmap"]
            ))

        for h in parsed_results.get("hosts", []):
            for p in h.get("ports", []):
                p_num = p.get("port")
                if p_num in seen_ports:
                    continue
                svc = p.get("service", "unknown")
                ver = p.get("version", "")
                findings.append(Finding(
                    id=f"CW-NMAP-{uuid.uuid4().hex[:6].upper()}",
                    target=target or h.get("ip"),
                    title=f"Open Port {p_num}/{p.get('protocol', 'tcp')} ({svc})",
                    vulnerability=f"Open Port {p_num}/{p.get('protocol', 'tcp')} ({svc})",
                    severity=SeverityLevel.INFO if p_num not in [21, 23, 445, 3306, 6379] else SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    category="network_exposure",
                    evidence=f"Service: {svc} {ver}".strip(),
                    port=p_num,
                    protocol=p.get("protocol", "tcp"),
                    service=svc,
                    remediation=f"Restrict port {p_num} access if unneeded.",
                    source_tool="Nmap",
                    source_tools=["Nmap"]
                ))
        return findings
