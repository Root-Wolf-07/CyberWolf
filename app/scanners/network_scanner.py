"""CYBERWOLF Network Scanner Engine.

Integrates Nmap with native high-concurrency Python socket scanning,
banner grabbing, and risk scoring.
"""

import socket
import concurrent.futures
from typing import Dict, List, Any, Optional
from datetime import datetime
from app.tools.adapters.nmap_adapter import NmapAdapter
from app.tools.runner import ToolRunner
from app.database.operations import create_scan, complete_scan, upsert_host, upsert_port, create_finding
from app.database.models import Finding
from app.core.logger import get_logger, audit_log

logger = get_logger()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017
]

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb"
}

class NetworkScanner:
    """Network scanner supporting both Nmap and native socket fallback."""
    
    def __init__(self):
        self.nmap_adapter = NmapAdapter()

    def scan(self, target: str, port_spec: Optional[str] = None, scan_type: str = "fast") -> Dict[str, Any]:
        """Execute network assessment using Nmap if available, otherwise native probe."""
        scan_id = create_scan("network", target, mode="SAFE_SCAN")
        logger.info(f"Starting network scan for {target} (Scan ID: {scan_id})")
        
        results = None
        if self.nmap_adapter.is_available():
            results = self._scan_with_nmap(target, port_spec, scan_type, scan_id)
        else:
            logger.info("Nmap binary not found. Using native CYBERWOLF socket engine.")
            results = self._scan_native(target, port_spec, scan_id)

        # Store to database
        total_findings = 0
        for host in results.get("hosts", []):
            host_id = upsert_host(host["ip"], hostname=host.get("hostname"), os_name=host.get("os_name"))
            for p in host.get("ports", []):
                upsert_port(
                    host_id=host_id,
                    port_number=p["port"],
                    protocol=p.get("protocol", "tcp"),
                    state=p.get("state", "open"),
                    service_name=p.get("service"),
                    service_product=p.get("product"),
                    service_version=p.get("version"),
                    banner=p.get("banner")
                )

        for f_dict in results.get("findings", []):
            finding_obj = Finding(
                id=f"CW-NET-{datetime.now().strftime('%Y%m%d')}-{len(results.get('findings', [])):04d}",
                target=target,
                vulnerability=f_dict["vulnerability"],
                severity=f_dict["severity"],
                confidence=f_dict.get("confidence", "HIGH"),
                evidence=f_dict["evidence"],
                port=f_dict.get("port"),
                service=f_dict.get("service"),
                remediation=f_dict.get("remediation"),
                source_tool=f_dict.get("source_tool", "CYBERWOLF Network Engine")
            )
            create_finding(finding_obj)
            total_findings += 1

        complete_scan(scan_id, "COMPLETED", summary=results, findings_count=total_findings)
        results["scan_id"] = scan_id
        return results

    def _scan_with_nmap(self, target: str, port_spec: Optional[str], scan_type: str, scan_id: str) -> Dict[str, Any]:
        cmd = self.nmap_adapter.build_command(target, ports=port_spec, scan_type=scan_type)
        exit_code, stdout, stderr = ToolRunner.execute(cmd, timeout=90, target=target, tool_name="nmap")
        parsed = self.nmap_adapter.parse_output(stdout, exit_code)
        parsed["engine"] = "Nmap"
        return parsed

    def _scan_native(self, target: str, port_spec: Optional[str], scan_id: str) -> Dict[str, Any]:
        ports_to_test = COMMON_PORTS
        if port_spec:
            if "-" in port_spec:
                s, e = map(int, port_spec.split("-"))
                ports_to_test = list(range(s, min(e + 1, 10000)))
            else:
                ports_to_test = [int(p) for p in port_spec.split(",") if p.isdigit()]

        open_ports = []
        findings = []
        
        # Resolve target IP
        try:
            target_ip = socket.gethostbyname(target)
        except Exception as e:
            logger.error(f"Cannot resolve host {target}: {e}")
            return {"success": False, "hosts": [], "findings": [], "error": f"DNS resolution failed: {e}"}

        def probe_port(port: int):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            try:
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    banner = ""
                    try:
                        # Grab service banner
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                    service = PORT_SERVICE_MAP.get(port, "unknown")
                    return {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "banner": banner[:100] if banner else None
                    }
            except Exception:
                pass
            finally:
                s.close()
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_port = {executor.submit(probe_port, p): p for p in ports_to_test}
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res:
                    open_ports.append(res)
                    # Check for risky exposed ports
                    p_num = res["port"]
                    if p_num in [21, 23, 445, 1433, 3306, 5432, 6379, 27017, 8080]:
                        sev = "HIGH" if p_num in [21, 23, 445, 6379, 27017] else "MEDIUM"
                        findings.append({
                            "vulnerability": f"Exposed Sensitive Service ({res['service']}) on Port {p_num}",
                            "severity": sev,
                            "confidence": "HIGH",
                            "evidence": f"Port {p_num}/tcp connection succeeded. Service: {res['service']}",
                            "port": p_num,
                            "service": res["service"],
                            "remediation": f"Block public access to port {p_num} using firewall rules."
                        })

        open_ports.sort(key=lambda x: x["port"])
        return {
            "success": True,
            "engine": "CYBERWOLF Native Socket Engine",
            "hosts": [{
                "ip": target_ip,
                "hostname": target if target != target_ip else None,
                "ports": open_ports
            }],
            "findings": findings
        }
