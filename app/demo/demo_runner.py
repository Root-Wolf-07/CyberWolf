"""CYBERWOLF Safe Demonstration Environment (cyberwolf demo)."""

import time
from datetime import datetime
from typing import Dict, Any
from app.database.operations import create_scan, complete_scan, upsert_host, upsert_port, create_finding, save_tool_output
from app.database.models import Finding
from app.reports.generator import ReportGenerator
from app.ai.orchestrator import get_ai_orchestrator
from app.core.logger import get_logger

logger = get_logger()

SAMPLE_NMAP_RAW = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-20 14:00 UTC
Nmap scan report for sec-lab-target.local (192.168.1.150)
Host is up (0.0021s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.7.33
8080/tcp open  http    Apache Tomcat 9.0.38 (Actuator enabled)
MAC Address: 00:0C:29:4F:8E:1A (VMware)
Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds
"""

class DemoRunner:
    """Runs a complete end-to-end simulated security assessment showcase."""
    
    def __init__(self):
        self.report_gen = ReportGenerator()
        self.ai = get_ai_orchestrator()

    def run_demo(self) -> Dict[str, Any]:
        """Execute full simulated assessment suite."""
        target = "sec-lab-target.local (192.168.1.150)"
        logger.info("Executing CYBERWOLF Demo Assessment")
        
        # 1. Simulate Network Scan
        scan_id = create_scan("network", target, mode="LAB_MODE")
        host_id = upsert_host("192.168.1.150", hostname="sec-lab-target.local", os_name="Ubuntu Linux 20.04")
        upsert_port(host_id, 22, "tcp", "open", "ssh", "OpenSSH", "8.2p1", "SSH-2.0-OpenSSH_8.2p1")
        upsert_port(host_id, 80, "tcp", "open", "http", "Apache", "2.4.41", "Apache/2.4.41 (Ubuntu)")
        upsert_port(host_id, 3306, "tcp", "open", "mysql", "MySQL", "5.7.33", "5.7.33-0ubuntu0.18.04.1")
        upsert_port(host_id, 8080, "tcp", "open", "http-alt", "Apache Tomcat", "9.0.38", "Apache Tomcat/9.0.38")
        save_tool_output("nmap", SAMPLE_NMAP_RAW, scan_id=scan_id, command_line="nmap -sV -sC 192.168.1.150")

        # 2. Add Normalized Demo Findings
        demo_findings = [
            Finding(
                id="CW-DEMO-0001",
                target=target,
                vulnerability="Log4Shell Remote Code Execution (Simulated)",
                severity="CRITICAL",
                evidence="HTTP JNDI lookup header '${jndi:ldap://127.0.0.1/a}' triggered callback on port 8080.",
                confidence="HIGH",
                cve="CVE-2021-44228",
                cwe="CWE-502",
                port=8080,
                service="Apache Tomcat",
                source_tool="Nuclei (Simulated)",
                remediation="Upgrade log4j-core to 2.17.1+ or apply formatMsgNoLookups=true flag."
            ),
            Finding(
                id="CW-DEMO-0002",
                target=target,
                vulnerability="SQL Injection in Search Endpoint",
                severity="CRITICAL",
                evidence="Parameter 'search' produced MySQL syntax error when probed with \"' OR '1'='1\".",
                confidence="HIGH",
                cve="CWE-89",
                cwe="CWE-89",
                port=80,
                service="http",
                source_tool="CYBERWOLF SQL Engine",
                remediation="Convert search query to prepared statements with parameterized inputs."
            ),
            Finding(
                id="CW-DEMO-0003",
                target=target,
                vulnerability="Exposed Database Service (MySQL)",
                severity="HIGH",
                evidence="Port 3306/tcp is publicly listening without network ACL restrictions.",
                confidence="HIGH",
                port=3306,
                service="mysql",
                source_tool="Nmap",
                remediation="Bind MySQL to 127.0.0.1 or enforce firewall rules allowing only backend servers."
            ),
            Finding(
                id="CW-DEMO-0004",
                target=target,
                vulnerability="Missing Content-Security-Policy & HSTS Headers",
                severity="MEDIUM",
                evidence="HTTP 80 response lacks HSTS and Content-Security-Policy headers.",
                confidence="HIGH",
                port=80,
                service="http",
                source_tool="CYBERWOLF Web Engine",
                remediation="Add Strict-Transport-Security and Content-Security-Policy headers to Apache config."
            )
        ]

        for f in demo_findings:
            create_finding(f)

        complete_scan(scan_id, "COMPLETED", findings_count=len(demo_findings))

        # 3. Request AI Summary
        ai_summary = "CYBERWOLF AI identified 4 vulnerabilities on target (2 CRITICAL, 1 HIGH, 1 MEDIUM). Priority remediation is urgently required for Log4Shell on port 8080 and SQL Injection on port 80."
        
        # 4. Generate Reports
        reports = self.report_gen.generate_all_formats(target, "CYBERWOLF Demonstration Assessment", ai_summary=ai_summary)

        return {
            "status": "DEMO_COMPLETED",
            "target": target,
            "findings_count": len(demo_findings),
            "reports": reports,
            "ai_analysis": ai_summary
        }
