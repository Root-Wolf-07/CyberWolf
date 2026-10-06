"""CYBERWOLF OWASP Top 10 Knowledge Base & Mapping Engine (V2).

Provides confident mapping of findings and CWEs to OWASP categories:
- A01:2021-Broken Access Control
- A02:2021-Cryptographic Failures
- A03:2021-Injection
- A04:2021-Insecure Design
- A05:2021-Security Misconfiguration
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from app.core.config import get_config
from app.core.logger import get_logger
from app.database.models import Finding

logger = get_logger()


class OWASPKnowledgeBase:
    """Offline OWASP Top 10 knowledge base & mapping engine."""

    def __init__(self, knowledge_path: Optional[str] = None):
        self.config = get_config()
        self.kb_file = Path(knowledge_path or (self.config.base_dir / "knowledge" / "owasp_playbooks.json")).resolve()
        self.playbooks: Dict[str, Dict[str, Any]] = {}
        self._load_database()

    def _load_database(self):
        """Load OWASP playbooks from local JSON."""
        if not self.kb_file.exists():
            return

        try:
            with open(self.kb_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    cat = item.get("category", "")
                    if cat:
                        self.playbooks[cat] = item
        except Exception as e:
            logger.error(f"Error loading OWASP knowledge base: {e}")

    def get_playbook(self, category_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve playbook by exact or prefix category name."""
        for cat, data in self.playbooks.items():
            if category_name.lower() in cat.lower():
                return data
        return None

    def map_finding(self, finding: Finding) -> Optional[Dict[str, Any]]:
        """Confidently map a finding to an OWASP category where applicable.
        
        Returns OWASP metadata dict or None if no confident mapping applies.
        """
        cwe_str = (finding.cwe or "").upper()
        title_lower = (finding.title or finding.vulnerability or "").lower()

        # A03: Injection (SQLi, Command Injection, etc.)
        if "CWE-89" in cwe_str or "sql" in title_lower or "injection" in title_lower:
            pb = self.get_playbook("A03:2021-Injection")
            return {
                "category": "A03:2021-Injection",
                "cwe": "CWE-89",
                "summary": pb.get("summary") if pb else "Untrusted data sent to interpreter as command/query.",
                "remediation": pb.get("remediation") if pb else "Use parameterized queries / prepared statements."
            }

        # A05: Security Misconfiguration
        if ("header" in title_lower or "cookie" in title_lower or "banner" in title_lower or
            "version" in title_lower or "misconfiguration" in title_lower or "CWE-16" in cwe_str):
            pb = self.get_playbook("A05:2021-Security Misconfiguration")
            return {
                "category": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-16, CWE-200",
                "summary": pb.get("summary") if pb else "Missing security headers, default banners, or unhardened configs.",
                "remediation": pb.get("remediation") if pb else "Harden server configs and apply security headers."
            }

        # A02: Cryptographic Failures
        if ("tls" in title_lower or "ssl" in title_lower or "cleartext" in title_lower or
            "unencrypted" in title_lower or "hsts" in title_lower or "CWE-327" in cwe_str):
            pb = self.get_playbook("A02:2021-Cryptographic Failures")
            return {
                "category": "A02:2021-Cryptographic Failures",
                "cwe": "CWE-327",
                "summary": pb.get("summary") if pb else "Weak or missing encryption in transit.",
                "remediation": pb.get("remediation") if pb else "Enforce TLS 1.3 and HSTS headers."
            }

        # A01: Broken Access Control
        if ("git" in title_lower or "actuator" in title_lower or "path traversal" in title_lower or
            "unauthorized" in title_lower or ".env" in title_lower or "CWE-284" in cwe_str):
            pb = self.get_playbook("A01:2021-Broken Access Control")
            return {
                "category": "A01:2021-Broken Access Control",
                "cwe": "CWE-200, CWE-284",
                "summary": pb.get("summary") if pb else "Flaws allowing users to act outside intended permissions.",
                "remediation": pb.get("remediation") if pb else "Enforce strict RBAC and block sensitive file paths."
            }

        # A04: Insecure Design
        if "CWE-502" in cwe_str or "deserialization" in title_lower or "log4j" in title_lower:
            pb = self.get_playbook("A04:2021-Insecure Design")
            return {
                "category": "A04:2021-Insecure Design",
                "cwe": "CWE-502",
                "summary": pb.get("summary") if pb else "Unsafe deserialization or architectural design weaknesses.",
                "remediation": pb.get("remediation") if pb else "Upgrade vulnerable libraries and validate data boundaries."
            }

        # Do not force an OWASP category onto unrelated findings (e.g. routine port scan open port)
        return None


_OWASP_KB: Optional[OWASPKnowledgeBase] = None

def get_owasp_kb() -> OWASPKnowledgeBase:
    global _OWASP_KB
    if _OWASP_KB is None:
        _OWASP_KB = OWASPKnowledgeBase()
    return _OWASP_KB

def map_finding_to_owasp(finding: Finding) -> Optional[Dict[str, Any]]:
    return get_owasp_kb().map_finding(finding)
