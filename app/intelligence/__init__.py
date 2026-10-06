"""CYBERWOLF Cybersecurity Knowledge & Intelligence Layer (V2).

Provides offline-first knowledge retrieval, CVE database lookups,
OWASP Top 10 category mapping, and structured remediation guidance.
"""

from app.intelligence.cve_kb import CVEKnowledgeBase, get_cve_kb, get_cve
from app.intelligence.owasp_kb import OWASPKnowledgeBase, get_owasp_kb, map_finding_to_owasp
from app.intelligence.remediation import RemediationAdvisor, get_remediation_advisor

__all__ = [
    "CVEKnowledgeBase", "get_cve_kb", "get_cve",
    "OWASPKnowledgeBase", "get_owasp_kb", "map_finding_to_owasp",
    "RemediationAdvisor", "get_remediation_advisor"
]
