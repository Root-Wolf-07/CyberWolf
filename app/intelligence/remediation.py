"""CYBERWOLF Structured Remediation & Finding Explanation Advisor (V2).

Answers the key operational security questions for every finding:
1. What was detected? (Observed facts)
2. Why is it dangerous? (Technical flaw explanation)
3. What evidence supports it? (Observed evidence and command output)
4. What is the likely impact? (Confidentiality, Integrity, Availability risk)
5. What should be fixed? (Actionable hardening guidance)
6. How can the fix be verified? (Verification command / inspection)

Offline-first: Produces complete, deterministic explanations without requiring external LLM APIs.
Clearly separates observed facts from AI-generated synthesis.
"""

from typing import Dict, Any, Optional
from app.database.models import Finding
from app.intelligence.cve_kb import get_cve
from app.intelligence.owasp_kb import map_finding_to_owasp
from app.ai.ollama_client import get_ollama_client
from app.core.logger import get_logger

logger = get_logger()


class RemediationAdvisor:
    """Generates structured, authoritative remediation guides and finding explanations."""

    def explain_finding(self, finding: Finding, use_ai_if_available: bool = False) -> Dict[str, Any]:
        """Produce structured 6-point explanation and remediation roadmap."""
        # 1. Observed facts
        cve_info = None
        if finding.cve_ids:
            cve_info = get_cve(finding.cve_ids[0])
        elif finding.cve:
            cve_info = get_cve(finding.cve.split(",")[0].strip())

        owasp_info = map_finding_to_owasp(finding)

        detected_what = f"{finding.title or finding.vulnerability} on {finding.target}"
        if finding.port:
            detected_what += f" (Port {finding.port}/{finding.protocol})"

        why_dangerous = self._infer_danger(finding, cve_info, owasp_info)
        evidence_summary = finding.evidence or "Observed response match during assessment."
        impact = self._infer_impact(finding, cve_info)
        remediation_steps = self._infer_remediation(finding, cve_info, owasp_info)
        verification_steps = self._infer_verification(finding)

        result = {
            "finding_id": finding.id,
            "observed_facts": {
                "what_was_detected": detected_what,
                "target": finding.target,
                "port": finding.port,
                "service": finding.service,
                "evidence": evidence_summary,
                "sources": finding.source_tools
            },
            "security_analysis": {
                "why_dangerous": why_dangerous,
                "likely_impact": impact,
                "cve_grounding": cve_info.get("cve_id") if cve_info else None,
                "owasp_category": owasp_info.get("category") if owasp_info else None
            },
            "actionable_guidance": {
                "what_should_be_fixed": remediation_steps,
                "how_to_verify": verification_steps
            },
            "ai_synthesis": None
        }

        # Optional AI enhancement (strictly non-fake)
        if use_ai_if_available:
            ollama = get_ollama_client()
            if ollama.is_online():
                from app.ai.orchestrator import get_ai_orchestrator
                try:
                    ai = get_ai_orchestrator()
                    ai_text = ai.analyze_vulnerability_finding(finding.to_dict())
                    result["ai_synthesis"] = {
                        "status": "AVAILABLE",
                        "provider": "Ollama Local LLM",
                        "explanation": ai_text
                    }
                except Exception as e:
                    logger.warning(f"AI enrichment failed: {e}")
                    result["ai_synthesis"] = {
                        "status": "UNAVAILABLE",
                        "note": "AI analysis unavailable. Showing deterministic security analysis instead."
                    }
            else:
                result["ai_synthesis"] = {
                    "status": "UNAVAILABLE",
                    "note": "AI analysis unavailable. Showing deterministic security analysis instead."
                }

        return result

    def _infer_danger(self, finding: Finding, cve_info: Optional[Dict[str, Any]],
                      owasp_info: Optional[Dict[str, Any]]) -> str:
        if cve_info and cve_info.get("description"):
            return cve_info["description"]
        if owasp_info and owasp_info.get("summary"):
            return owasp_info["summary"]

        cat = (finding.category or "").lower()
        if "sql" in (finding.title or "").lower() or cat == "injection":
            return "Improper input sanitization enables unauthenticated data extraction, authentication bypass, or database modification."
        if "rce" in (finding.title or "").lower() or cat == "remote_code_execution":
            return "Arbitrary code execution permits an attacker to execute shell commands with the privileges of the vulnerable application process."
        if "header" in (finding.title or "").lower():
            return "Missing HTTP security headers permit client-side attacks such as clickjacking, MIME sniffing, and SSL stripping."
        if "exposure" in cat or "port" in (finding.title or "").lower():
            return f"Exposing listening services without firewall access control expands the reachable perimeter to unauthorized probing."
        return "Discovered security weakness deviates from defensive configuration baselines."

    def _infer_impact(self, finding: Finding, cve_info: Optional[Dict[str, Any]]) -> str:
        sev = (finding.severity or "INFO").upper()
        if sev == "CRITICAL":
            return "High Risk of Full System Compromise, complete Confidentiality and Integrity loss."
        if sev == "HIGH":
            return "Direct exploitability or unauthorized access to sensitive application data or backend services."
        if sev == "MEDIUM":
            return "Potential information disclosure, elevated attack surface, or prerequisite for chained exploit."
        if sev == "LOW":
            return "Minor configuration discrepancy or metadata leakage."
        return "Informational observation; minimal direct security impact."

    def _infer_remediation(self, finding: Finding, cve_info: Optional[Dict[str, Any]],
                           owasp_info: Optional[Dict[str, Any]]) -> str:
        if finding.remediation:
            return finding.remediation
        if cve_info and cve_info.get("remediation"):
            return cve_info["remediation"]
        if owasp_info and owasp_info.get("remediation"):
            return owasp_info["remediation"]
        return "Review system configuration and apply vendor security updates."

    def _infer_verification(self, finding: Finding) -> str:
        t = finding.target
        p = finding.port
        if p and p in [80, 443, 8080, 8443]:
            return f"Run 'curl -I {t}' or verify HTTP response headers using browser developer tools."
        if p:
            return f"Run 'nc -zv {t} {p}' or 'nmap -p {p} {t}' to confirm port is filtered/closed."
        return f"Re-run CYBERWOLF assessment on {t} to verify finding resolution."


_REMEDIATION_ADVISOR: Optional[RemediationAdvisor] = None

def get_remediation_advisor() -> RemediationAdvisor:
    global _REMEDIATION_ADVISOR
    if _REMEDIATION_ADVISOR is None:
        _REMEDIATION_ADVISOR = RemediationAdvisor()
    return _REMEDIATION_ADVISOR
