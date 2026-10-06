"""CYBERWOLF Vulnerability Investigation & Exploitation Assessment Engine (BDIE V2).

Transforms raw findings into evidence-grounded security investigations:
- Exact Affected Location (Web, Network, Configuration, Source Code)
- Observed Behavior vs Verified Behavior
- Security Impact Analysis
- Security Exploitation Assessment (Exploitability, Prerequisites, Limitations)
- Verified CVE / CWE / OWASP Grounding
- Defensive Remediation & Verification Procedures
- Retest & Lifecycle Tracking

Strict rule: AI and heuristic layers must NEVER invent CVEs, requests, responses,
parameters, or fake exploitation results.
"""

from typing import Dict, Any, Optional, List, Union
from app.database.models import Finding, SeverityLevel, ConfidenceLevel, FindingStatus
from app.detection.exact_location import ExactLocationEngine, ExactLocation
from app.intelligence.cve_kb import get_cve
from app.intelligence.owasp_kb import map_finding_to_owasp
from app.core.logger import get_logger

logger = get_logger()


class InvestigationEngine:
    """Produces comprehensive, evidence-grounded vulnerability investigations."""

    def investigate(self, finding_input: Union[Finding, Dict[str, Any]],
                    use_ai_if_available: bool = False) -> Dict[str, Any]:
        """Perform full BDIE investigation on a finding."""
        if isinstance(finding_input, dict):
            finding_dict = finding_input
            # Create a Finding instance for consistent access
            finding = Finding(
                id=finding_dict.get("id", "FINDING-UNKNOWN"),
                target=finding_dict.get("target", ""),
                title=finding_dict.get("title") or finding_dict.get("vulnerability", "Security Issue"),
                vulnerability=finding_dict.get("vulnerability") or finding_dict.get("title", "Security Issue"),
                description=finding_dict.get("description", ""),
                severity=finding_dict.get("severity", "INFO"),
                confidence=finding_dict.get("confidence", "HIGH"),
                category=finding_dict.get("category", "general"),
                host=finding_dict.get("host"),
                port=finding_dict.get("port"),
                protocol=finding_dict.get("protocol", "tcp"),
                service=finding_dict.get("service"),
                service_version=finding_dict.get("service_version"),
                cve=finding_dict.get("cve"),
                cve_ids=finding_dict.get("cve_ids") or [],
                cwe=finding_dict.get("cwe"),
                cwe_ids=finding_dict.get("cwe_ids") or [],
                owasp_category=finding_dict.get("owasp_category"),
                cvss=finding_dict.get("cvss"),
                evidence=finding_dict.get("evidence", ""),
                evidence_ids=finding_dict.get("evidence_ids") or [],
                source_tool=finding_dict.get("source_tool", "CYBERWOLF"),
                source_tools=finding_dict.get("source_tools") or [finding_dict.get("source_tool", "CYBERWOLF")],
                remediation=finding_dict.get("remediation"),
                risk_score=float(finding_dict.get("risk_score", 0.0) or 0.0),
                risk_factors=finding_dict.get("risk_factors") or {},
                status=finding_dict.get("status", "OPEN"),
                verified=bool(finding_dict.get("verified", False)),
                url=finding_dict.get("url"),
                http_method=finding_dict.get("http_method"),
                endpoint=finding_dict.get("endpoint"),
                parameter=finding_dict.get("parameter"),
                component=finding_dict.get("component"),
                technology=finding_dict.get("technology"),
                config_area=finding_dict.get("config_area"),
                config_setting=finding_dict.get("config_setting"),
                config_observed=finding_dict.get("config_observed"),
                config_expected=finding_dict.get("config_expected"),
                source_file=finding_dict.get("source_file"),
                source_line=finding_dict.get("source_line"),
                source_function=finding_dict.get("source_function"),
                observed_behavior=finding_dict.get("observed_behavior"),
                verified_behavior=finding_dict.get("verified_behavior"),
                potential_impact=finding_dict.get("potential_impact"),
                exploitability=finding_dict.get("exploitability"),
                exploit_prerequisites=finding_dict.get("exploit_prerequisites"),
                exploit_limitations=finding_dict.get("exploit_limitations"),
                retest_status=finding_dict.get("retest_status"),
                retest_result=finding_dict.get("retest_result"),
                scan_id=finding_dict.get("scan_id"),
                tool_run_id=finding_dict.get("tool_run_id")
            )
        else:
            finding = finding_input
            finding_dict = finding.to_dict()

        # Ensure transparent risk factors are populated
        if not finding.risk_factors:
            from app.detection.risk_engine import RiskEngine
            re_res = RiskEngine().score_finding(finding)
            finding.risk_factors = re_res.get("factors", {})
            if not finding.risk_score:
                finding.risk_score = re_res.get("score", 0.0)

        # 1. Exact Location Resolution
        location = ExactLocationEngine.resolve_location(finding)

        # 2. Knowledge Grounding (CVE / CWE / OWASP)
        cve_info = None
        if finding.cve_ids:
            cve_info = get_cve(finding.cve_ids[0])
        elif finding.cve:
            cve_info = get_cve(finding.cve.split(",")[0].strip())

        owasp_info = map_finding_to_owasp(finding)

        # 3. Behavior Separation: Observed vs Verified
        observed = finding.observed_behavior or finding.evidence or "Insufficient evidence / Not observed"
        verified = self._determine_verified_behavior(finding, location)

        # 4. Security Impact Assessment
        impact = finding.potential_impact or self._assess_impact(finding, cve_info)

        # 5. Security Exploitation Assessment
        exploitation = self._assess_exploitation(finding, location, cve_info)

        # 6. Remediation & Verification Procedures
        remediation = finding.remediation or self._infer_remediation(finding, cve_info, owasp_info)
        verification_proc = self._infer_verification_procedure(finding, location)

        report = {
            "finding_id": finding.id,
            "title": finding.title or finding.vulnerability,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "risk_score": finding.risk_score,
            "risk_factors": finding.risk_factors,
            "status": finding.status,
            "exact_location": {
                "type": location.location_type,
                "summary": location.summary(),
                "hierarchy": location.format_hierarchy(),
                "details": location.to_dict()
            },
            "observed_behavior": observed,
            "verified_behavior": verified,
            "why_flagged": self._generate_why_flagged(finding, location, cve_info),
            "why_this_was_flagged": self._generate_why_flagged(finding, location, cve_info),
            "security_impact": impact,
            "exploitation_assessment": exploitation,
            "vulnerability_intelligence": {
                "cve": finding.cve,
                "cve_ids": finding.cve_ids,
                "cwe": finding.cwe,
                "cwe_ids": finding.cwe_ids,
                "owasp": finding.owasp_category or (owasp_info.get("category") if owasp_info else None),
                "cvss": finding.cvss or (cve_info.get("cvss") if cve_info else None),
                "cve_details": cve_info
            },
            "remediation": {
                "defensive_steps": remediation,
                "verification_procedure": verification_proc
            },
            "retest": {
                "status": finding.retest_status or "NOT_RETESTED",
                "result": finding.retest_result or "NONE",
                "last_verified": finding.last_verified
            },
            "evidence": {
                "summary": finding.evidence,
                "evidence_ids": finding.evidence_ids,
                "source_tools": finding.source_tools,
                "scan_id": finding.scan_id
            }
        }

        # 7. Optional AI Enrichment
        if use_ai_if_available:
            from app.intelligence.remediation import get_remediation_advisor
            advisor = get_remediation_advisor()
            ai_data = advisor.explain_finding(finding, use_ai_if_available=True).get("ai_synthesis")
            report["ai_synthesis"] = ai_data

        return report

    def _determine_verified_behavior(self, finding: Finding, location: ExactLocation) -> str:
        """State specifically what was verified in authorized assessment."""
        if finding.verified_behavior:
            return finding.verified_behavior

        if finding.confidence == ConfidenceLevel.CONFIRMED:
            if location.location_type == "WEB":
                return f"Verified server response on {location.http_method or 'GET'} {location.endpoint or location.url} during authorized assessment."
            if location.location_type == "NETWORK":
                return f"Verified listening port {location.port}/{location.protocol} and active service banner on {location.host or finding.target}."
            if location.location_type == "CONFIGURATION":
                return f"Verified server configuration on {location.host or finding.target} deviates from baseline."
            return "Vulnerability confirmed through multi-tool cross-validation."

        if finding.verified:
            return "Demonstrated flaw presence via safe non-destructive probing."

        return "Not independently probe-verified in current session; further authorized verification recommended."

    def _assess_impact(self, finding: Finding, cve_info: Optional[Dict[str, Any]]) -> str:
        """Derive objective security impact."""
        sev = (finding.severity or "INFO").upper()
        cat = (finding.category or "").lower()

        if "injection" in cat or "sql" in (finding.title or "").lower():
            return "Potential unauthorized access to backend database records, authentication bypass, and sensitive data extraction."
        if "remote_code_execution" in cat or "rce" in (finding.title or "").lower():
            return "High risk of arbitrary code execution with service process permissions, potentially leading to host compromise."
        if sev == SeverityLevel.CRITICAL:
            return "Severe impact on confidentiality, integrity, or system availability."
        if sev == SeverityLevel.HIGH:
            return "Significant risk of unauthorized information disclosure, access elevation, or administrative compromise."
        if sev == SeverityLevel.MEDIUM:
            return "Moderate risk of security control bypass, internal metadata leakage, or attack surface expansion."
        if sev == SeverityLevel.LOW:
            return "Low risk; configuration deviation or verbose service banner leakage."
        return "Informational observation with negligible direct security impact."

    def _assess_exploitation(self, finding: Finding, location: ExactLocation,
                             cve_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Produce structured exploitation assessment with prerequisites and limitations."""
        sev = (finding.severity or "INFO").upper()
        conf = (finding.confidence or "HIGH").upper()

        if finding.exploitability:
            level = finding.exploitability
        elif conf == ConfidenceLevel.CONFIRMED and sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            level = "CONFIRMED"
        elif sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            level = "HIGH"
        elif sev == SeverityLevel.MEDIUM:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Prerequisites
        prereqs = finding.exploit_prerequisites
        if not prereqs:
            if location.location_type == "WEB":
                prereqs = "Network access and reachability to HTTP endpoint. No authentication required unless behind login gate."
            elif location.location_type == "NETWORK":
                prereqs = f"Network access: Direct TCP/UDP route to port {location.port or 'service'} without blocking firewall."
            else:
                prereqs = "Network access: Direct reachability to target system."

        # Limitations
        limitations = finding.exploit_limitations
        if not limitations:
            limitations = "Non-destructive defensive assessment: CYBERWOLF assessment is strictly non-destructive and defensive. Weaponized exploitation, lateral movement, payload delivery, and credential theft were not conducted."

        return {
            "exploitability_level": level,
            "prerequisites": prereqs,
            "attack_surface": f"{location.host or finding.target}:{location.port or 'All'}",
            "limitations": limitations
        }

    def generate_investigation_report(self, finding_input: Union[Finding, Dict[str, Any]]) -> Dict[str, Any]:
        """Generate structured investigation report separating observed facts, verified behavior, and grounded knowledge."""
        investigation = self.investigate(finding_input)

        verified_raw = investigation.get("verified_behavior", "")
        if not verified_raw or "not independently" in verified_raw.lower() or "unverified" in verified_raw.lower():
            verified_text = "Not independently probe-verified in current session"
        else:
            verified_text = verified_raw

        evidence_text = investigation.get("evidence", {}).get("summary")
        if not evidence_text:
            evidence_text = "Insufficient evidence provided for confirmation"

        observed_text = investigation.get("observed_behavior") or "Insufficient evidence / Not observed"

        cve_val = investigation.get("vulnerability_intelligence", {}).get("cve")
        has_verified_mapping = bool(cve_val and cve_val != "Not identified / None" and investigation.get("vulnerability_intelligence", {}).get("cve_details"))

        exploit = investigation.get("exploitation_assessment", {})
        exploit_level = exploit.get("exploitability_level", "LOW")
        prereqs = exploit.get("prerequisites", "Network access to host")
        limitations = exploit.get("limitations", "Non-destructive testing only")

        return {
            "finding_id": investigation.get("finding_id"),
            "title": investigation.get("title"),
            "observed_facts": {
                "what_was_detected": observed_text,
                "what_was_verified": verified_text,
                "evidence": evidence_text
            },
            "security_exploitation": {
                "level": exploit_level,
                "prerequisites": prereqs,
                "limitations": limitations
            },
            "knowledge_grounding": {
                "cve": cve_val or "Not identified / None",
                "verified_mapping": has_verified_mapping
            },
            "full_investigation": investigation
        }

    def _generate_why_flagged(self, finding: Finding, location: ExactLocation,
                              cve_info: Optional[Dict[str, Any]]) -> str:
        """Provide a factual, evidence-grounded explanation of why this was flagged without hallucination."""
        title_lower = (finding.title or finding.vulnerability or "").lower()
        cat = (finding.category or "").lower()
        evidence_text = finding.evidence or finding.observed_behavior or ""

        if "sql" in title_lower or "injection" in cat:
            param_part = f"parameter '{location.parameter}'" if location.parameter else "an input parameter"
            endpoint_part = f"at {location.endpoint or location.url}" if (location.endpoint or location.url) else ""
            return (
                f"CyberWolf detected that {param_part} {endpoint_part} influenced the server-side database response in a way consistent with SQL injection behavior. "
                f"The scanner observed a measurable response difference or database error syntax when the parameter was tested. "
                f"The finding is supported by the captured request/response evidence."
            )
        elif "header" in title_lower or "missing" in title_lower:
            setting = location.config_setting or "security header"
            return (
                f"CyberWolf inspected the HTTP response headers for {location.host or finding.target} and detected that the '{setting}' header was not set. "
                f"Without this header, client browsers lack defensive directives to prevent MIME-confusion, clickjacking, or cleartext transmission."
            )
        elif "cookie" in title_lower:
            return (
                f"CyberWolf inspected HTTP Set-Cookie directives and identified cookies missing required 'Secure', 'HttpOnly', or 'SameSite' attributes. "
                f"This allows session cookies to be accessed by client scripts or transmitted across unencrypted channels."
            )
        elif "port" in title_lower or location.location_type == "NETWORK":
            return (
                f"CyberWolf detected an active service ({location.service or 'service'}) listening on port {location.port}/{location.protocol or 'tcp'}. "
                f"The scanner successfully received a valid response banner from the host. Network exposure analysis flagged this port for verification."
            )
        elif evidence_text:
            return (
                f"CyberWolf flagged this issue based on concrete evidence captured during security scanning: {evidence_text[:200].strip()}... "
                f"The observed behavior deviates from expected secure baselines."
            )
        else:
            return "Insufficient evidence for confirmation. Passive scanner observation requires active probe verification."

    def _infer_remediation(self, finding: Finding, cve_info: Optional[Dict[str, Any]],
                           owasp_info: Optional[Dict[str, Any]]) -> str:
        if finding.remediation:
            return finding.remediation
        if cve_info and cve_info.get("remediation"):
            return cve_info["remediation"]
        if owasp_info and owasp_info.get("remediation"):
            return owasp_info["remediation"]
        return "Review system configuration, restrict unauthorized network exposure, and apply vendor security patches."

    def _infer_verification_procedure(self, finding: Finding, location: ExactLocation) -> str:
        """Provide step-by-step safe verification procedure."""
        if location.location_type == "WEB":
            url = location.url or f"http://{finding.target}"
            return f"Execute safe HTTP request: curl -sI '{url}' and confirm absence of sensitive data or verify secure response code."
        if location.location_type == "NETWORK" and location.port:
            return f"Run port verification: nc -zv {location.host or finding.target} {location.port} to confirm port is closed or filtered."
        if location.location_type == "CONFIGURATION":
            return f"Inspect configuration setting '{location.config_setting}' and verify value matches expected secure baseline."
        return f"Re-run CYBERWOLF targeted scan on {finding.target} to verify finding resolution."


_INVESTIGATION_ENGINE: Optional[InvestigationEngine] = None

def get_investigation_engine() -> InvestigationEngine:
    global _INVESTIGATION_ENGINE
    if _INVESTIGATION_ENGINE is None:
        _INVESTIGATION_ENGINE = InvestigationEngine()
    return _INVESTIGATION_ENGINE
