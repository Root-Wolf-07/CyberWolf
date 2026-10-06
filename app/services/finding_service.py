"""CYBERWOLF Finding Management & Triage Service (V2).

Provides finding query filters, status triage, detail views, and
remediation explanation workflows.
"""

from typing import Dict, List, Any, Optional
from app.database.operations import (
    get_all_findings, get_finding, update_finding_status,
    get_findings_summary
)
from app.database.models import Finding, FindingStatus
from app.intelligence.remediation import get_remediation_advisor
from app.evidence.vault import get_evidence_vault
from app.core.exceptions import CyberWolfError


class FindingService:
    """Manages finding triage, detail inspection, and evidence provenance."""

    def __init__(self):
        self.advisor = get_remediation_advisor()
        self.vault = get_evidence_vault()

    def list_findings(self, target: Optional[str] = None, severity: Optional[str] = None,
                      status: Optional[str] = None, cve: Optional[str] = None,
                      limit: int = 500) -> List[Dict[str, Any]]:
        """Retrieve filtered findings list."""
        return get_all_findings(target=target, severity=severity, status=status, cve=cve, limit=limit)

    def get_summary(self) -> Dict[str, int]:
        """Retrieve finding count summary grouped by severity."""
        return get_findings_summary()

    def get_finding_detail(self, finding_id: str, use_ai_if_available: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve complete finding detail panel including evidence, provenance, and explanation."""
        f_dict = get_finding(finding_id)
        if not f_dict:
            return None

        # Build Finding object to run advisor
        finding_obj = Finding(
            id=f_dict["id"],
            target=f_dict["target"],
            title=f_dict.get("title") or f_dict.get("vulnerability", "Finding"),
            vulnerability=f_dict.get("vulnerability") or f_dict.get("title", "Finding"),
            severity=f_dict.get("severity", "INFO"),
            confidence=f_dict.get("confidence", "HIGH"),
            category=f_dict.get("category", "general"),
            evidence=f_dict.get("evidence", ""),
            port=f_dict.get("port"),
            protocol=f_dict.get("protocol", "tcp"),
            service=f_dict.get("service"),
            cve=f_dict.get("cve"),
            cwe=f_dict.get("cwe"),
            remediation=f_dict.get("remediation"),
            source_tool=f_dict.get("source_tool", "CYBERWOLF"),
            source_tools=f_dict.get("source_tools", [f_dict.get("source_tool", "CYBERWOLF")]),
            risk_score=float(f_dict.get("risk_score", 0.0) or 0.0),
            status=f_dict.get("status", "OPEN"),
            verified=bool(f_dict.get("verified", False))
        )

        # 6-point remediation explanation
        explanation = self.advisor.explain_finding(finding_obj, use_ai_if_available=use_ai_if_available)

        # Linked cryptographic evidence
        evidence_records = self.vault.get_finding_evidence(finding_id)

        return {
            "finding": f_dict,
            "explanation": explanation,
            "evidence_records": evidence_records,
            "allowed_statuses": FindingStatus.ALL
        }

    def update_status(self, finding_id: str, new_status: str, verified: Optional[bool] = None) -> bool:
        """Update finding status (e.g. mark OPEN, CONFIRMED, FALSE_POSITIVE, RESOLVED, ACCEPTED_RISK)."""
        return update_finding_status(finding_id, new_status=new_status, verified=verified)

    def explain_finding(self, finding_id: str, use_ai: bool = False) -> Optional[Dict[str, Any]]:
        """Generate isolated 6-point explanation for a finding."""
        detail = self.get_finding_detail(finding_id, use_ai_if_available=use_ai)
        return detail.get("explanation") if detail else None


_FINDING_SERVICE: Optional[FindingService] = None

def get_finding_service() -> FindingService:
    global _FINDING_SERVICE
    if _FINDING_SERVICE is None:
        _FINDING_SERVICE = FindingService()
    return _FINDING_SERVICE
