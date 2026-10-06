"""CYBERWOLF Finding Management & Investigation Service (BDIE V2).

Provides finding query filters, status triage, detail views,
remediation roadmap, automated retesting, and evidence investigation workflows.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime

from app.database.operations import (
    get_all_findings, get_finding, update_finding_status,
    get_findings_summary, get_finding_retests, get_finding_status_history
)
from app.database.models import Finding, FindingStatus
from app.intelligence.remediation import get_remediation_advisor
from app.intelligence.investigation import get_investigation_engine
from app.evidence.vault import get_evidence_vault
from app.core.exceptions import CyberWolfError


class FindingService:
    """Manages finding triage, detail inspection, evidence provenance, and retesting."""

    def __init__(self):
        self.advisor = get_remediation_advisor()
        self.investigation_engine = get_investigation_engine()
        self.vault = get_evidence_vault()

    def list_findings(self, target: Optional[str] = None, severity: Optional[str] = None,
                      status: Optional[str] = None, cve: Optional[str] = None,
                      limit: int = 500) -> List[Dict[str, Any]]:
        """Retrieve filtered findings list."""
        return get_all_findings(target=target, severity=severity, status=status, cve=cve, limit=limit)

    def get_summary(self) -> Dict[str, int]:
        """Retrieve finding count summary grouped by severity."""
        return get_findings_summary()

    def search_findings(self, query: str, severity: Optional[str] = None,
                        status: Optional[str] = None, target: Optional[str] = None,
                        limit: int = 100) -> List[Dict[str, Any]]:
        """Global search over titles, hosts, CVEs, CWEs, endpoints, and services."""
        all_findings = get_all_findings(target=target, severity=severity, status=status, limit=limit * 2)
        q = (query or "").lower().strip()
        if not q:
            return all_findings[:limit]

        matched = []
        for f in all_findings:
            searchable = " ".join([
                str(f.get("id") or ""),
                str(f.get("title") or ""),
                str(f.get("vulnerability") or ""),
                str(f.get("target") or ""),
                str(f.get("host") or ""),
                str(f.get("endpoint") or ""),
                str(f.get("parameter") or ""),
                str(f.get("service") or ""),
                str(f.get("cve") or ""),
                str(f.get("cwe") or ""),
                str(f.get("category") or "")
            ]).lower()
            if q in searchable:
                matched.append(f)
                if len(matched) >= limit:
                    break
        return matched

    def get_finding_detail(self, finding_id: str, use_ai_if_available: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve complete finding detail panel including BDIE investigation, evidence, and timeline."""
        f_dict = get_finding(finding_id)
        if not f_dict:
            return None

        # Build investigation report
        investigation = self.investigation_engine.investigate(f_dict, use_ai_if_available=use_ai_if_available)

        # 6-point remediation explanation
        f_obj = Finding(
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
            verified=bool(f_dict.get("verified", False)),
            url=f_dict.get("url"),
            endpoint=f_dict.get("endpoint"),
            parameter=f_dict.get("parameter"),
            http_method=f_dict.get("http_method")
        )
        explanation = self.advisor.explain_finding(f_obj, use_ai_if_available=use_ai_if_available)

        # Linked cryptographic evidence
        evidence_records = self.vault.get_finding_evidence(finding_id)
        if not evidence_records and f_dict.get("evidence_ids"):
            from app.database.operations import get_evidence
            for eid in f_dict.get("evidence_ids", []):
                ev = get_evidence(eid)
                if ev:
                    evidence_records.append(ev)

        for ev in evidence_records:
            ok, msg = self.vault.verify_evidence_integrity(ev.get("id"))
            ev["integrity_verified"] = ok
            ev["integrity_status"] = msg

        # Retest history & status history
        retests = get_finding_retests(finding_id)
        status_history = get_finding_status_history(finding_id)

        # Timeline
        timeline = self.get_timeline(finding_id, f_dict, status_history, retests)

        return {
            "finding": f_dict,
            "investigation": investigation,
            "explanation": explanation,
            "exact_location": investigation["exact_location"],
            "evidence_records": evidence_records,
            "evidence_chain": evidence_records,
            "retests": retests,
            "status_history": status_history,
            "timeline": timeline,
            "allowed_statuses": FindingStatus.ALL
        }

    def update_status(self, finding_id: str, new_status: str, verified: Optional[bool] = None,
                      reason: Optional[str] = None, changed_by: str = "ANALYST") -> bool:
        """Update finding status with reason and audit history."""
        return update_finding_status(
            finding_id, new_status=new_status, verified=verified,
            reason=reason, changed_by=changed_by
        )

    def retest_finding(self, finding_id: str, retested_by: str = "CYBERWOLF BDIE",
                       actor: Optional[str] = None) -> Dict[str, Any]:
        """Trigger an authorized verification probe and return structured retest result."""
        from app.services.retest_service import get_retest_service
        retest_svc = get_retest_service()
        caller = actor or retested_by
        return retest_svc.retest_finding(finding_id, retested_by=caller)

    def explain_finding(self, finding_id: str, use_ai: bool = False) -> Optional[Dict[str, Any]]:
        """Generate isolated 6-point explanation for a finding."""
        detail = self.get_finding_detail(finding_id, use_ai_if_available=use_ai)
        return detail.get("explanation") if detail else None

    def get_timeline(self, finding_id: str, finding_dict: Optional[Dict[str, Any]] = None,
                     status_history: Optional[List[Dict[str, Any]]] = None,
                     retests: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Construct chronological timeline of discovery, status transitions, and retests."""
        f_dict = finding_dict or get_finding(finding_id) or {}
        history = status_history if status_history is not None else get_finding_status_history(finding_id)
        retests_list = retests if retests is not None else get_finding_retests(finding_id)

        events = []

        # 1. Discovery event
        first_seen = f_dict.get("first_seen") or f_dict.get("created_at") or datetime.now().isoformat()
        events.append({
            "timestamp": first_seen,
            "event_type": "DISCOVERY",
            "actor": f_dict.get("source_tool", "CYBERWOLF"),
            "description": f"Finding initially identified on {f_dict.get('target', 'target')}",
            "badge": "DISCOVERED"
        })

        # 2. Status change events
        for h in history:
            events.append({
                "timestamp": h.get("changed_at"),
                "event_type": "STATUS_CHANGE",
                "actor": h.get("changed_by", "ANALYST"),
                "description": f"Status updated: {h.get('old_status')} -> {h.get('new_status')} ({h.get('reason') or 'No reason provided'})",
                "badge": h.get("new_status")
            })

        # 3. Retest events
        for r in retests_list:
            events.append({
                "timestamp": r.get("timestamp"),
                "event_type": "RETEST",
                "actor": r.get("retested_by", "CYBERWOLF BDIE"),
                "description": f"Verification re-test executed: Result {r.get('result')} ({r.get('details')})",
                "badge": f"RETEST_{r.get('result')}"
            })

        # Sort chronologically
        events.sort(key=lambda e: e.get("timestamp") or "")
        return events


_FINDING_SERVICE: Optional[FindingService] = None

def get_finding_service() -> FindingService:
    global _FINDING_SERVICE
    if _FINDING_SERVICE is None:
        _FINDING_SERVICE = FindingService()
    return _FINDING_SERVICE

