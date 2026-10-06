"""CYBERWOLF Finding Deduplicator Engine (V2).

Implements deterministic finding deduplication with strict provenance preservation:
- Generates canonical correlation keys (Host + Port + Protocol + CVE/Normalized Title)
- Merges source tools without losing detection history
- Unifies evidence snippets and remediation advice
- Promotes severity and confidence to the highest verified level
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from app.database.models import Finding, SeverityLevel, ConfidenceLevel
from app.core.logger import get_logger

logger = get_logger()

SEVERITY_ORDER = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4
}

CONFIDENCE_ORDER = {
    ConfidenceLevel.LOW: 0,
    ConfidenceLevel.MEDIUM: 1,
    ConfidenceLevel.HIGH: 2,
    ConfidenceLevel.CONFIRMED: 3
}


class FindingDeduplicator:
    """Merges redundant scanner findings while strictly preserving source provenance."""

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate a list of findings using deterministic correlation keys."""
        if not findings or len(findings) <= 1:
            return findings

        dedup_map: Dict[str, Finding] = {}

        for f in findings:
            key = self._generate_dedup_key(f)
            if key not in dedup_map:
                dedup_map[key] = f
            else:
                existing = dedup_map[key]
                dedup_map[key] = self._merge_findings(existing, f)

        merged_list = list(dedup_map.values())
        if len(merged_list) < len(findings):
            logger.info(
                f"Deduplication consolidated {len(findings)} raw findings into "
                f"{len(merged_list)} canonical findings."
            )
        return merged_list

    def _generate_dedup_key(self, f: Finding) -> str:
        """Create a deterministic unique correlation key for a finding."""
        host_key = (f.host or f.target or "unknown").strip().lower()
        port_key = str(f.port or 0)
        proto_key = (f.protocol or "tcp").strip().lower()

        # If a valid CVE exists, key directly on the CVE
        if f.cve_ids:
            primary_cve = sorted(f.cve_ids)[0].strip().upper()
            return f"{host_key}:{port_key}:{proto_key}:{primary_cve}"

        # Otherwise key on normalized title
        clean_title = re.sub(r'[^a-zA-Z0-9]', '', (f.title or f.vulnerability or "").lower())
        return f"{host_key}:{port_key}:{proto_key}:{clean_title}"

    def _merge_findings(self, base: Finding, incoming: Finding) -> Finding:
        """Merge incoming finding into base finding, keeping provenance intact."""
        # 1. Combine source tools
        all_sources = list(dict.fromkeys(base.source_tools + incoming.source_tools))
        base.source_tools = all_sources
        base.source_tool = all_sources[0]

        # 2. Promote severity if incoming is higher
        base_sev_rank = SEVERITY_ORDER.get(base.severity, 0)
        inc_sev_rank = SEVERITY_ORDER.get(incoming.severity, 0)
        if inc_sev_rank > base_sev_rank:
            base.severity = incoming.severity

        # 3. Promote confidence if incoming is higher
        base_conf_rank = CONFIDENCE_ORDER.get(base.confidence, 0)
        inc_conf_rank = CONFIDENCE_ORDER.get(incoming.confidence, 0)
        if inc_conf_rank > base_conf_rank:
            base.confidence = incoming.confidence

        # 4. Merge CVE and CWE lists
        all_cves = list(dict.fromkeys(base.cve_ids + incoming.cve_ids))
        base.cve_ids = all_cves
        base.cve = ", ".join(all_cves) if all_cves else None

        all_cwes = list(dict.fromkeys(base.cwe_ids + incoming.cwe_ids))
        base.cwe_ids = all_cwes
        base.cwe = ", ".join(all_cwes) if all_cwes else None

        # 5. Combine evidence if distinct
        if incoming.evidence and incoming.evidence not in base.evidence:
            base.evidence = f"{base.evidence}\n[Additional Evidence from {incoming.source_tool}]: {incoming.evidence}".strip()

        # 6. Prefer longer/more detailed remediation
        if incoming.remediation and len(incoming.remediation) > len(base.remediation or ""):
            base.remediation = incoming.remediation

        # 7. Merge references
        base.references = list(dict.fromkeys(base.references + incoming.references))

        # 8. Service / Port
        if not base.service and incoming.service:
            base.service = incoming.service
        if not base.port and incoming.port:
            base.port = incoming.port

        return base


_DEDUPLICATOR: Optional[FindingDeduplicator] = None

def get_deduplicator() -> FindingDeduplicator:
    global _DEDUPLICATOR
    if _DEDUPLICATOR is None:
        _DEDUPLICATOR = FindingDeduplicator()
    return _DEDUPLICATOR
