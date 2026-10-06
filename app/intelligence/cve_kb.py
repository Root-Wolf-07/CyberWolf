"""CYBERWOLF CVE Knowledge Base & Lookup Engine (V2).

Provides offline-first CVE information lookups from local knowledge database:
- CVE ID exact and fuzzy lookups
- Affected services and versions
- CVSS scores and CWE classifications
- Deterministic remediation baselines
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from app.core.config import get_config
from app.core.logger import get_logger

logger = get_logger()


class CVEKnowledgeBase:
    """Local offline-first CVE lookup abstraction."""

    def __init__(self, knowledge_path: Optional[str] = None):
        self.config = get_config()
        self.kb_file = Path(knowledge_path or (self.config.base_dir / "knowledge" / "cve_database.json")).resolve()
        self.cve_index: Dict[str, Dict[str, Any]] = {}
        self._load_database()

    def _load_database(self):
        """Load and index CVEs from JSON storage."""
        if not self.kb_file.exists():
            logger.warning(f"CVE database file not found at {self.kb_file}")
            return

        try:
            with open(self.kb_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for entry in data:
                    cve_id = entry.get("cve", "").strip().upper()
                    if cve_id:
                        self.cve_index[cve_id] = {
                            "cve_id": cve_id,
                            "title": entry.get("title", ""),
                            "description": entry.get("description", ""),
                            "severity": entry.get("severity", "UNKNOWN").upper(),
                            "cvss": float(entry.get("cvss", 0.0)),
                            "cwe": entry.get("cwe"),
                            "affected_products": entry.get("affected_services", []),
                            "remediation": entry.get("remediation", ""),
                            "references": entry.get("references", [
                                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                            ])
                        }
            logger.info(f"Loaded {len(self.cve_index)} CVE records from local knowledge base.")
        except Exception as e:
            logger.error(f"Error loading CVE knowledge base: {e}")

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Lookup CVE by identifier (e.g. 'CVE-2021-44228')."""
        if not cve_id:
            return None
        clean_id = cve_id.strip().upper()
        return self.cve_index.get(clean_id)

    def search_cves(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search CVE records by title, service, or keyword."""
        q = query.strip().lower()
        results = []
        for cve_id, data in self.cve_index.items():
            if (q in cve_id.lower() or
                q in data["title"].lower() or
                q in data["description"].lower() or
                any(q in str(s).lower() for s in data["affected_products"])):
                results.append(data)
                if len(results) >= limit:
                    break
        return results

    def count(self) -> int:
        return len(self.cve_index)


_CVE_KB: Optional[CVEKnowledgeBase] = None

def get_cve_kb() -> CVEKnowledgeBase:
    global _CVE_KB
    if _CVE_KB is None:
        _CVE_KB = CVEKnowledgeBase()
    return _CVE_KB

def get_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Convenience helper to retrieve CVE info."""
    return get_cve_kb().get_cve(cve_id)
