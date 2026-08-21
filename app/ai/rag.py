"""CYBERWOLF Local Security Knowledge Base & RAG Engine."""

import os
import json
import math
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.core.config import get_config
from app.core.logger import get_logger

logger = get_logger()

def tokenize(text: str) -> List[str]:
    """Simple alphanumeric tokenization and lowercase normalization."""
    return re.findall(r'[a-zA-Z0-9_\-]+', text.lower())

class LocalSecurityRAG:
    """Local vector/keyword RAG retrieval over CVEs, OWASP playbooks, and security notes."""
    
    def __init__(self, knowledge_dir: Optional[str] = None):
        self.config = get_config()
        self.knowledge_dir = Path(knowledge_dir or (self.config.base_dir / "knowledge")).resolve()
        self.documents: List[Dict[str, Any]] = []
        self._load_knowledge()

    def _load_knowledge(self):
        """Ingest all JSON and markdown files in the knowledge directory."""
        self.documents.clear()
        if not self.knowledge_dir.exists():
            return

        # Load CVE database
        cve_file = self.knowledge_dir / "cve_database.json"
        if cve_file.exists():
            try:
                with open(cve_file, "r", encoding="utf-8") as f:
                    cves = json.load(f)
                    for item in cves:
                        doc_text = f"CVE: {item.get('cve')} Title: {item.get('title')} Severity: {item.get('severity')} Description: {item.get('description')} Remediation: {item.get('remediation')}"
                        self.documents.append({
                            "id": item.get("cve"),
                            "type": "CVE",
                            "title": item.get("title"),
                            "content": doc_text,
                            "raw": item,
                            "tokens": set(tokenize(doc_text))
                        })
            except Exception as e:
                logger.error(f"Error loading CVE database: {e}")

        # Load OWASP playbooks
        owasp_file = self.knowledge_dir / "owasp_playbooks.json"
        if owasp_file.exists():
            try:
                with open(owasp_file, "r", encoding="utf-8") as f:
                    owasps = json.load(f)
                    for item in owasps:
                        doc_text = f"OWASP Category: {item.get('category')} CWE: {item.get('cwe')} Summary: {item.get('summary')} Detection: {item.get('detection_strategy')} Remediation: {item.get('remediation')}"
                        self.documents.append({
                            "id": item.get("category"),
                            "type": "OWASP",
                            "title": item.get("category"),
                            "content": doc_text,
                            "raw": item,
                            "tokens": set(tokenize(doc_text))
                        })
            except Exception as e:
                logger.error(f"Error loading OWASP playbooks: {e}")

    def query(self, query_str: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Retrieve most relevant knowledge snippets based on Jaccard/TF token similarity."""
        query_tokens = set(tokenize(query_str))
        if not query_tokens or not self.documents:
            return []

        scored_docs = []
        for doc in self.documents:
            intersection = query_tokens.intersection(doc["tokens"])
            if not intersection:
                continue
            # Jaccard index similarity score
            score = len(intersection) / len(query_tokens.union(doc["tokens"]))
            # Boost exact CVE matches
            for t in query_tokens:
                if t in doc["id"].lower():
                    score += 0.5
            scored_docs.append((score, doc))

        scored_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored_docs[:top_k]]

    def get_context_str(self, query_str: str) -> str:
        """Format retrieved knowledge documents as prompt context string."""
        matches = self.query(query_str, top_k=2)
        if not matches:
            return "No matching local knowledge base records found."

        snippets = []
        for m in matches:
            snippets.append(f"[{m['type']}: {m['title']}]\n{m['content']}")
        return "\n\n".join(snippets)

_RAG_INSTANCE: Optional[LocalSecurityRAG] = None

def get_rag() -> LocalSecurityRAG:
    global _RAG_INSTANCE
    if _RAG_INSTANCE is None:
        _RAG_INSTANCE = LocalSecurityRAG()
    return _RAG_INSTANCE
