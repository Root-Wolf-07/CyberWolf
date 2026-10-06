"""CYBERWOLF Cryptographic Evidence Engine (V2).

Provides forensic evidence preservation and provenance tracking:
- Structured Evidence creation and SQLite persistence
- Cryptographic SHA-256 hashing for tamper detection
- Raw artifact file vault management
- Traceability between Findings, Evidence, and ToolRuns
"""

from app.evidence.vault import EvidenceVault, get_evidence_vault

__all__ = ["EvidenceVault", "get_evidence_vault"]
