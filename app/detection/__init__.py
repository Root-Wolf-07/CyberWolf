"""CYBERWOLF Detection Intelligence Package (V2).

Includes:
- FindingNormalizer: Standardizes disparate tool findings into canonical models
- FindingDeduplicator: Deterministic finding deduplication with provenance merging
- FindingCorrelator: Deterministic cross-tool finding and asset correlation
- RiskEngine: Explainable, transparent multi-factor security risk scoring
"""

from app.detection.normalizer import FindingNormalizer, get_normalizer
from app.detection.deduplicator import FindingDeduplicator, get_deduplicator
from app.detection.correlator import FindingCorrelator, get_correlator
from app.detection.risk_engine import RiskEngine, get_risk_engine

__all__ = [
    "FindingNormalizer", "get_normalizer",
    "FindingDeduplicator", "get_deduplicator",
    "FindingCorrelator", "get_correlator",
    "RiskEngine", "get_risk_engine"
]
