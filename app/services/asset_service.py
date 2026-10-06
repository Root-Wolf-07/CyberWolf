"""CYBERWOLF Asset Inventory & Risk Service (V2).

Provides unified tracking, deduplication, and risk posture calculation
for discovered network and web assets.
"""

from typing import Dict, List, Any, Optional
from app.database.operations import get_all_assets, get_asset, get_all_findings
from app.database.models import Finding
from app.detection.risk_engine import get_risk_engine


class AssetService:
    """Manages asset inventory, technology discovery, and attack surface posture."""

    def __init__(self):
        self.risk_engine = get_risk_engine()

    def list_assets(self) -> List[Dict[str, Any]]:
        """Retrieve all discovered assets with calculated risk level."""
        return get_all_assets()

    def get_asset_detail(self, asset_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve asset with its associated findings and ports."""
        asset = get_asset(asset_id)
        if not asset:
            return None

        # Fetch findings for this asset
        target_ident = asset.get("target_identifier")
        ip = asset.get("ip_address")
        findings = get_all_findings(target=target_ident or ip)

        return {
            "asset": asset,
            "findings_count": len(findings),
            "findings": findings
        }


_ASSET_SERVICE: Optional[AssetService] = None

def get_asset_service() -> AssetService:
    global _ASSET_SERVICE
    if _ASSET_SERVICE is None:
        _ASSET_SERVICE = AssetService()
    return _ASSET_SERVICE
