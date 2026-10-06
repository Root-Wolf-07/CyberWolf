"""Integration tests for CYBERWOLF Unified ScanService Pipeline."""

import pytest
from app.services.scan_service import get_scan_service
from app.security.authorization import add_authorized_target


def test_scan_service_pipeline_end_to_end():
    """Verify full end-to-end execution of scan pipeline on authorized target."""
    target = "127.0.0.1"
    # Target 127.0.0.1 is pre-authorized in config/targets.yaml under local-loopback

    service = get_scan_service()
    result = service.start_scan(
        target=target,
        scan_type="network",
        options={"ports": "80,443", "profile": "fast"},
        interactive_auth=False
    )

    assert result["target"] == target
    assert result["scan_id"].startswith("SCAN-")
    assert result["status"] == "COMPLETED"
    assert "tools_executed" in result
    assert "reports" in result
    assert "HTML" in result["reports"]
    assert "JSON" in result["reports"]
