"""Integration tests for CYBERWOLF Web REST API & Workstation."""

import pytest
import threading
import time
import requests
from app.web.server import CyberWolfServer


@pytest.fixture(scope="module")
def live_server():
    """Start local CyberWolf test server."""
    port = 8996
    server = CyberWolfServer(host="127.0.0.1", port=port)
    t = threading.Thread(target=server.start, daemon=True)
    t.start()
    time.sleep(0.5)
    yield f"http://127.0.0.1:{port}"
    server.stop()


def test_api_health(live_server):
    """Test /api/health endpoint."""
    res = requests.get(f"{live_server}/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["version"] == "2.0.0"


def test_api_status(live_server):
    """Test /api/status endpoint."""
    res = requests.get(f"{live_server}/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "tools" in data
    assert "summary" in data


def test_api_findings_and_triage(live_server):
    """Test listing findings and updating finding status."""
    res = requests.get(f"{live_server}/api/findings")
    assert res.status_code == 200
    data = res.json()
    assert "findings" in data

    if data["findings"]:
        f_id = data["findings"][0]["id"]
        # Update status
        up = requests.post(f"{live_server}/api/findings/{f_id}/status", json={"status": "CONFIRMED"})
        assert up.status_code == 200
        assert up.json()["status"] == "CONFIRMED"


def test_api_assets(live_server):
    """Test /api/assets endpoint."""
    res = requests.get(f"{live_server}/api/assets")
    assert res.status_code == 200
    assert "assets" in res.json()


def test_dashboard_ui_html(live_server):
    """Test / root endpoint delivers workstation dashboard."""
    res = requests.get(f"{live_server}/")
    assert res.status_code == 200
    assert "CYBERWOLF" in res.text
    assert "Security Operations Workstation" in res.text
