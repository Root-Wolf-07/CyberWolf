"""Unit tests for BDIE Exact Location Engine."""

import pytest
from app.detection.exact_location import ExactLocationEngine, ExactLocation


class TestExactLocationEngine:
    """Test suite for exact affected location resolution."""

    def test_web_location_full_hierarchy(self):
        engine = ExactLocationEngine()
        loc = engine.resolve_location(
            target="https://sec-lab.example.org:8443/api/v1/auth/login",
            port=8443,
            url="https://sec-lab.example.org:8443/api/v1/auth/login",
            http_method="POST",
            endpoint="/api/v1/auth/login",
            parameter="username"
        )

        assert loc.domain == "sec-lab.example.org"
        assert loc.scheme == "https"
        assert loc.hostname == "sec-lab.example.org"
        assert loc.port == 8443
        assert loc.protocol in ["tcp", "https"]
        assert loc.http_method == "POST"
        assert loc.endpoint == "/api/v1/auth/login"
        assert loc.parameter == "username"

        hierarchy = loc.format_hierarchy()
        assert "sec-lab.example.org" in hierarchy
        assert "POST" in hierarchy
        assert "/api/v1/auth/login" in hierarchy
        assert "username" in hierarchy

    def test_network_location_resolution(self):
        engine = ExactLocationEngine()
        loc = engine.resolve_location(
            target="192.168.1.50",
            port=22,
            protocol="tcp",
            service="ssh",
            service_version="OpenSSH 8.9p1"
        )

        assert loc.ip_address == "192.168.1.50"
        assert loc.port == 22
        assert loc.protocol == "tcp"
        assert loc.service == "ssh"
        assert loc.service_version == "OpenSSH 8.9p1"
        assert loc.parameter is None
        assert "22/tcp" in loc.summary() and "ssh" in loc.summary()

    def test_config_location_resolution(self):
        engine = ExactLocationEngine()
        loc = engine.resolve_location(
            target="sec-lab.example.org",
            config_location="HTTP Security Headers -> Strict-Transport-Security"
        )

        assert loc.config_location == "HTTP Security Headers -> Strict-Transport-Security"
        assert "Config: HTTP Security Headers" in loc.summary()

    def test_source_code_location_resolution(self):
        engine = ExactLocationEngine()
        loc = engine.resolve_location(
            target="internal-repo",
            source_file="app/auth/views.py",
            source_line=142
        )

        assert loc.source_file == "app/auth/views.py"
        assert loc.source_line == 142
        assert "app/auth/views.py:142" in loc.summary()

    def test_no_fabrication_when_data_missing(self):
        engine = ExactLocationEngine()
        loc = engine.resolve_location(target="10.0.0.1")

        assert loc.port is None
        assert loc.parameter is None
        assert loc.source_file is None
        assert loc.config_location is None
        assert loc.service_version is None
        assert loc.summary() == "10.0.0.1"

    def test_parse_web_target_url(self):
        engine = ExactLocationEngine()
        domain, scheme, port, endpoint = engine.parse_web_target("https://portal.target.com/console/admin")
        assert domain == "portal.target.com"
        assert scheme == "https"
        assert port == 443
        assert endpoint == "/console/admin"
