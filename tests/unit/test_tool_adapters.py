"""Unit tests for CYBERWOLF Security Tool Adapters & Parser Fixtures."""

import pytest
from app.tools.adapters.nmap_adapter import NmapAdapter
from app.tools.adapters.nuclei_adapter import NucleiAdapter
from app.tools.adapters.nikto_adapter import NiktoAdapter
from app.tools.adapters.ffuf_adapter import FfufAdapter
from app.tools.adapters.tshark_adapter import TsharkAdapter
from app.database.models import Finding, SeverityLevel


def test_nmap_parser_with_xml_fixture(nmap_xml_sample):
    """Test Nmap XML output parsing and finding normalization."""
    adapter = NmapAdapter()
    parsed = adapter.parse_output(nmap_xml_sample)
    assert parsed.get("target") == "192.168.1.100"
    assert len(parsed.get("hosts", [])) >= 1

    # Test normalization
    findings = adapter.normalize_results(parsed, target="192.168.1.100")
    assert len(findings) >= 4
    for f in findings:
        assert isinstance(f, Finding)
        assert f.source_tool == "Nmap"
        assert f.port in [22, 80, 443, 3306]


def test_nuclei_parser_with_jsonl_fixture(nuclei_jsonl_sample):
    """Test Nuclei JSONL stream parsing and canonical finding normalization."""
    adapter = NucleiAdapter()
    parsed = adapter.parse_output(nuclei_jsonl_sample)
    assert len(parsed.get("findings", [])) == 3

    findings = adapter.normalize_results(parsed, target="192.168.1.100")
    assert len(findings) == 3

    # Check Log4j finding
    log4j = next((f for f in findings if "cve-2021-44228" in (f.cve or "").lower() or "log4j" in f.title.lower()), None)
    assert log4j is not None
    assert log4j.severity == SeverityLevel.CRITICAL
    assert log4j.source_tool == "Nuclei"


def test_nikto_parser_with_fixture(nikto_txt_sample):
    """Test Nikto text output parsing."""
    adapter = NiktoAdapter()
    parsed = adapter.parse_output(nikto_txt_sample)
    findings = adapter.normalize_results(parsed, target="192.168.1.100")
    assert len(findings) >= 2
    for f in findings:
        assert isinstance(f, Finding)
        assert f.source_tool == "Nikto"


def test_ffuf_parser_with_json_fixture(ffuf_json_sample):
    """Test ffuf JSON endpoint fuzzing output parsing."""
    adapter = FfufAdapter()
    parsed = adapter.parse_output(ffuf_json_sample)
    findings = adapter.normalize_results(parsed, target="192.168.1.100")
    assert len(findings) == 3
    # Verify .env finding promoted to HIGH
    env_finding = next((f for f in findings if ".env" in f.title), None)
    assert env_finding is not None
    assert env_finding.severity in [SeverityLevel.HIGH, SeverityLevel.MEDIUM]


def test_tshark_parser_with_fixture(tshark_txt_sample):
    """Test TShark packet capture output parsing."""
    adapter = TsharkAdapter()
    parsed = adapter.parse_output(tshark_txt_sample)
    findings = adapter.normalize_results(parsed, target="192.168.1.100")
    assert len(findings) >= 1
    assert any(f.source_tool == "TShark" for f in findings)


def test_command_construction_safe(monkeypatch):
    """Verify adapters construct command argument lists rather than raw strings without requiring tools in PATH."""
    nmap = NmapAdapter()
    monkeypatch.setattr(nmap, "is_available", lambda: True)
    nmap.binary_path = "/usr/bin/nmap"
    cmd = nmap.build_command("192.168.1.100", ports="80,443", scan_type="fast")
    assert isinstance(cmd, list)
    assert "nmap" in cmd[0].lower()
    assert "-p" in cmd
    assert "80,443" in cmd
    assert "192.168.1.100" in cmd
