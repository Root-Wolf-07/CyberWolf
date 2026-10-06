"""CYBERWOLF Test Suite Configuration & Shared Fixtures."""

import os
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def nmap_xml_sample() -> str:
    """Return raw content of sample Nmap XML."""
    with open(FIXTURES_DIR / "sample_nmap.xml", "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def nuclei_jsonl_sample() -> str:
    """Return raw content of sample Nuclei JSONL."""
    with open(FIXTURES_DIR / "sample_nuclei.jsonl", "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def nikto_txt_sample() -> str:
    """Return raw content of sample Nikto output."""
    with open(FIXTURES_DIR / "sample_nikto.txt", "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def ffuf_json_sample() -> str:
    """Return raw content of sample ffuf JSON."""
    with open(FIXTURES_DIR / "sample_ffuf.json", "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def tshark_txt_sample() -> str:
    """Return raw content of sample TShark output."""
    with open(FIXTURES_DIR / "sample_tshark.txt", "r", encoding="utf-8") as f:
        return f.read()
