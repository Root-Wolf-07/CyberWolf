"""CYBERWOLF Tool Discovery & Diagnostics Engine."""

import shutil
import subprocess
from typing import Dict, List, Any, Optional
from app.core.platform_adapter import get_platform_adapter

# All 15 required security tools with their candidate executable names and install guides
SECURITY_TOOLS: Dict[str, Dict[str, Any]] = {
    "Nmap": {
        "binaries": ["nmap"],
        "category": "Network Discovery & Port Scanning",
        "install_guide": {
            "darwin": "brew install nmap",
            "debian": "sudo apt-get install -y nmap",
            "arch": "sudo pacman -S nmap",
            "windows": "winget install Insecure.Nmap"
        }
    },
    "Wireshark/tshark": {
        "binaries": ["tshark", "wireshark"],
        "category": "Packet Capture & Traffic Analysis",
        "install_guide": {
            "darwin": "brew install tshark",
            "debian": "sudo apt-get install -y tshark",
            "arch": "sudo pacman -S wireshark-cli",
            "windows": "winget install WiresharkFoundation.Wireshark"
        }
    },
    "Burp Suite": {
        "binaries": ["burpsuite", "burp", "/Applications/Burp Suite Community Edition.app/Contents/MacOS/JavaApplicationStub"],
        "category": "Web Application Proxy & Security Testing",
        "install_guide": {
            "darwin": "brew install --cask burp-suite",
            "debian": "sudo apt-get install -y burpsuite",
            "arch": "yay -S burpsuite",
            "windows": "winget install PortSwigger.BurpSuite.Community"
        }
    },
    "Metasploit": {
        "binaries": ["msfconsole", "msfvenom"],
        "category": "Controlled Penetration Testing Framework",
        "install_guide": {
            "darwin": "brew install metasploit",
            "debian": "sudo apt-get install -y metasploit-framework",
            "arch": "sudo pacman -S metasploit",
            "windows": "https://www.metasploit.com/download"
        }
    },
    "Gobuster": {
        "binaries": ["gobuster"],
        "category": "Directory/DNS/VHost Brute-Forcing",
        "install_guide": {
            "darwin": "brew install gobuster",
            "debian": "sudo apt-get install -y gobuster",
            "arch": "sudo pacman -S gobuster",
            "windows": "go install github.com/OJ/gobuster/v3@latest"
        }
    },
    "ffuf": {
        "binaries": ["ffuf"],
        "category": "Fast Web Fuzzer",
        "install_guide": {
            "darwin": "brew install ffuf",
            "debian": "sudo apt-get install -y ffuf",
            "arch": "sudo pacman -S ffuf",
            "windows": "go install github.com/ffuf/ffuf/v2@latest"
        }
    },
    "Nikto": {
        "binaries": ["nikto", "nikto.pl"],
        "category": "Web Server Vulnerability Scanner",
        "install_guide": {
            "darwin": "brew install nikto",
            "debian": "sudo apt-get install -y nikto",
            "arch": "sudo pacman -S nikto",
            "windows": "git clone https://github.com/sullo/nikto"
        }
    },
    "John the Ripper": {
        "binaries": ["john"],
        "category": "Password Security & Hash Auditing",
        "install_guide": {
            "darwin": "brew install john",
            "debian": "sudo apt-get install -y john",
            "arch": "sudo pacman -S john",
            "windows": "https://www.openwall.com/john/"
        }
    },
    "Hashcat": {
        "binaries": ["hashcat"],
        "category": "Advanced Password Recovery & Benchmark",
        "install_guide": {
            "darwin": "brew install hashcat",
            "debian": "sudo apt-get install -y hashcat",
            "arch": "sudo pacman -S hashcat",
            "windows": "winget install hashcat.hashcat"
        }
    },
    "Hydra": {
        "binaries": ["hydra"],
        "category": "Network Logon Authentication Tester",
        "install_guide": {
            "darwin": "brew install hydra",
            "debian": "sudo apt-get install -y hydra",
            "arch": "sudo pacman -S hydra",
            "windows": "https://github.com/vanhauser-thc/thc-hydra"
        }
    },
    "Aircrack-ng": {
        "binaries": ["aircrack-ng"],
        "category": "Wireless Security Assessment",
        "install_guide": {
            "darwin": "brew install aircrack-ng",
            "debian": "sudo apt-get install -y aircrack-ng",
            "arch": "sudo pacman -S aircrack-ng",
            "windows": "https://www.aircrack-ng.org/"
        }
    },
    "Kismet": {
        "binaries": ["kismet"],
        "category": "Wireless Network & Device Detector",
        "install_guide": {
            "darwin": "brew install kismet",
            "debian": "sudo apt-get install -y kismet",
            "arch": "sudo pacman -S kismet",
            "windows": "https://www.kismetwireless.net/"
        }
    },
    "BloodHound": {
        "binaries": ["bloodhound", "bloodhound-python"],
        "category": "Active Directory Attack Path Analysis",
        "install_guide": {
            "darwin": "pip install bloodhound",
            "debian": "sudo apt-get install -y bloodhound bloodhound-python",
            "arch": "yay -S bloodhound",
            "windows": "pip install bloodhound"
        }
    },
    "Impacket": {
        "binaries": ["impacket-secretsdump", "secretsdump.py", "impacket-psexec", "psexec.py"],
        "category": "Network Protocol & Pentest Toolkit",
        "install_guide": {
            "darwin": "pip install impacket",
            "debian": "sudo apt-get install -y python3-impacket",
            "arch": "sudo pacman -S python-impacket",
            "windows": "pip install impacket"
        }
    },
    "Nuclei": {
        "binaries": ["nuclei"],
        "category": "Template-based Vulnerability Assessment",
        "install_guide": {
            "darwin": "brew install nuclei",
            "debian": "sudo apt-get install -y nuclei",
            "arch": "yay -S nuclei",
            "windows": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        }
    }
}

SYSTEM_DEPENDENCIES: Dict[str, Dict[str, Any]] = {
    "Python": {"binaries": ["python3", "python"], "desc": "Execution runtime"},
    "Go": {"binaries": ["go"], "desc": "Security tools compiler"},
    "Java": {"binaries": ["java"], "desc": "Burp Suite & analyzer runtime"},
    "Git": {"binaries": ["git"], "desc": "Repository and template manager"},
    "Ollama": {"binaries": ["ollama"], "desc": "Local AI LLM inference engine"},
    "Docker": {"binaries": ["docker"], "desc": "Isolated containerized lab runner"}
}

class ToolDetector:
    """Discovers installed system and security tools on the host."""
    def __init__(self):
        self.platform = get_platform_adapter()

    def find_binary(self, candidate_binaries: List[str]) -> Optional[str]:
        """Search for binary in system PATH or standard absolute paths."""
        for b in candidate_binaries:
            found = shutil.which(b)
            if found:
                return found
            # Check absolute path directly
            if b.startswith("/") and shutil.which(b) is None:
                import os
                if os.path.exists(b):
                    return b
        return None

    def check_system_dependencies(self) -> Dict[str, Dict[str, Any]]:
        """Check status of core runtime dependencies."""
        results = {}
        for name, spec in SYSTEM_DEPENDENCIES.items():
            path = self.find_binary(spec["binaries"])
            version = None
            if path:
                try:
                    out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3)
                    version = (out.stdout or out.stderr or "").strip().split("\n")[0]
                except Exception:
                    version = "Detected"
            results[name] = {
                "installed": bool(path),
                "path": path,
                "version": version,
                "description": spec["desc"]
            }
        return results

    def check_security_tools(self) -> Dict[str, Dict[str, Any]]:
        """Check status of all 15 security tools."""
        results = {}
        os_key = "darwin" if self.platform.os_type == "darwin" else ("windows" if self.platform.os_type == "windows" else "debian")
        
        for name, spec in SECURITY_TOOLS.items():
            path = self.find_binary(spec["binaries"])
            install_cmd = spec["install_guide"].get(os_key, spec["install_guide"].get("debian", "Install manually"))
            results[name] = {
                "installed": bool(path),
                "path": path,
                "category": spec["category"],
                "install_command": install_cmd
            }
        return results

    def get_full_doctor_report(self) -> Dict[str, Any]:
        """Aggregate platform, system dependencies, and security tools."""
        return {
            "platform": self.platform.get_platform_info(),
            "dependencies": self.check_system_dependencies(),
            "security_tools": self.check_security_tools()
        }

_DETECTOR: Optional[ToolDetector] = None

def get_tool_detector() -> ToolDetector:
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = ToolDetector()
    return _DETECTOR
