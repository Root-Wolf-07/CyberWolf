"""CYBERWOLF Cross-Platform Adapter Subsystem.

Provides OS detection, architecture inspection, privilege discovery,
network interface queries, and platform-specific capabilities.
"""

import os
import sys
import platform
import socket
import subprocess
from typing import Dict, List, Any, Optional

class BasePlatformAdapter:
    """Base adapter for OS-specific operations."""
    def __init__(self):
        self.os_type = platform.system().lower()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.architecture = platform.machine()
        self.python_version = platform.python_version()

    def get_os_display_name(self) -> str:
        return f"{platform.system()} {platform.release()} ({self.architecture})"

    def is_elevated(self) -> bool:
        """Check if running with root/administrator privileges."""
        try:
            if hasattr(os, 'geteuid'):
                return os.geteuid() == 0
            # Windows fallback
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def get_shell(self) -> str:
        return os.environ.get("SHELL") or os.environ.get("COMSPEC", "unknown")

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Return discovered network interfaces and IP addresses."""
        interfaces = []
        try:
            # Standard hostname/ip resolution
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            interfaces.append({
                "name": "default",
                "ip": local_ip,
                "hostname": hostname,
                "loopback": False
            })
        except Exception:
            pass

        # Loopback
        interfaces.append({
            "name": "lo/loopback",
            "ip": "127.0.0.1",
            "hostname": "localhost",
            "loopback": True
        })
        return interfaces

    def get_platform_info(self) -> Dict[str, Any]:
        return {
            "os_name": self.get_os_display_name(),
            "os_type": self.os_type,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "is_elevated": self.is_elevated(),
            "shell": self.get_shell(),
            "interfaces": self.get_network_interfaces()
        }


class MacOSAdapter(BasePlatformAdapter):
    """Adapter for macOS systems."""
    def get_os_display_name(self) -> str:
        mac_ver = platform.mac_ver()[0]
        return f"macOS {mac_ver} ({self.architecture})"

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        interfaces = super().get_network_interfaces()
        try:
            out = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=3)
            if out.returncode == 0:
                for iface in out.stdout.strip().split():
                    if not any(i["name"] == iface for i in interfaces):
                        interfaces.append({"name": iface, "ip": "Dynamic/Active", "loopback": iface.startswith("lo")})
        except Exception:
            pass
        return interfaces


class LinuxAdapter(BasePlatformAdapter):
    """Adapter for Linux systems (Debian, Ubuntu, Kali, etc.)."""
    def __init__(self):
        super().__init__()
        self.distro_name = self._detect_distro()

    def _detect_distro(self) -> str:
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            return line.strip().split("=", 1)[1].strip('"\'')
            except Exception:
                pass
        return "Linux"

    def get_os_display_name(self) -> str:
        return f"{self.distro_name} ({self.architecture})"


class WindowsAdapter(BasePlatformAdapter):
    """Adapter for Microsoft Windows systems."""
    def get_os_display_name(self) -> str:
        win_ver = platform.win32_ver()[0]
        return f"Windows {win_ver} ({self.architecture})"


def get_platform_adapter() -> BasePlatformAdapter:
    """Factory method to return the active OS adapter."""
    system = platform.system().lower()
    if system == "darwin":
        return MacOSAdapter()
    elif system == "windows":
        return WindowsAdapter()
    else:
        return LinuxAdapter()
