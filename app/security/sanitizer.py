"""CYBERWOLF Target Validation & Input Sanitization Subsystem (V2).

Provides robust, multi-layer networking parsing and validation:
- IPv4 / IPv6 validation via standard library ipaddress
- CIDR range parsing and safety constraints
- Hostname RFC 1123 compliance
- URL scheme allowlisting (http/https only)
- host:port format parsing
- Strict command injection metacharacter detection
- Directory traversal prevention
"""

import re
import ipaddress
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Optional, Tuple
from app.core.exceptions import TargetValidationError

# Strict injection prevention
DANGEROUS_SHELL_CHARS = re.compile(r'[;&|`$><!\\\'"\n\r]')
SAFE_HOSTNAME_REGEX = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)
SAFE_PORT_REGEX = re.compile(r'^([1-9][0-9]{0,4})(-[1-9][0-9]{0,4})?$')
ALLOWED_URL_SCHEMES = {"http", "https"}


class TargetType:
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    URL = "url"
    HOST_PORT = "host_port"


@dataclass
class TargetValidationResult:
    """Structured representation of a parsed and validated target."""
    raw_target: str
    normalized: str
    target_type: str  # 'ipv4', 'ipv6', 'cidr', 'hostname', 'url', 'host_port'
    host: str
    port: Optional[int] = None
    scheme: Optional[str] = None
    is_loopback: bool = False
    is_private: bool = False
    is_multicast: bool = False

    @property
    def is_valid(self) -> bool:
        return True

    @property
    def clean_target(self) -> str:
        return self.normalized

    @property
    def ip_address(self) -> Optional[str]:
        return self.host if self.target_type in ["ipv4", "ipv6"] else None

    @property
    def hostname(self) -> Optional[str]:
        return self.host if self.target_type == "hostname" else None


def parse_and_validate_target(target: str) -> TargetValidationResult:
    """Parse, inspect, and validate any target representation.
    
    Raises:
        TargetValidationError: If input contains illegal characters or invalid networking syntax.
    """
    if not target or not isinstance(target, str):
        raise TargetValidationError(
            "Target cannot be empty.",
            remediation="Provide an IP address, CIDR range, hostname, or URL."
        )

    clean = target.strip()

    # 1. Detect command injection characters
    if DANGEROUS_SHELL_CHARS.search(clean):
        raise TargetValidationError(
            f"Target contains forbidden shell characters: '{clean}'",
            remediation="Ensure target input contains only valid host, IP, or URL characters."
        )

    # 2. Check for URL
    if clean.startswith("http://") or clean.startswith("https://") or "://" in clean:
        try:
            parsed = urlparse(clean)
            if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
                raise TargetValidationError(
                    f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.",
                    remediation="Use an http:// or https:// URL."
                )
            if not parsed.hostname:
                raise TargetValidationError(f"Invalid URL missing hostname: '{clean}'")

            # Validate the embedded hostname/IP
            host_str = parsed.hostname
            is_loopback = False
            is_private = False
            try:
                ip_obj = ipaddress.ip_address(host_str)
                is_loopback = ip_obj.is_loopback
                is_private = ip_obj.is_private
            except ValueError:
                if host_str in ["localhost", "ip6-localhost"]:
                    is_loopback = True

            return TargetValidationResult(
                raw_target=target,
                normalized=clean,
                target_type="url",
                host=host_str,
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                scheme=parsed.scheme.lower(),
                is_loopback=is_loopback,
                is_private=is_private
            )
        except TargetValidationError:
            raise
        except Exception as e:
            raise TargetValidationError(f"Malformed URL structure: {e}")

    # 3. Check for host:port format (e.g. 192.168.1.10:8080 or host.local:80)
    if ":" in clean and not clean.startswith("[") and clean.count(":") == 1:
        parts = clean.split(":")
        host_candidate = parts[0]
        port_candidate = parts[1]
        if port_candidate.isdigit():
            p_val = int(port_candidate)
            if 1 <= p_val <= 65535:
                # Recursively validate host part
                res = parse_and_validate_target(host_candidate)
                return TargetValidationResult(
                    raw_target=target,
                    normalized=f"{res.host}:{p_val}",
                    target_type="host_port",
                    host=res.host,
                    port=p_val,
                    is_loopback=res.is_loopback,
                    is_private=res.is_private
                )

    # 4. Check for CIDR notation
    if "/" in clean:
        try:
            net = ipaddress.ip_network(clean, strict=False)
            # Guard against overly broad ranges (e.g. 0.0.0.0/0 or /7)
            if net.prefixlen < 8:
                raise TargetValidationError(
                    f"CIDR prefix /{net.prefixlen} is dangerously broad and forbidden.",
                    remediation="Narrow scope to /16 or smaller subnet."
                )
            if net.prefixlen < 16 and not net.is_private and not net.is_loopback:
                raise TargetValidationError(
                    f"CIDR prefix /{net.prefixlen} is too broad for authorized scanning.",
                    remediation="Narrow scope to /16 or smaller subnet."
                )
            return TargetValidationResult(
                raw_target=target,
                normalized=str(net),
                target_type="cidr",
                host=str(net.network_address),
                is_loopback=net.is_loopback,
                is_private=net.is_private,
                is_multicast=net.is_multicast
            )
        except ValueError as e:
            raise TargetValidationError(f"Invalid CIDR network specification '{clean}': {e}")

    # 5. Check for IP address (IPv4 / IPv6)
    try:
        ip_obj = ipaddress.ip_address(clean)
        t_type = "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
        return TargetValidationResult(
            raw_target=target,
            normalized=str(ip_obj),
            target_type=t_type,
            host=str(ip_obj),
            is_loopback=ip_obj.is_loopback,
            is_private=ip_obj.is_private,
            is_multicast=ip_obj.is_multicast
        )
    except ValueError:
        pass

    # 6. Check for valid hostname / domain / localhost
    if clean.lower() in ["localhost", "ip6-localhost"]:
        return TargetValidationResult(
            raw_target=target,
            normalized="localhost",
            target_type="hostname",
            host="localhost",
            is_loopback=True,
            is_private=True
        )

    if len(clean) <= 253 and SAFE_HOSTNAME_REGEX.match(clean):
        return TargetValidationResult(
            raw_target=target,
            normalized=clean.lower(),
            target_type="hostname",
            host=clean.lower()
        )

    raise TargetValidationError(
        f"Invalid target format: '{clean}'. Expected IPv4, IPv6, CIDR, Hostname, or URL.",
        remediation="Provide a valid IP (e.g. 192.168.1.1), CIDR (192.168.1.0/24), hostname, or URL."
    )


def sanitize_target(target: str) -> str:
    """Validate and normalize a target string (backward-compatible)."""
    result = parse_and_validate_target(target)
    return result.normalized


def sanitize_ports(port_spec: str) -> str:
    """Validate port or port-range specification (e.g. '80', '1-1024', '80,443,8080')."""
    if not port_spec:
        return "1-1000"

    clean = port_spec.strip().replace(" ", "")
    parts = clean.split(",")
    for part in parts:
        if not SAFE_PORT_REGEX.match(part):
            raise TargetValidationError(
                f"Invalid port specification: '{part}'.",
                remediation="Use port numbers (e.g. 80,443) or valid ranges (e.g. 1-1024)."
            )
        if "-" in part:
            start_p, end_p = map(int, part.split("-"))
            if start_p < 1 or end_p > 65535 or start_p > end_p:
                raise TargetValidationError(f"Port range out of bounds: {part} (1-65535)")
        else:
            p_val = int(part)
            if p_val < 1 or p_val > 65535:
                raise TargetValidationError(f"Port number out of bounds: {part} (1-65535)")
    return clean


def sanitize_file_path(filename: str) -> str:
    """Ensure filenames do not perform directory traversal."""
    if not filename:
        raise TargetValidationError("Filename cannot be empty.")
    if ".." in filename or filename.startswith("/") or "\\" in filename:
        raise TargetValidationError(
            "Path traversal sequences and absolute paths are forbidden in filenames.",
            remediation="Provide a relative filename without '../' or directory separators."
        )
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)
