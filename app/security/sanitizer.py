"""CYBERWOLF Input Sanitization & Command Injection Prevention."""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional
from app.core.exceptions import ValidationError

SAFE_HOSTNAME_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
SAFE_PORT_REGEX = re.compile(r'^([1-9][0-9]{0,4})(-[1-9][0-9]{0,4})?$')
DANGEROUS_SHELL_CHARS = re.compile(r'[;&|`$><!\\\'"\n\r]')

def sanitize_target(target: str) -> str:
    """Validate and normalize a target string (IP, CIDR, Hostname, URL)."""
    if not target or not isinstance(target, str):
        raise ValidationError("Target cannot be empty.")
    
    clean_target = target.strip()
    
    # Check for shell injection characters
    if DANGEROUS_SHELL_CHARS.search(clean_target):
        raise ValidationError(f"Target contains forbidden characters: {clean_target}")

    # Check if target is a URL
    if clean_target.startswith("http://") or clean_target.startswith("https://"):
        try:
            parsed = urlparse(clean_target)
            if not parsed.hostname:
                raise ValidationError(f"Invalid URL structure: {clean_target}")
            return clean_target
        except Exception as e:
            raise ValidationError(f"Invalid target URL: {e}")

    # Check if target is an IP or CIDR
    try:
        if "/" in clean_target:
            ipaddress.ip_network(clean_target, strict=False)
            return clean_target
        else:
            ipaddress.ip_address(clean_target)
            return clean_target
    except ValueError:
        pass

    # Check if hostname / domain
    if SAFE_HOSTNAME_REGEX.match(clean_target):
        return clean_target

    raise ValidationError(f"Invalid target format: '{clean_target}'. Expected IP, CIDR, Hostname, or URL.")

def sanitize_ports(port_spec: str) -> str:
    """Validate port or port-range specification (e.g. '80', '1-1024', '80,443,8080')."""
    if not port_spec:
        return "1-1000"
    
    clean = port_spec.strip().replace(" ", "")
    parts = clean.split(",")
    for part in parts:
        if not SAFE_PORT_REGEX.match(part):
            raise ValidationError(f"Invalid port specification: {part}")
        if "-" in part:
            start_p, end_p = map(int, part.split("-"))
            if start_p < 1 or end_p > 65535 or start_p > end_p:
                raise ValidationError(f"Port range out of bounds: {part}")
        else:
            p_val = int(part)
            if p_val < 1 or p_val > 65535:
                raise ValidationError(f"Port number out of bounds: {part}")
    return clean

def sanitize_file_path(filename: str) -> str:
    """Ensure filenames don't perform path traversal."""
    if not filename:
        raise ValidationError("Filename cannot be empty.")
    if ".." in filename or filename.startswith("/") or "\\" in filename:
        raise ValidationError("Path traversal or absolute paths forbidden in filename.")
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)
