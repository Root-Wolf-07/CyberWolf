"""CYBERWOLF Exact Location Engine (BDIE V2).

Identifies the most precise location supported by actual evidence:
- Web: Domain -> Scheme -> Hostname -> Port -> URL -> HTTP Method -> Endpoint -> Parameter
- Network: Asset -> IP Address -> Port -> Protocol -> Service -> Version
- Configuration: Host -> Configuration Area -> Setting -> Observed Value -> Expected Secure State
- Source Code: Repository -> Commit -> File -> Class -> Function -> Line -> Code Pattern (only when real source exists)

Strict rule: Never fabricate or invent missing parameters, files, or line numbers.
"""

import os
import re
import urllib.parse
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple


@dataclass
class ExactLocation:
    """Represents the structured, verified location of a vulnerability."""
    location_type: str = "GENERIC"  # 'WEB', 'NETWORK', 'CONFIGURATION', 'SOURCE_CODE', 'GENERIC'

    # Common
    target: str = ""
    host: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None

    # Web Vulnerability
    scheme: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None

    # Network / Service
    service: Optional[str] = None
    service_version: Optional[str] = None

    # Configuration Vulnerability
    config_area: Optional[str] = None
    config_setting: Optional[str] = None
    config_observed: Optional[str] = None
    config_expected: Optional[str] = None

    # Source Code Vulnerability (Only when source code is actually present)
    repository: Optional[str] = None
    commit_hash: Optional[str] = None
    source_file: Optional[str] = None
    source_class: Optional[str] = None
    source_function: Optional[str] = None
    source_line: Optional[int] = None
    code_pattern: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with null fields preserved."""
        return asdict(self)

    @property
    def hostname(self) -> Optional[str]:
        return self.host or self.domain

    @property
    def config_location(self) -> Optional[str]:
        return self.config_area

    def __iter__(self):
        """Allow tuple unpacking: domain, scheme, port, endpoint = loc."""
        return iter((self.domain or self.host or self.target, self.scheme or ("https" if self.port == 443 else "http"), self.port or (443 if self.scheme == "https" else 80), self.endpoint or "/"))

    def summary(self) -> str:
        """Return concise human-readable exact location line."""
        if self.location_type == "WEB":
            meth = f"{self.http_method} " if self.http_method else ""
            endp = self.endpoint or self.url or self.target
            param_str = f" [param: {self.parameter}]" if self.parameter else ""
            port_str = f":{self.port}" if self.port and self.port not in [80, 443] else ""
            return f"{meth}{self.host or self.domain or self.target}{port_str}{endp}{param_str}"

        if self.location_type == "NETWORK":
            p = f":{self.port}" if self.port is not None else ""
            proto = f"/{self.protocol}" if self.protocol else ""
            svc = f" ({self.service}" if self.service else ""
            ver = f" {self.service_version}" if self.service_version else ""
            close_svc = ")" if svc else ""
            return f"{self.ip_address or self.host or self.target}{p}{proto}{svc}{ver}{close_svc}"

        if self.location_type == "CONFIGURATION":
            if self.config_area and "->" in self.config_area:
                return f"Config: {self.config_area.split('->')[0].strip()}"
            elif self.config_area:
                return f"Config: {self.config_area}"
            setting = self.config_setting or "Configuration"
            return f"{self.host or self.target} -> {setting}"

        if self.location_type == "SOURCE_CODE":
            line_str = f":{self.source_line}" if self.source_line is not None else ""
            fn_str = f" in {self.source_function}()" if self.source_function else ""
            return f"{self.source_file or 'Source'}{line_str}{fn_str}"

        return self.target or "Unknown Location"

    def format_hierarchy(self) -> str:
        """Format the exact vertical location hierarchy."""
        lines = []
        if self.location_type == "WEB":
            lines.append("Domain:       " + (self.domain or "Not identified"))
            lines.append("Scheme:       " + (self.scheme or ("https" if self.port == 443 else "http")))
            lines.append("Hostname:     " + (self.host or "Not identified"))
            lines.append("Port:         " + (str(self.port) if self.port else "Not identified"))
            if self.url:
                lines.append("URL:          " + self.url)
            if self.http_method:
                lines.append("HTTP Method:  " + self.http_method)
            lines.append("Endpoint:     " + (self.endpoint or "Not identified"))
            lines.append("Parameter:    " + (self.parameter if self.parameter else "None (Endpoint / Header level)"))

        elif self.location_type == "NETWORK":
            lines.append("Target/Asset: " + (self.host or self.target))
            lines.append("IP Address:   " + (self.ip_address or "Not resolved"))
            lines.append("Port:         " + (str(self.port) if self.port is not None else "All / Host-level"))
            lines.append("Protocol:     " + (self.protocol.upper() if self.protocol else "TCP"))
            lines.append("Service:      " + (self.service or "Not identified"))
            lines.append("Version:      " + (self.service_version if self.service_version else "Not fingerprinted"))

        elif self.location_type == "CONFIGURATION":
            lines.append("Host:         " + (self.host or self.target))
            lines.append("Area:         " + (self.config_area or "General Security Configuration"))
            lines.append("Setting:      " + (self.config_setting or "Not identified"))
            lines.append("Observed:     " + (self.config_observed or "Not recorded"))
            lines.append("Expected:     " + (self.config_expected or "Compliant Secure Baseline"))

        elif self.location_type == "SOURCE_CODE":
            if self.repository:
                lines.append("Repository:   " + self.repository)
            if self.commit_hash:
                lines.append("Commit:       " + self.commit_hash)
            lines.append("File:         " + (self.source_file or "Not identified"))
            if self.source_class:
                lines.append("Class:        " + self.source_class)
            if self.source_function:
                lines.append("Function:     " + self.source_function + "()")
            if self.source_line is not None:
                lines.append("Line:         " + str(self.source_line))
            if self.code_pattern:
                lines.append("Code Pattern: " + self.code_pattern)

        else:
            lines.append("Target:       " + self.target)
            if self.host:
                lines.append("Host:         " + self.host)
            if self.port:
                lines.append("Port:         " + str(self.port))

        return "\n".join(lines)


class ExactLocationEngine:
    """Analyzes and resolves verified vulnerability locations across protocols and targets."""

    @classmethod
    def resolve_location(cls, finding: Any = None, **kwargs) -> ExactLocation:
        """Resolve the most specific ExactLocation for a Finding object, dictionary, or kwargs."""
        if finding is None:
            data = kwargs
        elif isinstance(finding, dict):
            data = {**finding, **kwargs}
        elif hasattr(finding, "__dict__"):
            data = {k: getattr(finding, k, None) for k in dir(finding) if not k.startswith("_")}
            data.update(kwargs)
        else:
            data = kwargs

        f_get = data.get

        target = f_get("target") or ""
        url = f_get("url")
        endpoint = f_get("endpoint")
        method = f_get("http_method")
        param = f_get("parameter")
        host = f_get("host")
        port = f_get("port")
        protocol = f_get("protocol") or "tcp"
        service = f_get("service")
        service_ver = f_get("service_version")

        config_location = f_get("config_location")
        config_area = f_get("config_area") or config_location
        config_setting = f_get("config_setting")
        config_observed = f_get("config_observed")
        config_expected = f_get("config_expected")

        source_file = f_get("source_file")
        source_line = f_get("source_line")
        source_func = f_get("source_function")

        # 1. Check if source code location is present
        if source_file:
            return ExactLocation(
                location_type="SOURCE_CODE",
                target=target,
                host=host,
                source_file=source_file,
                source_line=source_line,
                source_function=source_func
            )

        # 2. Check if configuration location is present
        if config_area or config_setting:
            return ExactLocation(
                location_type="CONFIGURATION",
                target=target,
                host=host or target,
                config_area=config_area,
                config_setting=config_setting,
                config_observed=config_observed,
                config_expected=config_expected
            )

        # 3. Check if web vulnerability location
        candidate_url = url or (target if target.startswith("http://") or target.startswith("https://") else None)
        if candidate_url or endpoint or param or (port in [80, 443, 8080, 8443]):
            parsed = urllib.parse.urlparse(candidate_url) if candidate_url else None
            scheme = parsed.scheme if parsed and parsed.scheme else ("https" if port == 443 else "http")
            hostname = parsed.hostname if parsed and parsed.hostname else (host or target)
            parsed_port = parsed.port if parsed and parsed.port else (port or (443 if scheme == "https" else 80))
            resolved_endpoint = endpoint or (parsed.path if parsed and parsed.path else "/")

            # Parse query parameters if not explicitly provided
            resolved_param = param
            if not resolved_param and parsed and parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query)
                if len(query_params) == 1:
                    resolved_param = list(query_params.keys())[0]

            return ExactLocation(
                location_type="WEB",
                target=target,
                host=hostname,
                domain=hostname,
                scheme=scheme,
                protocol=protocol or scheme,
                port=parsed_port,
                url=candidate_url or f"{scheme}://{hostname}:{parsed_port}{resolved_endpoint}",
                http_method=method or "GET",
                endpoint=resolved_endpoint,
                parameter=resolved_param
            )

        # 4. Check if network vulnerability location
        if port is not None or service:
            candidate_ip = host or target
            is_ip = bool(candidate_ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", candidate_ip))
            return ExactLocation(
                location_type="NETWORK",
                target=target,
                host=host or target,
                ip_address=candidate_ip if is_ip else None,
                port=port,
                protocol=protocol,
                service=service,
                service_version=service_ver
            )

        # 5. Fallback generic
        return ExactLocation(
            location_type="GENERIC",
            target=target,
            host=host or target
        )

    @classmethod
    def parse_web_target(cls, target_url: str, method: str = "GET",
                           endpoint: Optional[str] = None, parameter: Optional[str] = None) -> ExactLocation:
        """Parse a web target into an ExactLocation representation."""
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"http://{target_url}"

        parsed = urllib.parse.urlparse(target_url)
        scheme = parsed.scheme
        hostname = parsed.hostname or target_url
        port = parsed.port or (443 if scheme == "https" else 80)
        path = endpoint or (parsed.path if parsed.path else "/")

        resolved_param = parameter
        if not resolved_param and parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            if len(params) == 1:
                resolved_param = list(params.keys())[0]

        return ExactLocation(
            location_type="WEB",
            target=target_url,
            host=hostname,
            domain=hostname,
            scheme=scheme,
            port=port,
            url=target_url,
            http_method=method.upper(),
            endpoint=path,
            parameter=resolved_param
        )


def get_exact_location(finding: Any) -> ExactLocation:
    """Convenience accessor to resolve exact location for finding."""
    return ExactLocationEngine.resolve_location(finding)
