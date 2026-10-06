"""CYBERWOLF Finding Normalizer.

Transforms disparate scanner outputs (Nmap, Nuclei, Nikto, ffuf, TShark,
native engines) into consistent, strongly-typed Finding domain objects.
"""

import uuid
import re
from typing import Dict, List, Any, Optional, Union
from app.database.models import Finding, SeverityLevel, ConfidenceLevel, FindingStatus


class FindingNormalizer:
    """Normalizes raw scanner finding dictionaries and objects into canonical Finding instances."""

    SEVERITY_MAP = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "FATAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MEDIUM": SeverityLevel.MEDIUM,
        "MED": SeverityLevel.MEDIUM,
        "WARN": SeverityLevel.MEDIUM,
        "WARNING": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
        "INFO": SeverityLevel.INFO,
        "INFORMATIONAL": SeverityLevel.INFO,
        "UNKNOWN": SeverityLevel.INFO
    }

    CONFIDENCE_MAP = {
        "CONFIRMED": ConfidenceLevel.CONFIRMED,
        "CERTAIN": ConfidenceLevel.CONFIRMED,
        "HIGH": ConfidenceLevel.HIGH,
        "MEDIUM": ConfidenceLevel.MEDIUM,
        "MED": ConfidenceLevel.MEDIUM,
        "LOW": ConfidenceLevel.LOW
    }

    def normalize_severity(self, sev_raw: str) -> SeverityLevel:
        """Standardize raw tool severity string to canonical SeverityLevel."""
        cleaned = str(sev_raw or "INFO").strip().upper()
        return self.SEVERITY_MAP.get(cleaned, SeverityLevel.INFO)

    def normalize(self, raw: Union[Finding, Dict[str, Any]], target: str,
                  source_tool: str = "CYBERWOLF Engine") -> Finding:
        """Normalize a single finding dictionary or existing Finding."""
        if isinstance(raw, Finding):
            # Already a Finding, ensure target and source_tool are set
            if not raw.target:
                raw.target = target
            if source_tool and source_tool not in raw.source_tools:
                raw.source_tools.append(source_tool)
            return raw

        title = raw.get("vulnerability") or raw.get("title") or "Security Finding"
        sev_raw = str(raw.get("severity", "INFO")).upper()
        severity = self.SEVERITY_MAP.get(sev_raw, SeverityLevel.INFO)

        conf_raw = str(raw.get("confidence", "HIGH")).upper()
        confidence = self.CONFIDENCE_MAP.get(conf_raw, ConfidenceLevel.HIGH)

        cve = raw.get("cve")
        cve_ids = []
        if isinstance(cve, list):
            cve_ids = [str(c).strip() for c in cve if c]
            cve_str = ", ".join(cve_ids)
        elif isinstance(cve, str) and cve.strip():
            cve_ids = [c.strip() for c in cve.split(",") if c.strip()]
            cve_str = cve.strip()
        else:
            cve_str = None

        cwe = raw.get("cwe")
        cwe_ids = []
        if isinstance(cwe, list):
            cwe_ids = [str(c).strip() for c in cwe if c]
            cwe_str = ", ".join(cwe_ids)
        elif isinstance(cwe, str) and cwe.strip():
            cwe_ids = [c.strip() for c in cwe.split(",") if c.strip()]
            cwe_str = cwe.strip()
        else:
            cwe_str = None

        tool_name = raw.get("source_tool") or source_tool
        source_tools = raw.get("source_tools") or [tool_name]

        finding_id = raw.get("id") or f"CW-{tool_name.upper()[:4]}-{uuid.uuid4().hex[:6].upper()}"

        from app.detection.exact_location import ExactLocationEngine
        loc = ExactLocationEngine.resolve_location(raw)

        url_val = raw.get("url") or loc.url
        endpoint_val = raw.get("endpoint") or loc.endpoint
        method_val = raw.get("http_method") or loc.http_method
        param_val = raw.get("parameter") or loc.parameter
        svc_ver_val = raw.get("service_version") or loc.service_version

        evidence_str = raw.get("evidence", "")
        observed = raw.get("observed_behavior") or evidence_str or title

        return Finding(
            id=finding_id,
            target=target,
            title=title,
            vulnerability=title,
            description=raw.get("description") or evidence_str or title,
            severity=severity,
            confidence=confidence,
            category=raw.get("category", self._infer_category(title, cwe_str)),
            asset_id=raw.get("asset_id"),
            host=raw.get("host") or loc.host or target,
            port=raw.get("port") or loc.port,
            protocol=raw.get("protocol") or loc.protocol or "tcp",
            service=raw.get("service") or loc.service,
            service_version=svc_ver_val,
            cve=cve_str,
            cve_ids=cve_ids,
            cwe=cwe_str,
            cwe_ids=cwe_ids,
            owasp_category=raw.get("owasp_category"),
            cvss=float(raw.get("cvss")) if raw.get("cvss") is not None else None,
            evidence=evidence_str,
            evidence_ids=raw.get("evidence_ids", []),
            source_tool=tool_name,
            source_tools=source_tools,
            remediation=raw.get("remediation"),
            status=FindingStatus.normalize(raw.get("status", "OPEN")),
            verified=bool(raw.get("verified", False)),
            url=url_val,
            http_method=method_val,
            endpoint=endpoint_val,
            parameter=param_val,
            component=raw.get("component"),
            technology=raw.get("technology"),
            config_area=raw.get("config_area") or loc.config_area,
            config_setting=raw.get("config_setting") or loc.config_setting,
            config_observed=raw.get("config_observed") or loc.config_observed,
            config_expected=raw.get("config_expected") or loc.config_expected,
            source_file=raw.get("source_file") or loc.source_file,
            source_line=raw.get("source_line") or loc.source_line,
            source_function=raw.get("source_function") or loc.source_function,
            source_commit=raw.get("source_commit") or loc.commit_hash,
            observed_behavior=observed,
            verified_behavior=raw.get("verified_behavior"),
            potential_impact=raw.get("potential_impact"),
            exploitability=raw.get("exploitability"),
            exploit_prerequisites=raw.get("exploit_prerequisites"),
            exploit_limitations=raw.get("exploit_limitations"),
            retest_status=raw.get("retest_status"),
            retest_result=raw.get("retest_result"),
            scan_id=raw.get("scan_id"),
            tool_run_id=raw.get("tool_run_id")
        )

    def normalize_list(self, raw_list: List[Union[Finding, Dict[str, Any]]],
                       target: str, source_tool: str = "CYBERWOLF Engine") -> List[Finding]:
        """Normalize a collection of findings."""
        return [self.normalize(item, target, source_tool) for item in raw_list]

    def _infer_category(self, title: str, cwe: Optional[str]) -> str:
        t = title.lower()
        if "sql" in t or (cwe and "89" in cwe):
            return "injection"
        if "header" in t or "cookie" in t or "ssl" in t or "tls" in t or "version" in t:
            return "web_misconfiguration"
        if "port" in t or "exposed" in t or "service" in t:
            return "network_exposure"
        if "traffic" in t or "packet" in t or "anomaly" in t:
            return "network_traffic"
        if "rce" in t or "remote code" in t:
            return "remote_code_execution"
        return "vulnerability"


_NORMALIZER: Optional[FindingNormalizer] = None

def get_normalizer() -> FindingNormalizer:
    global _NORMALIZER
    if _NORMALIZER is None:
        _NORMALIZER = FindingNormalizer()
    return _NORMALIZER
