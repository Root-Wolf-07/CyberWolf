"""CYBERWOLF Non-Destructive SQL Injection Testing Module."""

import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
from app.database.operations import create_scan, complete_scan, create_finding
from app.database.models import Finding
from app.core.logger import get_logger, audit_log

logger = get_logger()

SQL_ERROR_SIGNATURES = [
    ("MySQL", "you have an error in your sql syntax"),
    ("MySQL", "warning: mysql"),
    ("PostgreSQL", "pg_query(): query failed: error: syntax error"),
    ("PostgreSQL", "unterminated quoted string at or near"),
    ("MSSQL", "unclosed quotation mark after the character string"),
    ("MSSQL", "microsoft ole db provider for sql server"),
    ("Oracle", "ora-00933: sql command not properly ended"),
    ("Oracle", "ora-01756: quoted string not properly terminated"),
    ("SQLite", "sqlite3.operationalerror: near"),
    ("SQLite", "unrecognized token:")
]

SAFE_PROBES = [
    # Error probe
    ("error_single_quote", "'", "Single quote error probe"),
    ("error_double_quote", '"', "Double quote error probe"),
    # Boolean probes
    ("bool_true", "' OR '1'='1", "Boolean tautology probe"),
    ("bool_false", "' AND '1'='2", "Boolean contradiction probe")
]

class SQLiScanner:
    """Safely assesses authorized web targets for SQL injection vulnerabilities."""
    
    def test_endpoint(self, target_url: str, param_name: Optional[str] = None) -> Dict[str, Any]:
        """Perform non-destructive heuristic testing for SQL injection flaws."""
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        scan_id = create_scan("sqli", target_url, mode="SAFE_SCAN")
        logger.info(f"Starting SQL injection assessment on {target_url} (Scan ID: {scan_id})")
        audit_log("SQLI_TEST", "PROBE", target=target_url, decision="PROCEEDED")

        findings: List[Finding] = []
        tested_params = []

        if not params and not param_name:
            # Test default parameter if URL has none
            test_url = target_url + ("&" if "?" in target_url else "?") + "id=1"
            parsed = urllib.parse.urlparse(test_url)
            params = urllib.parse.parse_qs(parsed.query)

        # Baseline request
        try:
            baseline_resp = requests.get(target_url, timeout=8, verify=False,
                                         headers={"User-Agent": "CYBERWOLF SQL Security Probe"})
            baseline_len = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except Exception as e:
            complete_scan(scan_id, "FAILED")
            return {"success": False, "error": f"Failed to connect to target: {e}"}

        target_params = [param_name] if param_name else list(params.keys())

        for p in target_params:
            tested_params.append(p)
            base_val = params.get(p, ["1"])[0]
            
            # 1. Test Error-based Injection
            for probe_id, payload, probe_desc in SAFE_PROBES[:2]:
                mutated_query = dict(params)
                mutated_query[p] = base_val + payload
                encoded_query = urllib.parse.urlencode(mutated_query, doseq=True)
                probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_query, parsed.fragment))
                
                try:
                    res = requests.get(probe_url, timeout=8, verify=False)
                    res_lower = res.text.lower()
                    
                    for db_engine, sig in SQL_ERROR_SIGNATURES:
                        if sig in res_lower:
                            f = Finding(
                                id=f"CW-SQLI-{datetime.now().strftime('%Y%m%d%H%M%S')}-{p}",
                                target=target_url,
                                vulnerability=f"SQL Injection via Parameter '{p}' ({db_engine})",
                                severity="CRITICAL",
                                evidence=f"Heuristic error reflection triggered by payload '{payload}'. Matched DB error signature: '{sig}'",
                                confidence="HIGH",
                                cve="CWE-89",
                                cwe="CWE-89",
                                source_tool="CYBERWOLF SQL Engine",
                                remediation="Use parameterized SQL queries (PreparedStatements / ORM) and strict input validation."
                            )
                            create_finding(f)
                            findings.append(f)
                            break
                except Exception:
                    pass

        complete_scan(scan_id, "COMPLETED", findings_count=len(findings))
        return {
            "success": True,
            "scan_id": scan_id,
            "target": target_url,
            "tested_parameters": tested_params,
            "is_vulnerable": len(findings) > 0,
            "findings_count": len(findings),
            "findings": [vars(f) for f in findings]
        }
