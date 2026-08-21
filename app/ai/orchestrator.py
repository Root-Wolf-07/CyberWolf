"""CYBERWOLF AI Orchestrator & Specialist Agent Router."""

from typing import Dict, List, Any, Optional
from app.ai.ollama_client import get_ollama_client
from app.ai.prompts import get_system_prompt
from app.ai.rag import get_rag
from app.database.operations import save_ai_analysis
from app.core.logger import get_logger

logger = get_logger()

class AIOrchestrator:
    """Coordinates specialist prompts, local RAG retrieval, and Ollama inference."""
    
    def __init__(self):
        self.client = get_ollama_client()
        self.rag = get_rag()

    def analyze_network_scan(self, target: str, hosts_data: List[Dict[str, Any]], scan_id: Optional[str] = None) -> str:
        """Analyze discovered network hosts, open ports, and exposed services."""
        role = "Network Security Analyst"
        system_prompt = get_system_prompt(role)
        
        rag_context = self.rag.get_context_str(f"network exposure {target}")
        
        prompt = f"""
TARGET: {target}

STRUCTURED SCAN EVIDENCE:
{hosts_data}

LOCAL KNOWLEDGE CONTEXT:
{rag_context}

TASK:
Provide a professional security assessment of the scan results.
Identify high-risk exposed services, potential misconfigurations, and recommended mitigation actions.
"""
        success, response = self.client.generate(prompt, system_prompt=system_prompt)
        if success:
            save_ai_analysis(specialist_role=role, model_name=self.client.get_active_model() or "Ollama",
                             analysis_text=response, scan_id=scan_id)
        return response

    def analyze_vulnerability_finding(self, finding: Dict[str, Any], scan_id: Optional[str] = None) -> str:
        """Analyze a specific vulnerability finding with CVE/CWE grounding."""
        role = "Vulnerability Analyst"
        system_prompt = get_system_prompt(role)
        
        query_term = f"{finding.get('vulnerability')} {finding.get('cve', '')} {finding.get('service', '')}"
        rag_context = self.rag.get_context_str(query_term)
        
        prompt = f"""
VULNERABILITY FINDING EVIDENCE:
- Vulnerability: {finding.get('vulnerability')}
- Severity: {finding.get('severity')}
- Target: {finding.get('target')}
- Port/Service: {finding.get('port')}/{finding.get('service')}
- Evidence: {finding.get('evidence')}
- Source Tool: {finding.get('source_tool')}

LOCAL KNOWLEDGE RETRIEVAL:
{rag_context}

TASK:
Analyze this finding. Confirm whether the evidence warrants the severity, assess potential exploit impact, and outline explicit remediation and verification steps.
"""
        success, response = self.client.generate(prompt, system_prompt=system_prompt)
        if success:
            save_ai_analysis(specialist_role=role, model_name=self.client.get_active_model() or "Ollama",
                             analysis_text=response, finding_id=finding.get('id'), scan_id=scan_id)
        return response

    def analyze_sql_injection(self, target_url: str, param: str, evidence: str) -> str:
        """Analyze detected SQL injection vulnerability."""
        role = "SQL Security Analyst"
        system_prompt = get_system_prompt(role)
        rag_context = self.rag.get_context_str("SQL Injection CWE-89 parameterized query")

        prompt = f"""
TARGET URL: {target_url}
PARAMETER: {param}
HEURISTIC DETECTION EVIDENCE:
{evidence}

LOCAL KNOWLEDGE CONTEXT:
{rag_context}

TASK:
Evaluate the SQL injection vulnerability based on the evidence. Explain the technical vulnerability mechanism, potential database risk, and provide code remediation using parameterized queries.
"""
        success, response = self.client.generate(prompt, system_prompt=system_prompt)
        return response

    def analyze_traffic_anomaly(self, metrics: Dict[str, Any]) -> str:
        """Analyze network traffic spike or suspected DoS/DDoS pattern."""
        role = "SOC Analyst"
        system_prompt = get_system_prompt(role)
        
        prompt = f"""
NETWORK TRAFFIC TELEMETRY:
- Requests/sec (RPS): {metrics.get('rps')}
- Packets/sec (PPS): {metrics.get('pps')}
- Active Connections: {metrics.get('active_connections')}
- Anomaly Score: {metrics.get('anomaly_score')}/100
- Protocol Distribution: {metrics.get('protocols')}
- Top Source IPs: {metrics.get('top_sources')}

TASK:
Analyze this traffic pattern. Determine if this represents scanning, a traffic surge, or a potential DoS/DDoS condition. Recommend defensive containment actions.
"""
        success, response = self.client.generate(prompt, system_prompt=system_prompt)
        return response

    def query_assistant(self, user_question: str) -> str:
        """General security advisor interactive prompt."""
        role = "Remediation Advisor"
        system_prompt = get_system_prompt(role)
        rag_context = self.rag.get_context_str(user_question)

        prompt = f"""
SECURITY QUESTION:
{user_question}

LOCAL SECURITY KNOWLEDGE:
{rag_context}

Provide a precise, technical, and actionable security answer.
"""
        success, response = self.client.generate(prompt, system_prompt=system_prompt)
        return response

_ORCHESTRATOR: Optional[AIOrchestrator] = None

def get_ai_orchestrator() -> AIOrchestrator:
    global _ORCHESTRATOR
    if _ORCHESTRATOR is None:
        _ORCHESTRATOR = AIOrchestrator()
    return _ORCHESTRATOR
