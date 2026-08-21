"""Unit tests for AI prompts, local RAG retrieval, and Demo mode."""

import unittest
from app.ai.prompts import get_system_prompt
from app.ai.rag import get_rag
from app.ai.ollama_client import get_ollama_client
from app.demo.demo_runner import DemoRunner

class TestAIAndRAG(unittest.TestCase):
    def test_system_prompts(self):
        prompt = get_system_prompt("Network Security Analyst")
        self.assertIn("NEVER hallucinate", prompt)
        self.assertIn("Network Security Analyst", prompt)

    def test_rag_knowledge_retrieval(self):
        rag = get_rag()
        # Query for Log4Shell / CVE-2021-44228
        results = rag.query("CVE-2021-44228 Log4Shell", top_k=2)
        self.assertTrue(len(results) >= 1)
        self.assertEqual(results[0]["id"], "CVE-2021-44228")

        # Query for SQL Injection
        owasp_results = rag.query("SQL Injection CWE-89", top_k=2)
        self.assertTrue(len(owasp_results) >= 1)

    def test_ollama_client(self):
        client = get_ollama_client()
        # Should be able to query online status and active model without crashing
        is_up = client.is_online()
        model = client.get_active_model()
        self.assertIsInstance(is_up, bool)

    def test_demo_runner(self):
        runner = DemoRunner()
        res = runner.run_demo()
        self.assertEqual(res["status"], "DEMO_COMPLETED")
        self.assertGreater(res["findings_count"], 0)
        self.assertIn("HTML", res["reports"])

if __name__ == "__main__":
    unittest.main()
