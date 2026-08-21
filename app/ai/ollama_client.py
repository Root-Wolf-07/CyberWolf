"""CYBERWOLF Local AI Engine (Ollama / Gemma Integration)."""

import json
import requests
from typing import Dict, List, Any, Optional, Tuple
from app.core.config import get_config
from app.core.logger import get_logger, audit_log
from app.core.exceptions import AIError

logger = get_logger()

class OllamaClient:
    """Communicates directly with the local Ollama LLM instance."""
    
    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.config = get_config()
        ai_cfg = self.config.get_ai_config()
        self.base_url = (base_url or ai_cfg.get("base_url", "http://localhost:11434")).rstrip("/")
        self.preferred_model = model or ai_cfg.get("model", "gemma4:26b")
        self.fallback_models = ai_cfg.get("fallback_models", ["gemma", "llama3.2:1b", "qwen2.5:0.5b"])
        self.timeout = ai_cfg.get("timeout", 45)
        self.temperature = ai_cfg.get("temperature", 0.2)

    def is_online(self) -> bool:
        """Check if local Ollama daemon is reachable."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    def list_installed_models(self) -> List[str]:
        """Fetch all installed models in the local Ollama registry."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                return models
        except Exception as e:
            logger.warning(f"Failed to query Ollama models: {e}")
        return []

    def get_active_model(self) -> Optional[str]:
        """Select the best available model (preferred first, then fallbacks)."""
        installed = self.list_installed_models()
        if not installed:
            return None

        # Check preferred model exact or prefix match
        for m in installed:
            if m == self.preferred_model or m.startswith(self.preferred_model.split(":")[0]):
                return m

        # Check fallbacks
        for fb in self.fallback_models:
            for m in installed:
                if m == fb or m.startswith(fb.split(":")[0]):
                    return m

        # Return first installed model
        return installed[0]

    def generate(self, prompt: str, system_prompt: Optional[str] = None, model: Optional[str] = None) -> Tuple[bool, str]:
        """Send prompt to local model and return generated text."""
        if not self.is_online():
            return False, "[!] Ollama is not running or unreachable at " + self.base_url + ". Please run 'ollama serve'."

        active_model = model or self.get_active_model()
        if not active_model:
            return False, "[!] No suitable local AI model found in Ollama. Please run 'ollama pull gemma' or 'ollama pull llama3.2'."

        payload = {
            "model": active_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature
            }
        }
        if system_prompt:
            payload["system"] = system_prompt

        logger.info(f"Submitting AI request to Ollama model '{active_model}'")
        audit_log("AI_INFERENCE", "GENERATE", tool=f"ollama/{active_model}", decision="PROCEEDED")

        try:
            resp = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                result_json = resp.json()
                response_text = result_json.get("response", "").strip()
                return True, response_text
            else:
                return False, f"[!] Ollama API returned status {resp.status_code}: {resp.text}"
        except requests.Timeout:
            return False, f"[!] AI generation timed out after {self.timeout} seconds."
        except Exception as e:
            return False, f"[!] AI inference error: {e}"

_OLLAMA_CLIENT: Optional[OllamaClient] = None

def get_ollama_client() -> OllamaClient:
    global _OLLAMA_CLIENT
    if _OLLAMA_CLIENT is None:
        _OLLAMA_CLIENT = OllamaClient()
    return _OLLAMA_CLIENT
