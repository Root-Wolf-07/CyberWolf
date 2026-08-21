"""CYBERWOLF Unified Configuration Subsystem."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    "app": {
        "name": "CYBERWOLF",
        "version": "1.0.0",
        "tagline": "Hunt Threats. Find Weaknesses. Defend Everything."
    },
    "ai": {
        "provider": "ollama",
        "model": "gemma4:26b",
        "fallback_models": ["gemma", "gemma:2b", "gemma:7b", "llama3.2:1b", "qwen2.5:0.5b"],
        "base_url": "http://localhost:11434",
        "timeout": 45,
        "temperature": 0.2
    },
    "database": {
        "type": "sqlite",
        "path": "./database/cyberwolf.db",
        "backup_dir": "./database/backups"
    },
    "security": {
        "require_authorization": True,
        "safe_mode": True,
        "default_mode": "SAFE_SCAN",
        "confirmation_required": True,
        "allowed_modes": ["PASSIVE", "SAFE_SCAN", "ACTIVE_SCAN", "AUTHORIZED_PENTEST", "LAB_MODE"]
    },
    "storage": {
        "local_only": True,
        "reports_dir": "./reports",
        "logs_dir": "./logs",
        "knowledge_dir": "./knowledge"
    },
    "logging": {
        "enabled": True,
        "level": "INFO",
        "file": "./logs/cyberwolf.log",
        "audit_file": "./logs/security/audit.log"
    }
}

class ConfigManager:
    """Manages system configuration, targets, authorizations, and policies."""
    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.base_dir = Path(base_dir).resolve()
        else:
            # Locate root directory relative to this file
            self.base_dir = Path(__file__).resolve().parent.parent.parent
            
        self.config_dir = self.base_dir / "config"
        self.config_path = self.config_dir / "config.yaml"
        self.targets_path = self.config_dir / "targets.yaml"
        self.auth_path = self.config_dir / "authorization.yaml"
        self.policies_path = self.config_dir / "policies.yaml"
        
        self.config: Dict[str, Any] = {}
        self.targets_data: Dict[str, Any] = {}
        self.auth_data: Dict[str, Any] = {}
        self.policies_data: Dict[str, Any] = {}
        
        self.load_all()

    def _load_yaml(self, path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
        if not path.exists():
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data if isinstance(data, dict) else default
        except Exception:
            return default

    def load_all(self):
        """Load all YAML configuration files."""
        self.config = self._load_yaml(self.config_path, DEFAULT_CONFIG)
        self.targets_data = self._load_yaml(self.targets_path, {"scopes": [], "excluded_targets": []})
        self.auth_data = self._load_yaml(self.auth_path, {"authorizations": []})
        self.policies_data = self._load_yaml(self.policies_path, {"policies": {"modes": {}}})

    def get(self, section: str, default: Any = None) -> Any:
        return self.config.get(section, default)

    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a relative path against the application base directory."""
        p = Path(relative_path)
        if p.is_absolute():
            return p
        return (self.base_dir / p).resolve()

    def get_db_path(self) -> str:
        db_rel = self.config.get("database", {}).get("path", "./database/cyberwolf.db")
        return str(self.resolve_path(db_rel))

    def get_active_mode(self) -> str:
        return self.config.get("security", {}).get("default_mode", "SAFE_SCAN")

    def set_active_mode(self, mode: str):
        valid_modes = self.config.get("security", {}).get("allowed_modes", ["SAFE_SCAN"])
        if mode in valid_modes:
            if "security" not in self.config:
                self.config["security"] = {}
            self.config["security"]["default_mode"] = mode
            return True
        return False

    def get_ai_config(self) -> Dict[str, Any]:
        return self.config.get("ai", {})

_CONFIG_INSTANCE: Optional[ConfigManager] = None

def get_config(base_dir: Optional[str] = None) -> ConfigManager:
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = ConfigManager(base_dir)
    return _CONFIG_INSTANCE
