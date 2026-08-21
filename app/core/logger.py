"""CYBERWOLF Structured Logging & Security Auditing Subsystem."""

import os
import logging
import re
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional, Dict, Any

SECRET_PATTERNS = [
    re.compile(r'(password|passwd|pwd|secret|token|api[_-]?key|bearer|auth|authorization)[\s:=]+([^\s,;]+)', re.IGNORECASE),
    re.compile(r'(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*', re.IGNORECASE),
    re.compile(r'(--password|--token|--key)[\s=]+([^\s]+)', re.IGNORECASE)
]

def sanitize_message(msg: str) -> str:
    """Mask credentials, passwords, and tokens before logging."""
    if not isinstance(msg, str):
        msg = str(msg)
    sanitized = msg
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub(r'\1 [REDACTED]', sanitized)
    return sanitized

class SensitiveFilter(logging.Filter):
    def filter(self, record):
        record.msg = sanitize_message(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(sanitize_message(a) if isinstance(a, str) else a for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: (sanitize_message(v) if isinstance(v, str) else v) for k, v in record.args.items()}
        return True

_LOGGER: Optional[logging.Logger] = None
_AUDIT_LOGGER: Optional[logging.Logger] = None

def setup_logger(log_file: str = "./logs/cyberwolf.log",
                 audit_file: str = "./logs/security/audit.log",
                 level: str = "INFO") -> logging.Logger:
    global _LOGGER, _AUDIT_LOGGER
    
    # Ensure log directories exist
    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(audit_file)), exist_ok=True)
    
    _LOGGER = logging.getLogger("cyberwolf")
    _LOGGER.setLevel(getattr(logging, level.upper(), logging.INFO))
    _LOGGER.handlers.clear()
    
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s:%(module)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SensitiveFilter())
    _LOGGER.addHandler(file_handler)
    
    # Audit logger
    _AUDIT_LOGGER = logging.getLogger("cyberwolf.audit")
    _AUDIT_LOGGER.setLevel(logging.INFO)
    _AUDIT_LOGGER.handlers.clear()
    
    audit_handler = RotatingFileHandler(
        audit_file, maxBytes=10*1024*1024, backupCount=10, encoding="utf-8"
    )
    audit_formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", %(message)s}',
        datefmt='%Y-%m-%dT%H:%M:%SZ'
    )
    audit_handler.setFormatter(audit_formatter)
    audit_handler.addFilter(SensitiveFilter())
    _AUDIT_LOGGER.addHandler(audit_handler)
    
    return _LOGGER

def get_logger() -> logging.Logger:
    global _LOGGER
    if _LOGGER is None:
        return setup_logger()
    return _LOGGER

def audit_log(event_type: str, action: str, target: Optional[str] = None,
              tool: Optional[str] = None, decision: str = "PROCEEDED",
              details: Optional[str] = None):
    """Record an immutable security audit event."""
    global _AUDIT_LOGGER
    if _AUDIT_LOGGER is None:
        setup_logger()
    
    safe_target = sanitize_message(target or "N/A")
    safe_tool = sanitize_message(tool or "N/A")
    safe_details = sanitize_message(details or "N/A")
    
    payload = f'"event_type": "{event_type}", "action": "{action}", "target": "{safe_target}", "tool": "{safe_tool}", "decision": "{decision}", "details": "{safe_details}"'
    if _AUDIT_LOGGER:
        _AUDIT_LOGGER.info(payload)
