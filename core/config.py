#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Configuration Module
Manages all configuration including AI providers, targets, and tool paths.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Central configuration for the AI Bug Bounty Hunter."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config.json"
        self.data: Dict[str, Any] = self._load_defaults()
        if Path(self.config_path).exists():
            self._load_file()

    def _load_defaults(self) -> Dict[str, Any]:
        return {
            "ai": {
                "provider": "openai",  # openai, anthropic, groq, ollama
                "model": "gpt-4o",
                "api_key": os.getenv("AI_API_KEY", ""),
                "api_base": os.getenv("AI_API_BASE", ""),
                "temperature": 0.1,
                "max_tokens": 4096,
                "ollama_model": "llama3",
                "ollama_url": "http://localhost:11434",
            },
            "target": {
                "domain": "",
                "scope": [],
                "exclude": [],
                "rate_limit": 10,  # requests per second
                "timeout": 10,
                "max_depth": 3,
                "max_pages": 500,
                "concurrent_requests": 20,
            },
            "recon": {
                "subdomains": True,
                "port_scan": True,
                "tech_detect": True,
                "url_crawl": True,
                "osint": True,
                "use_passive_only": False,
                "subfinder_path": "subfinder",
                "httpx_path": "httpx",
                "nuclei_path": "nuclei",
                "katana_path": "katana",
                "ffuf_path": "ffuf",
            },
            "scanners": {
                "xss": {"enabled": True, "blind_xss_enabled": True, "dom_xss_enabled": True},
                "sqli": {"enabled": True, "time_based": True, "error_based": True, "boolean_based": True},
                "ssti": {"enabled": True},
                "ssrf": {"enabled": True, "oob_enabled": True},
                "lfi": {"enabled": True},
                "open_redirect": {"enabled": True},
                "idor": {"enabled": True, "auto_detect_params": True},
                "api": {"enabled": True, "graphql_enabled": True},
                "web3": {"enabled": False, "chain": "ethereum"},
            },
            "ai_engine": {
                "validation_gate_enabled": True,
                "validation_questions": 7,
                "auto_prioritize": True,
                "auto_remediate": False,
                "min_confidence": 0.6,
                "enable_payload_generation": True,
            },
            "reports": {
                "format": "markdown",  # markdown, html, json, pdf
                "platform": "hackerone",  # hackerone, bugcrowd, intigriti, immunefi
                "include_evidence": True,
                "include_remediation": True,
                "include_poc": True,
                "auto_submit": False,
            },
            "stealth": {
                "enabled": False,
                "rotate_user_agents": True,
                "random_delays": True,
                "proxy_rotation": False,
                "proxy_file": "proxies.txt",
                "respect_robots": True,
            },
        }

    def _load_file(self):
        with open(self.config_path, "r") as f:
            loaded = json.load(f)
            self._deep_update(self.data, loaded)

    def _deep_update(self, base: dict, update: dict):
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_update(base[key], value)
            else:
                base[key] = value

    def get(self, *keys: str, default=None):
        """Traverse nested keys safely."""
        current = self.data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
                if current is None:
                    return default
            else:
                return default
        return current

    def set_target(self, domain: str, scope: Optional[list] = None):
        """Set the target domain and optional scope."""
        self.data["target"]["domain"] = domain
        if scope:
            self.data["target"]["scope"] = scope
        self.save()

    def save(self):
        with open(self.config_path, "w") as f:
            json.dump(self.data, f, indent=4)

    @property
    def ai_provider(self) -> str:
        return self.data["ai"]["provider"]

    @property
    def target_domain(self) -> str:
        return self.data["target"]["domain"]
