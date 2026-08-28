#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Dynamic Wordlist Management
Manages static wordlists and AI-generated dynamic wordlists.
"""
import os
import json
import random
from pathlib import Path
from typing import List, Optional, Dict
from core.config import Config
from core.logger import Logger


class WordlistManager:
    """
    Manages wordlists for fuzzing, subdomain enumeration, and directory brute-forcing.
    Supports both static wordlists and AI-generated dynamic ones.
    """

    BUILTIN_WORDLISTS: Dict[str, List[str]] = {
        "common_dirs": [
            "admin", "login", "dashboard", "api", "v1", "v2", "test",
            "dev", "staging", "backup", "config", "setup", "install",
            "wp-admin", "administrator", "manage", "console", "portal",
            "upload", "uploads", "files", "data", "db", "database",
            "logs", "log", "tmp", "temp", "cache", "static", "assets",
            "images", "img", "css", "js", "scripts", "includes",
            "phpinfo.php", ".env", ".git", "robots.txt", "sitemap.xml",
            "swagger.json", "openapi.json", "api-docs", ".well-known",
        ],
        "common_files": [
            ".env", ".env.local", ".env.production", ".env.backup",
            "config.json", "config.yaml", "config.yml", "secrets.json",
            "database.yml", "settings.py", "application.properties",
            "web.config", "appsettings.json", ".htaccess", ".htpasswd",
            "id_rsa", "id_rsa.pub", "authorized_keys", "known_hosts",
            "credentials", "passwords.txt", "backup.sql", "dump.sql",
        ],
        "api_endpoints": [
            "users", "user", "accounts", "account", "profile", "profiles",
            "admin", "settings", "config", "health", "status", "ping",
            "auth", "login", "logout", "register", "signup", "token",
            "tokens", "keys", "secrets", "webhooks", "webhook",
            "orders", "order", "products", "product", "payments", "payment",
            "documents", "document", "files", "uploads", "reports",
            "metrics", "analytics", "logs", "events", "notifications",
        ],
    }

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("WordlistManager")
        self.wordlist_dir = Path("wordlists")
        self.wordlist_dir.mkdir(exist_ok=True)

    def get(self, name: str, shuffle: bool = False) -> List[str]:
        """Get a wordlist by name."""
        # Check builtin
        if name in self.BUILTIN_WORDLISTS:
            words = self.BUILTIN_WORDLISTS[name].copy()
            if shuffle:
                random.shuffle(words)
            return words

        # Check file
        wl_path = self.wordlist_dir / f"{name}.txt"
        if wl_path.exists():
            with open(wl_path) as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if shuffle:
                random.shuffle(words)
            return words

        self.logger.warning(f"Wordlist not found: {name}")
        return []

    def save(self, name: str, words: List[str]):
        """Save a wordlist to disk."""
        path = self.wordlist_dir / f"{name}.txt"
        with open(path, "w") as f:
            f.write("\n".join(sorted(set(words))))
        self.logger.info(f"Saved {len(words)} words to {path}")

    def merge(self, *names: str) -> List[str]:
        """Merge multiple wordlists, deduplicated."""
        merged = set()
        for name in names:
            merged.update(self.get(name))
        return sorted(merged)

    def list_available(self) -> List[str]:
        """List all available wordlists."""
        builtin = list(self.BUILTIN_WORDLISTS.keys())
        file_based = [p.stem for p in self.wordlist_dir.glob("*.txt")]
        return sorted(set(builtin + file_based))
