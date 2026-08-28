#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Logging System
Rich terminal output with color-coded severity levels and timestamps.
"""
import sys
import logging
from datetime import datetime
from typing import Optional

import io
import os

try:
    from rich.console import Console
    from rich.text import Text
    from rich.theme import Theme

    _theme = Theme({
        "info": "cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "debug": "dim white",
        "critical": "bold white on red",
    })
    # Force UTF-8 safe output on Windows
    _console = Console(
        theme=_theme,
        highlight=False,
        force_terminal=True,
        force_jupyter=False,
        safe_box=True,
    )
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class Logger:
    """
    Unified logger for the AI-BugBounty-Hunter.
    Supports rich terminal output with fallback to standard logging.
    """

    LEVELS = {
        "DEBUG": 0,
        "INFO": 1,
        "SUCCESS": 2,
        "WARNING": 3,
        "ERROR": 4,
        "CRITICAL": 5,
    }

    ICONS = {
        "DEBUG": "[D]",
        "INFO": "[*]",
        "SUCCESS": "[+]",
        "WARNING": "[!]",
        "ERROR": "[x]",
        "CRITICAL": "[!!]",
    }

    COLORS = {
        "DEBUG": "\033[90m",      # dark gray
        "INFO": "\033[96m",       # cyan
        "SUCCESS": "\033[92m",    # green
        "WARNING": "\033[93m",    # yellow
        "ERROR": "\033[91m",      # red
        "CRITICAL": "\033[97;41m",  # white on red
    }
    RESET = "\033[0m"

    def __init__(self, name: str = "BugHunter", verbose: int = 0,
                 log_file: Optional[str] = None):
        self.name = name
        self.verbose = verbose
        self.log_file: Optional[logging.Logger] = None

        if log_file:
            self._setup_file_logger(log_file)

    def _setup_file_logger(self, log_file: str):
        """Set up file-based logging."""
        file_logger = logging.getLogger(self.name)
        file_logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        file_logger.addHandler(handler)
        self.log_file = file_logger

    def _log(self, level: str, message: str):
        """Internal log method."""
        # Skip debug in non-verbose mode
        if level == "DEBUG" and self.verbose < 2:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")

        if RICH_AVAILABLE:
            icon = self.ICONS.get(level, "●")
            style_map = {
                "DEBUG": "debug",
                "INFO": "info",
                "SUCCESS": "success",
                "WARNING": "warning",
                "ERROR": "error",
                "CRITICAL": "critical",
            }
            style = style_map.get(level, "info")
            _console.print(
                f"[dim]{timestamp}[/dim] [{style}]{icon} [{self.name}][/{style}] {message}"
            )
        else:
            color = self.COLORS.get(level, "")
            icon = self.ICONS.get(level, "●")
            print(
                f"{color}{timestamp} {icon} [{self.name}] {message}{self.RESET}",
                file=sys.stderr if level in ("ERROR", "CRITICAL") else sys.stdout,
            )

        if self.log_file:
            log_fn = getattr(self.log_file, level.lower(), self.log_file.info)
            log_fn(f"[{self.name}] {message}")

    def debug(self, message: str):
        self._log("DEBUG", message)

    def info(self, message: str):
        self._log("INFO", message)

    def success(self, message: str):
        self._log("SUCCESS", message)

    def warning(self, message: str):
        self._log("WARNING", message)

    def error(self, message: str):
        self._log("ERROR", message)

    def critical(self, message: str):
        self._log("CRITICAL", message)

    def banner(self, text: str):
        """Print a section banner."""
        separator = "─" * 60
        if RICH_AVAILABLE:
            _console.print(f"\n[bold cyan]{separator}[/bold cyan]")
            _console.print(f"[bold cyan]  {text}[/bold cyan]")
            _console.print(f"[bold cyan]{separator}[/bold cyan]\n")
        else:
            print(f"\n{separator}\n  {text}\n{separator}\n")
