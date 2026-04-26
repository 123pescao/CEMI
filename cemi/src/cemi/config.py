"""Compile-time configuration constants for CEMÍ.

CEMÍ does NOT load runtime configuration from the filesystem, the network,
or environment variables. Every value in this module is a hard-coded
constant, known at import time, and contains no user data and no secrets.
"""
from __future__ import annotations

from typing import Final

from jinja2 import Environment

# --- Identity -----------------------------------------------------------------

TOOL_NAME: Final[str] = "CEMÍ"
TOOL_TAGLINE: Final[str] = "Computer Evidence Monitoring Inspector"
SCAN_VERSION: Final[str] = "0.1.0"

# --- Redaction markers --------------------------------------------------------

REDACTED_MARKER: Final[str] = "[REDACTED]"
REDACTED_TOKEN_MARKER: Final[str] = "[REDACTED_TOKEN]"

# --- Privacy notice -----------------------------------------------------------

PRIVACY_NOTICE: Final[str] = (
    "This tool will scan system metadata such as installed apps, startup "
    "entries, services, and browser configurations. It will NOT access "
    "personal files, browser history, or send any data externally. Reports "
    "are saved locally."
)


def get_template_env() -> Environment:
    """Return a Jinja2 Environment with HTML autoescaping always enabled."""
    return Environment(autoescape=True)
