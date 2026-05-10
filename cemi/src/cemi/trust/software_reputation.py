"""Deterministic software reputation analysis for local CEMÍ findings."""
from __future__ import annotations
from typing import Optional

KNOWN_VENDORS: dict[str, list[str]] = {
    "Microsoft": ["microsoft", "onenote", "onedrive", "office", "windows"],
    "Google": ["google", "chrome", "gmail", "google drive"],
    "Mozilla": ["mozilla", "firefox"],
    "Bitwarden": ["bitwarden"],
    "GitHub": ["github"],
    "Visual Studio Code": ["visual studio code", "vscode", "code.exe"],
    "Discord": ["discord"],
    "Steam": ["steam"],
    "NVIDIA": ["nvidia"],
    "Intel": ["intel"],
    "AMD": ["amd"],
    "Docker": ["docker"],
}


def _normalize_text(value: Optional[str]) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def assess_software_reputation(
    name: Optional[str] = None,
    publisher: Optional[str] = None,
    path: Optional[str] = None,
) -> dict[str, Optional[object]]:
    """Assess reputation from local name, publisher, and path metadata."""
    candidates = []
    if publisher:
        candidates.append((publisher, "publisher"))
    if name:
        candidates.append((name, "name"))
    if path:
        candidates.append((path, "path"))

    matched_vendor: Optional[str] = None
    matched_field: Optional[str] = None

    for text, field in candidates:
        lower_text = _normalize_text(text)
        for vendor, tokens in KNOWN_VENDORS.items():
            for token in tokens:
                if token in lower_text:
                    matched_vendor = vendor
                    matched_field = field
                    break
            if matched_vendor:
                break
        if matched_vendor:
            break

    if matched_vendor:
        reasoning = [
            f"Matched local metadata in {matched_field} to known vendor {matched_vendor}."
        ]
        return {
            "known_vendor": True,
            "trust_level": "known",
            "publisher": publisher if publisher else matched_vendor,
            "reasoning": reasoning,
        }

    return {
        "known_vendor": False,
        "trust_level": "unknown",
        "publisher": publisher,
        "reasoning": [
            "No known software vendor metadata was detected from the local artifact.",
        ],
    }


__all__ = ["assess_software_reputation", "KNOWN_VENDORS"]
