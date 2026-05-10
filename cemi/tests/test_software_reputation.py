"""Tests for software reputation heuristics used by CEMÍ."""
from __future__ import annotations

from cemi.trust.software_reputation import assess_software_reputation


def test_known_vendor_from_publisher() -> None:
    result = assess_software_reputation(publisher="Microsoft Corporation")
    assert result["known_vendor"] is True
    assert result["trust_level"] == "known"
    assert "Microsoft" in result["publisher"]
    assert any("known vendor" in note.lower() for note in result["reasoning"])


def test_known_vendor_from_name() -> None:
    result = assess_software_reputation(name="Bitwarden Password Manager")
    assert result["known_vendor"] is True
    assert result["trust_level"] == "known"
    assert any("known vendor" in note.lower() for note in result["reasoning"])


def test_onedrive_detected_as_known_vendor() -> None:
    result = assess_software_reputation(name="OneDrive", path="C:\\Users\\user\\AppData\\Roaming\\Microsoft\\OneDrive\\OneDrive.exe")
    assert result["known_vendor"] is True
    assert result["trust_level"] == "known"
    assert any("known vendor" in note.lower() for note in result["reasoning"])


def test_unknown_vendor_returns_unknown_trust_level() -> None:
    result = assess_software_reputation(name="SuspiciousApp", publisher="Unknown Pub")
    assert result["known_vendor"] is False
    assert result["trust_level"] == "unknown"
    assert result["publisher"] == "Unknown Pub"
    assert any("no known software vendor" in note.lower() for note in result["reasoning"])
