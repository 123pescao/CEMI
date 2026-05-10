"""Tests for persistence rules."""
from __future__ import annotations

from cemi.models import Severity
from cemi.rules.persistence_rules import (
    PersistExtensionSpywareRule,
    PersistStartupUserWritableRule,
    PersistUnsignedUserWritableRule,
)


class TestPersistUnsignedUserWritableRule:
    def test_no_findings_when_no_signatures(self) -> None:
        rule = PersistUnsignedUserWritableRule()
        findings = rule.evaluate({}, "test-scan")
        assert findings == []

    def test_no_findings_when_signed(self) -> None:
        items_by_collector = {
            "signatures": [
                {
                    "path": "C:\\Windows\\System32\\notepad.exe",
                    "exists": True,
                    "is_executable": True,
                    "signature_status": "valid",
                    "path_redacted": "C:\\Windows\\System32\\notepad.exe",
                }
            ]
        }
        rule = PersistUnsignedUserWritableRule()
        findings = rule.evaluate(items_by_collector, "test-scan")
        assert findings == []

    def test_finding_when_unsigned_in_user_location(self) -> None:
        items_by_collector = {
            "signatures": [
                {
                    "path": "C:\\Users\\test\\AppData\\evil.exe",
                    "exists": True,
                    "is_executable": True,
                    "signature_status": "unknown",
                    "path_redacted": "C:\\Users\\[REDACTED]\\AppData\\evil.exe",
                }
            ]
        }
        rule = PersistUnsignedUserWritableRule()
        findings = rule.evaluate(items_by_collector, "test-scan")
        assert len(findings) == 1
        assert findings[0].id == "PERSIST-001"
        assert findings[0].severity == Severity.HIGH


class TestPersistStartupUserWritableRule:
    def test_no_findings_when_no_startup(self) -> None:
        rule = PersistStartupUserWritableRule()
        findings = rule.evaluate({}, "test-scan")
        assert findings == []

    def test_finding_when_startup_from_user_location(self) -> None:
        items_by_collector = {
            "startup": [
                {
                    "name": "EvilApp",
                    "source": "registry",
                    "command": "C:\\Users\\test\\evil.exe",
                    "path_redacted": "C:\\Users\\[REDACTED]\\evil.exe",
                    "scope": "user",
                }
            ]
        }
        rule = PersistStartupUserWritableRule()
        findings = rule.evaluate(items_by_collector, "test-scan")
        assert len(findings) == 1
        assert findings[0].id == "PERSIST-002"
        assert findings[0].severity == Severity.HIGH


class TestPersistExtensionSpywareRule:
    def test_no_findings_when_no_extensions(self) -> None:
        rule = PersistExtensionSpywareRule()
        findings = rule.evaluate({}, "test-scan")
        assert findings == []

    def test_finding_when_extension_has_spyware_permissions(self) -> None:
        items_by_collector = {
            "browser_extensions": [
                {
                    "name": "Spyware Extension",
                    "permissions": ["cookies", "scripting"],
                    "host_permissions": ["<all_urls>"],
                }
            ]
        }
        rule = PersistExtensionSpywareRule()
        findings = rule.evaluate(items_by_collector, "test-scan")
        assert len(findings) == 1
        assert findings[0].id == "PERSIST-003"
        assert findings[0].severity == Severity.HIGH

    def test_critical_when_native_messaging(self) -> None:
        items_by_collector = {
            "browser_extensions": [
                {
                    "name": "Critical Spyware",
                    "permissions": ["nativeMessaging", "cookies"],
                    "host_permissions": ["<all_urls>"],
                }
            ]
        }
        rule = PersistExtensionSpywareRule()
        findings = rule.evaluate(items_by_collector, "test-scan")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL