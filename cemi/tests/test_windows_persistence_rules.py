"""Tests for Windows persistence detection rules."""
from __future__ import annotations

from cemi.rules.windows_persistence_rules import (
    LolbinStartupTaskRule,
    RunOncePersistenceRule,
    SuspiciousPowerShellStartupRule,
)
from cemi.scan_engine import _build_rule_engine


def test_winpersist_001_fires_for_runonce() -> None:
    rule = RunOncePersistenceRule()
    item = {
        "name": "OneShot",
        "source": "registry_runonce",
        "command": "C:\\Users\\[REDACTED]\\temp\\runonce.exe /install",
        "path_redacted": "C:\\Users\\[REDACTED]\\temp\\runonce.exe",
        "scope": "user",
    }
    findings = rule.evaluate({"startup": [item]}, "scan-123")

    assert len(findings) == 1
    assert findings[0].id == "WINPERSIST-001"
    assert findings[0].severity.name == "MEDIUM"
    assert findings[0].category == "Persistence"


def test_winpersist_002_fires_for_encoded_powershell_startup() -> None:
    rule = SuspiciousPowerShellStartupRule()
    item = {
        "name": "PowerShellBoot",
        "source": "registry_run",
        "command": "powershell -EncodedCommand ABCDEFGHIJKLMNOP",
        "path_redacted": "powershell",
        "scope": "user",
    }
    findings = rule.evaluate({"startup": [item]}, "scan-123")

    assert len(findings) == 1
    assert findings[0].id == "WINPERSIST-002"
    assert findings[0].severity.name == "HIGH"


def test_winpersist_002_fires_for_hidden_powershell_scheduled_task() -> None:
    rule = SuspiciousPowerShellStartupRule()
    item = {
        "task_name": "HiddenPowerShell",
        "task_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "enabled": True,
        "action_command_redacted": "pwsh",
        "action_arguments_redacted": "-windowstyle hidden -nop -command Invoke-Expression",
        "trigger_count": 1,
        "scope": "system",
    }
    findings = rule.evaluate({"scheduled_tasks": [item]}, "scan-123")

    assert len(findings) == 1
    assert findings[0].id == "WINPERSIST-002"
    assert findings[0].severity.name == "HIGH"


def test_winpersist_003_fires_for_rundll32_startup_command() -> None:
    rule = LolbinStartupTaskRule()
    item = {
        "name": "LoLTask",
        "source": "registry_run",
        "command": "rundll32 C:\\Windows\\System32\\some.dll,Entry",
        "path_redacted": "C:\\Windows\\System32\\some.dll",
        "scope": "user",
    }
    findings = rule.evaluate({"startup": [item]}, "scan-123")

    assert len(findings) == 1
    assert findings[0].id == "WINPERSIST-003"
    assert findings[0].severity.name == "MEDIUM"


def test_winpersist_003_upgrades_to_high_for_user_writable_path() -> None:
    rule = LolbinStartupTaskRule()
    item = {
        "name": "MshtaStartup",
        "source": "registry_run",
        "command": "C:\\Users\\[REDACTED]\\AppData\\Local\\Temp\\mshta.exe",
        "path_redacted": "C:\\Users\\[REDACTED]\\AppData\\Local\\Temp\\mshta.exe",
        "scope": "user",
    }
    findings = rule.evaluate({"startup": [item]}, "scan-123")

    assert len(findings) == 1
    assert findings[0].id == "WINPERSIST-003"
    assert findings[0].severity.name == "HIGH"


def test_no_raw_paths_or_secrets_in_evidence() -> None:
    rule = SuspiciousPowerShellStartupRule()
    item = {
        "name": "PowerShellBoot",
        "source": "registry_run",
        "command": "powershell -EncodedCommand [REDACTED_TOKEN]",
        "path_redacted": "powershell",
        "scope": "user",
    }
    findings = rule.evaluate({"startup": [item]}, "scan-123")

    assert findings
    evidence_text = " ".join(e.value for e in findings[0].evidence)
    assert "C:\\Users\\" not in evidence_text
    assert "[REDACTED_TOKEN]" in evidence_text


def test_scan_engine_includes_windows_persistence_rules() -> None:
    rules = _build_rule_engine()._rules
    assert any(rule.__class__.__name__ == "RunOncePersistenceRule" for rule in rules)
    assert any(rule.__class__.__name__ == "SuspiciousPowerShellStartupRule" for rule in rules)
    assert any(rule.__class__.__name__ == "LolbinStartupTaskRule" for rule in rules)
