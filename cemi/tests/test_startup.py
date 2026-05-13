"""Tests for startup collector."""
from __future__ import annotations

import platform

import pytest

from cemi.collectors.startup import StartupCollector


class TestStartupCollector:
    def test_name(self) -> None:
        collector = StartupCollector()
        assert collector.name == "startup"

    def test_privilege_level(self) -> None:
        collector = StartupCollector()
        assert collector.privilege_level == "partial"

    def test_collect_non_windows(self) -> None:
        if platform.system() == "Windows":
            pytest.skip("Test for non-Windows only")

        collector = StartupCollector()
        items, health = collector.collect()

        assert items == []
        assert health.collector_name == "startup"
        assert health.ran_successfully is True
        assert health.items_collected == 0
        assert "winreg not available" in health.skipped_reason

    def test_collect_runonce_and_startupapproved_keys(self, monkeypatch) -> None:
        import cemi.collectors.startup as startup_module

        class FakeKey:
            def __init__(self, values):
                self._values = values

            def __enter__(self) -> "FakeKey":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def EnumValue(self, idx: int):
                if idx >= len(self._values):
                    raise OSError
                return self._values[idx]

        class FakeWinreg:
            HKEY_CURRENT_USER = 1
            HKEY_LOCAL_MACHINE = 2

            def __init__(self, values_by_key):
                self._values_by_key = values_by_key

            def OpenKey(self, hive: int, subkey: str) -> FakeKey:
                return FakeKey(self._values_by_key.get((hive, subkey), []))

            def EnumValue(self, key: FakeKey, idx: int):
                return key.EnumValue(idx)

        runonce_value = (
            "OneShot",
            '"C:\\Users\\Alice\\temp\\runonce.exe" /install',
            1,
        )
        approved_value = ("OneShot", bytes([2, 0, 0, 0]), 3)
        fake_winreg = FakeWinreg({
            (FakeWinreg.HKEY_CURRENT_USER, startup_module._RUNONCE_KEY): [runonce_value],
            (FakeWinreg.HKEY_LOCAL_MACHINE, startup_module._RUNONCE_KEY): [],
            (FakeWinreg.HKEY_CURRENT_USER, startup_module._STARTUP_APPROVED_RUN_KEY): [approved_value],
            (FakeWinreg.HKEY_LOCAL_MACHINE, startup_module._STARTUP_APPROVED_RUN_KEY): [],
        })

        monkeypatch.setattr(startup_module, "_WINREG_AVAILABLE", True)
        monkeypatch.setattr(startup_module, "_winreg", fake_winreg)
        monkeypatch.setattr(StartupCollector, "_collect_from_folders", lambda self, entries, errors: None)

        collector = StartupCollector()
        items, health = collector.collect()

        assert health.ran_successfully is True
        assert any(item["source"] == "registry_runonce" for item in items)
        assert any(item["source"] == "startup_approved_run" for item in items)
        runonce_item = next(item for item in items if item["source"] == "registry_runonce")
        assert runonce_item["name"] == "OneShot"
        assert "command" in runonce_item
        assert runonce_item["path_redacted"] == "C:\\Users\\[REDACTED]\\temp\\runonce.exe"

    def test_missing_registry_keys_does_not_crash(self, monkeypatch) -> None:
        import cemi.collectors.startup as startup_module

        class FakeWinreg:
            HKEY_CURRENT_USER = 1
            HKEY_LOCAL_MACHINE = 2

            def OpenKey(self, hive: int, subkey: str) -> None:
                raise OSError("Access denied")

        monkeypatch.setattr(startup_module, "_WINREG_AVAILABLE", True)
        monkeypatch.setattr(startup_module, "_winreg", FakeWinreg())
        monkeypatch.setattr(StartupCollector, "_collect_from_folders", lambda self, entries, errors: None)

        collector = StartupCollector()
        items, health = collector.collect()

        assert items == []
        assert health.ran_successfully is True
        assert len(health.errors) > 0
        assert all("Access denied" in error for error in health.errors)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows only")
    def test_collect_windows(self) -> None:
        collector = StartupCollector()
        items, health = collector.collect()

        assert isinstance(items, list)
        assert health.collector_name == "startup"
        assert health.ran_successfully is True
        # Check that items have expected fields; some entries may be status-only.
        for item in items:
            assert "name" in item
            assert "source" in item
            assert "scope" in item
            assert any(key in item for key in ("command", "command_redacted", "status"))
            if item.get("command"):
                assert "C:\\Users\\" not in item["command"]
            if item.get("command_redacted"):
                assert "C:\\Users\\" not in item["command_redacted"]
