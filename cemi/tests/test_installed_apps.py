"""Tests for cemi.collectors.installed_apps.

Non-Windows path is exercised directly (winreg unavailable on Linux CI).
Windows registry behaviour is exercised via a fully mocked winreg module.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cemi.collectors.installed_apps import InstalledAppsCollector
from cemi.models import CollectorHealth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_winreg(
    subkey_names: list[str],
    fields: dict[str, str],
) -> MagicMock:
    """Build a mock winreg module.

    All three hive roots will each enumerate ``subkey_names`` and return
    ``fields`` values for every app subkey.
    """
    mock_wr = MagicMock()
    mock_wr.HKEY_LOCAL_MACHINE = 0x80000002
    mock_wr.HKEY_CURRENT_USER = 0x80000001

    def _enum_key(handle: object, idx: int) -> str:
        if idx < len(subkey_names):
            return subkey_names[idx]
        raise OSError("no more subkeys")

    mock_wr.EnumKey.side_effect = _enum_key

    def _query_value_ex(handle: object, name: str) -> tuple[str, int]:
        if name in fields:
            return (fields[name], 1)
        raise OSError(f"value not found: {name}")

    mock_wr.QueryValueEx.side_effect = _query_value_ex

    # OpenKey returns a context-manager-compatible handle
    mock_handle = MagicMock()
    mock_handle.__enter__ = MagicMock(return_value=mock_handle)
    mock_handle.__exit__ = MagicMock(return_value=False)
    mock_wr.OpenKey.return_value = mock_handle

    return mock_wr


# ---------------------------------------------------------------------------
# Non-Windows (no winreg) — runs on every platform including Linux CI
# ---------------------------------------------------------------------------


class TestInstalledAppsCollectorNonWindows:
    """Verify graceful behaviour when winreg is absent."""

    def test_returns_list_and_health(self) -> None:
        collector = InstalledAppsCollector()
        items, health = collector.run()
        assert isinstance(items, list)
        assert isinstance(health, CollectorHealth)

    def test_does_not_crash(self) -> None:
        collector = InstalledAppsCollector()
        collector.run()  # must not raise

    def test_items_collected_non_negative(self) -> None:
        collector = InstalledAppsCollector()
        _, health = collector.run()
        assert health.items_collected >= 0

    def test_skips_gracefully_without_winreg(self) -> None:
        import cemi.collectors.installed_apps as mod

        if mod._WINREG_AVAILABLE:
            pytest.skip("winreg is available on this platform")

        collector = InstalledAppsCollector()
        items, health = collector.run()
        assert items == []
        assert health.ran_successfully is True
        assert health.skipped_reason is not None
        assert health.errors == []


# ---------------------------------------------------------------------------
# Mocked winreg — validates Windows registry logic on any platform
# ---------------------------------------------------------------------------


class TestInstalledAppsCollectorMocked:
    """Registry collection logic exercised through a mocked winreg."""

    _BASE_FIELDS: dict[str, str] = {
        "DisplayName": "Test Application",
        "Publisher": "ACME Corp",
        "DisplayVersion": "2.0.1",
        "InstallLocation": r"C:\Program Files\TestApp",
        "InstallDate": "20240101",
        "UninstallString": r"C:\Program Files\TestApp\uninstall.exe",
    }

    def _patch_winreg(self, mock_wr: MagicMock):
        return (
            patch("cemi.collectors.installed_apps._winreg", mock_wr),
            patch("cemi.collectors.installed_apps._WINREG_AVAILABLE", True),
        )

    def test_collects_apps(self) -> None:
        mock_wr = _make_winreg(["subkey_0"], self._BASE_FIELDS)
        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            items, health = InstalledAppsCollector().collect()

        assert len(items) > 0
        assert health.ran_successfully is True
        assert health.items_collected == len(items)

    def test_app_has_expected_fields(self) -> None:
        mock_wr = _make_winreg(["subkey_0"], self._BASE_FIELDS)
        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            items, _ = InstalledAppsCollector().collect()

        app = items[0]
        assert app["name"] == "Test Application"
        assert app["publisher"] == "ACME Corp"
        assert app["version"] == "2.0.1"
        assert app["install_date"] == "20240101"
        assert "install_location" in app
        assert "uninstall_string" in app

    def test_skips_entries_without_display_name(self) -> None:
        fields = {k: v for k, v in self._BASE_FIELDS.items() if k != "DisplayName"}
        mock_wr = _make_winreg(["subkey_0"], fields)
        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            items, health = InstalledAppsCollector().collect()

        assert items == []
        assert health.items_collected == 0

    def test_user_paths_in_install_location_are_redacted(self) -> None:
        fields = {**self._BASE_FIELDS, "InstallLocation": r"C:\Users\alice\AppData\TestApp"}
        mock_wr = _make_winreg(["subkey_0"], fields)
        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            items, _ = InstalledAppsCollector().collect()

        loc = items[0]["install_location"]
        assert loc is not None
        assert "alice" not in loc
        assert "[REDACTED]" in loc

    def test_user_paths_in_uninstall_string_are_redacted(self) -> None:
        fields = {
            **self._BASE_FIELDS,
            "UninstallString": r"C:\Users\bob\AppData\Temp\uninstall.exe",
        }
        mock_wr = _make_winreg(["subkey_0"], fields)
        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            items, _ = InstalledAppsCollector().collect()

        uninst = items[0]["uninstall_string"]
        assert uninst is not None
        assert "bob" not in uninst
        assert "[REDACTED]" in uninst

    def test_permission_error_on_root_key_does_not_crash(self) -> None:
        mock_wr = MagicMock()
        mock_wr.HKEY_LOCAL_MACHINE = 0x80000002
        mock_wr.HKEY_CURRENT_USER = 0x80000001
        mock_wr.OpenKey.side_effect = PermissionError("Access denied")

        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            items, health = InstalledAppsCollector().collect()

        assert isinstance(items, list)
        assert isinstance(health, CollectorHealth)
        assert health.ran_successfully is True  # collector survived

    def test_errors_from_root_key_are_redacted(self) -> None:
        """OSError messages that contain user paths must be redacted."""
        mock_wr = MagicMock()
        mock_wr.HKEY_LOCAL_MACHINE = 0x80000002
        mock_wr.HKEY_CURRENT_USER = 0x80000001
        mock_wr.OpenKey.side_effect = OSError(
            r"Cannot access C:\Users\carol\NTUSER.DAT"
        )

        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            _, health = InstalledAppsCollector().collect()

        assert health.errors
        for msg in health.errors:
            assert "carol" not in msg

    def test_missing_optional_fields_returned_as_none(self) -> None:
        """Only DisplayName is required; other fields may be absent."""
        mock_wr = _make_winreg(["subkey_0"], {"DisplayName": "MinimalApp"})
        p1, p2 = self._patch_winreg(mock_wr)
        with p1, p2:
            items, health = InstalledAppsCollector().collect()

        assert len(items) > 0
        app = items[0]
        assert app["name"] == "MinimalApp"
        assert app["publisher"] is None
        assert app["version"] is None
        assert app["install_location"] is None
        assert app["install_date"] is None
        assert app["uninstall_string"] is None
