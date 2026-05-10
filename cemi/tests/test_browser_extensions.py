"""Tests for BrowserExtensionsCollector."""
from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, mock_open, patch

from cemi.collectors.browser_extensions import (
    BrowserExtensionsCollector,
    _candidate_dirs,
    _read_extension_manifest,
    _resolve_localized_name,
    _scan_extensions_dir,
)
from cemi.models import CollectorHealth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextmanager
def _windows_env(tmpdir: str):
    """Patch _IS_WINDOWS=True and point LOCALAPPDATA at tmpdir."""
    with (
        patch("cemi.collectors.browser_extensions._IS_WINDOWS", True),
        patch.dict(os.environ, {"LOCALAPPDATA": tmpdir}, clear=False),
    ):
        yield


def _chrome_extensions_dir(base: str) -> str:
    return os.path.join(base, "Google", "Chrome", "User Data", "Default", "Extensions")


def _make_extension(
    extensions_dir: str,
    extension_id: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    version_dir: str = "1.0.0_0",
    manifest: dict[str, Any] | None = None,
) -> str:
    """Create <extensions_dir>/<id>/<version>/manifest.json and return the manifest path."""
    ver_dir = os.path.join(extensions_dir, extension_id, version_dir)
    os.makedirs(ver_dir, exist_ok=True)
    manifest_path = os.path.join(ver_dir, "manifest.json")
    data = manifest or {
        "name": "Test Extension",
        "version": "1.0.0",
        "manifest_version": 2,
        "permissions": ["tabs", "storage"],
        "host_permissions": ["https://*.example.com/*"],
    }
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return manifest_path


# ---------------------------------------------------------------------------
# Non-Windows skip
# ---------------------------------------------------------------------------


class TestNonWindowsSkip:
    def test_non_windows_returns_skipped_reason(self) -> None:
        with patch("cemi.collectors.browser_extensions._IS_WINDOWS", False):
            _, health = BrowserExtensionsCollector().run()
        assert health.skipped_reason is not None
        assert len(health.skipped_reason) > 0

    def test_non_windows_ran_successfully(self) -> None:
        with patch("cemi.collectors.browser_extensions._IS_WINDOWS", False):
            _, health = BrowserExtensionsCollector().run()
        assert health.ran_successfully is True

    def test_non_windows_returns_empty_items(self) -> None:
        with patch("cemi.collectors.browser_extensions._IS_WINDOWS", False):
            items, _ = BrowserExtensionsCollector().run()
        assert items == []

    def test_non_windows_zero_items_collected(self) -> None:
        with patch("cemi.collectors.browser_extensions._IS_WINDOWS", False):
            _, health = BrowserExtensionsCollector().run()
        assert health.items_collected == 0

    def test_non_windows_collector_name(self) -> None:
        with patch("cemi.collectors.browser_extensions._IS_WINDOWS", False):
            _, health = BrowserExtensionsCollector().run()
        assert health.collector_name == "browser_extensions"


# ---------------------------------------------------------------------------
# Missing directories — no crash
# ---------------------------------------------------------------------------


class TestMissingDirectories:
    def test_no_crash_when_all_dirs_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                items, health = BrowserExtensionsCollector().run()
        assert health.ran_successfully is True
        assert items == []

    def test_no_errors_when_dirs_simply_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                _, health = BrowserExtensionsCollector().run()
        assert health.errors == []

    def test_zero_items_when_dirs_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                _, health = BrowserExtensionsCollector().run()
        assert health.items_collected == 0

    def test_privilege_user_when_no_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                _, health = BrowserExtensionsCollector().run()
        assert health.privilege_level == "user"


# ---------------------------------------------------------------------------
# Valid extension parsing
# ---------------------------------------------------------------------------


class TestValidExtension:
    def test_valid_extension_collected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(_chrome_extensions_dir(tmpdir))
            with _windows_env(tmpdir):
                items, health = BrowserExtensionsCollector().run()
        assert len(items) == 1

    def test_items_collected_count_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            _make_extension(ext_dir, extension_id="aaa1")
            _make_extension(ext_dir, extension_id="bbb2")
            with _windows_env(tmpdir):
                items, health = BrowserExtensionsCollector().run()
        assert health.items_collected == 2
        assert len(items) == 2

    def test_browser_field_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(_chrome_extensions_dir(tmpdir))
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["browser"] == "Chrome"

    def test_extension_id_field_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(_chrome_extensions_dir(tmpdir), extension_id="myextensionid")
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["extension_id"] == "myextensionid"

    def test_name_field_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(
                _chrome_extensions_dir(tmpdir),
                manifest={"name": "My Ext", "version": "1.0", "manifest_version": 2},
            )
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["name"] == "My Ext"

    def test_name_none_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(
                _chrome_extensions_dir(tmpdir),
                manifest={"version": "1.0", "manifest_version": 2},
            )
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["name"] is None

    def test_version_field_from_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(
                _chrome_extensions_dir(tmpdir),
                manifest={"name": "Ext", "version": "2.3.4", "manifest_version": 2},
            )
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["version"] == "2.3.4"

    def test_ran_successfully_with_valid_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(_chrome_extensions_dir(tmpdir))
            with _windows_env(tmpdir):
                _, health = BrowserExtensionsCollector().run()
        assert health.ran_successfully is True


# ---------------------------------------------------------------------------
# Permissions extraction
# ---------------------------------------------------------------------------


class TestPermissionsExtraction:
    def test_permissions_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(
                _chrome_extensions_dir(tmpdir),
                manifest={
                    "name": "Ext", "version": "1.0", "manifest_version": 2,
                    "permissions": ["tabs", "storage", "cookies"],
                },
            )
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["permissions"] == ["tabs", "storage", "cookies"]

    def test_permissions_empty_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(
                _chrome_extensions_dir(tmpdir),
                manifest={"name": "Ext", "version": "1.0", "manifest_version": 2},
            )
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["permissions"] == []

    def test_host_permissions_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(
                _chrome_extensions_dir(tmpdir),
                manifest={
                    "name": "Ext", "version": "1.0", "manifest_version": 3,
                    "host_permissions": ["https://*.example.com/*", "https://*.google.com/*"],
                },
            )
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["host_permissions"] == ["https://*.example.com/*", "https://*.google.com/*"]

    def test_host_permissions_empty_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(
                _chrome_extensions_dir(tmpdir),
                manifest={"name": "Ext", "version": "1.0", "manifest_version": 2},
            )
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items[0]["host_permissions"] == []


# ---------------------------------------------------------------------------
# Path redaction
# ---------------------------------------------------------------------------


class TestPathRedaction:
    def test_manifest_path_is_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_extension(_chrome_extensions_dir(tmpdir))
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert isinstance(items[0]["manifest_path"], str)
        assert items[0]["manifest_path"]

    def test_manifest_path_username_is_redacted(self) -> None:
        fake_path = (
            r"C:\Users\alice\AppData\Local\Google\Chrome"
            r"\User Data\Default\Extensions\extid\1.0_0\manifest.json"
        )
        manifest_data = json.dumps({"name": "Ext", "version": "1.0"})
        errors: list[str] = []
        with patch("builtins.open", mock_open(read_data=manifest_data)):
            result = _read_extension_manifest(fake_path, "Chrome", "extid", errors)
        assert result is not None
        assert "alice" not in result["manifest_path"]
        assert "[REDACTED]" in result["manifest_path"]


# ---------------------------------------------------------------------------
# Invalid JSON handling
# ---------------------------------------------------------------------------


class TestInvalidJSON:
    def test_invalid_json_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            ver_dir = os.path.join(ext_dir, "aaa1", "1.0_0")
            os.makedirs(ver_dir, exist_ok=True)
            with open(os.path.join(ver_dir, "manifest.json"), "w") as fh:
                fh.write("{ not valid json }")
            with _windows_env(tmpdir):
                _, health = BrowserExtensionsCollector().run()
        assert len(health.errors) >= 1

    def test_invalid_json_not_added_to_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            ver_dir = os.path.join(ext_dir, "aaa1", "1.0_0")
            os.makedirs(ver_dir, exist_ok=True)
            with open(os.path.join(ver_dir, "manifest.json"), "w") as fh:
                fh.write("not json at all")
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert items == []

    def test_mixed_valid_and_invalid_partial_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            _make_extension(ext_dir, extension_id="good1")
            bad_dir = os.path.join(ext_dir, "bad2", "1.0_0")
            os.makedirs(bad_dir, exist_ok=True)
            with open(os.path.join(bad_dir, "manifest.json"), "w") as fh:
                fh.write("{broken")
            with _windows_env(tmpdir):
                items, health = BrowserExtensionsCollector().run()
        assert len(items) == 1
        assert len(health.errors) >= 1


# ---------------------------------------------------------------------------
# Missing manifest.json — no crash
# ---------------------------------------------------------------------------


class TestMissingManifest:
    def test_no_crash_on_missing_manifest_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            ver_dir = os.path.join(ext_dir, "aaa1", "1.0_0")
            os.makedirs(ver_dir, exist_ok=True)
            # Intentionally no manifest.json
            with _windows_env(tmpdir):
                items, health = BrowserExtensionsCollector().run()
        assert health.ran_successfully is True
        assert items == []
        assert health.errors == []

    def test_non_json_files_in_version_dir_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            ver_dir = os.path.join(ext_dir, "aaa1", "1.0_0")
            os.makedirs(ver_dir, exist_ok=True)
            with open(os.path.join(ver_dir, "background.js"), "w") as fh:
                fh.write("// script")
            with _windows_env(tmpdir):
                items, health = BrowserExtensionsCollector().run()
        assert items == []
        assert health.errors == []


# ---------------------------------------------------------------------------
# Multiple extensions
# ---------------------------------------------------------------------------


class TestMultipleExtensions:
    def test_multiple_extensions_collected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            _make_extension(ext_dir, extension_id="ext1")
            _make_extension(ext_dir, extension_id="ext2")
            _make_extension(ext_dir, extension_id="ext3")
            with _windows_env(tmpdir):
                items, health = BrowserExtensionsCollector().run()
        assert health.items_collected == 3
        assert len(items) == 3

    def test_extension_ids_all_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            _make_extension(ext_dir, extension_id="ext1")
            _make_extension(ext_dir, extension_id="ext2")
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        ids = {item["extension_id"] for item in items}
        assert ids == {"ext1", "ext2"}


# ---------------------------------------------------------------------------
# Localization
# ---------------------------------------------------------------------------


class TestLocalization:
    def test_localized_name_resolved_from_en_locale(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            extension_id = "localized_ext"
            ver_dir = os.path.join(ext_dir, extension_id, "1.0_0")
            os.makedirs(ver_dir, exist_ok=True)
            # Create manifest with __MSG_extensionName__
            manifest_path = os.path.join(ver_dir, "manifest.json")
            with open(manifest_path, "w") as fh:
                json.dump({"name": "__MSG_extensionName__", "version": "1.0"}, fh)
            # Create _locales/en/messages.json
            locales_dir = os.path.join(ver_dir, "_locales", "en")
            os.makedirs(locales_dir, exist_ok=True)
            messages_path = os.path.join(locales_dir, "messages.json")
            with open(messages_path, "w") as fh:
                json.dump({"extensionName": {"message": "Localized Extension Name"}}, fh)
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert len(items) == 1
        assert items[0]["name"] == "Localized Extension Name"

    def test_fallback_to_raw_name_if_localization_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            _make_extension(ext_dir, manifest={"name": "__MSG_extensionName__", "version": "1.0"})
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert len(items) == 1
        assert items[0]["name"] == "__MSG_extensionName__"

    def test_default_locale_used_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            extension_id = "default_locale_ext"
            ver_dir = os.path.join(ext_dir, extension_id, "1.0_0")
            os.makedirs(ver_dir, exist_ok=True)
            # Manifest with default_locale
            manifest_path = os.path.join(ver_dir, "manifest.json")
            with open(manifest_path, "w") as fh:
                json.dump({"name": "__MSG_extensionName__", "version": "1.0", "default_locale": "fr"}, fh)
            # _locales/fr/messages.json
            locales_dir = os.path.join(ver_dir, "_locales", "fr")
            os.makedirs(locales_dir, exist_ok=True)
            messages_path = os.path.join(locales_dir, "messages.json")
            with open(messages_path, "w") as fh:
                json.dump({"extensionName": {"message": "Nom de l'Extension"}}, fh)
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert len(items) == 1
        assert items[0]["name"] == "Nom de l'Extension"

    def test_case_insensitive_message_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            extension_id = "case_insensitive_ext"
            ver_dir = os.path.join(ext_dir, extension_id, "1.0_0")
            os.makedirs(ver_dir, exist_ok=True)
            manifest_path = os.path.join(ver_dir, "manifest.json")
            with open(manifest_path, "w") as fh:
                json.dump({"name": "__MSG_extensionname__", "version": "1.0"}, fh)  # lowercase
            locales_dir = os.path.join(ver_dir, "_locales", "en")
            os.makedirs(locales_dir, exist_ok=True)
            messages_path = os.path.join(locales_dir, "messages.json")
            with open(messages_path, "w") as fh:
                json.dump({"extensionName": {"message": "Case Insensitive Name"}}, fh)  # mixed case
            with _windows_env(tmpdir):
                items, _ = BrowserExtensionsCollector().run()
        assert len(items) == 1
        assert items[0]["name"] == "Case Insensitive Name"

    def test_failed_localization_does_not_add_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = _chrome_extensions_dir(tmpdir)
            _make_extension(ext_dir, manifest={"name": "__MSG_missing__", "version": "1.0"})
            with _windows_env(tmpdir):
                _, health = BrowserExtensionsCollector().run()
        assert health.errors == []


# ---------------------------------------------------------------------------
# _read_extension_manifest unit tests
# ---------------------------------------------------------------------------


class TestReadExtensionManifest:
    def test_valid_manifest_returns_dict(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump({"name": "Ext", "version": "1.0", "permissions": ["tabs"]}, fh)
            path = fh.name
        try:
            result = _read_extension_manifest(path, "Chrome", "abc123", [])
        finally:
            os.unlink(path)
        assert result is not None
        assert result["name"] == "Ext"
        assert result["extension_id"] == "abc123"
        assert result["browser"] == "Chrome"

    def test_invalid_json_returns_none(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            fh.write("{not valid}")
            path = fh.name
        try:
            errors: list[str] = []
            result = _read_extension_manifest(path, "Chrome", "abc123", errors)
        finally:
            os.unlink(path)
        assert result is None
        assert len(errors) == 1

    def test_missing_file_returns_none(self) -> None:
        errors: list[str] = []
        result = _read_extension_manifest("/nonexistent/manifest.json", "Chrome", "abc123", errors)
        assert result is None
        assert len(errors) == 1

    def test_permissions_list_returned(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump({"name": "Ext", "version": "1.0", "permissions": ["tabs", "storage"]}, fh)
            path = fh.name
        try:
            result = _read_extension_manifest(path, "Chrome", "abc123", [])
        finally:
            os.unlink(path)
        assert result is not None
        assert result["permissions"] == ["tabs", "storage"]

    def test_host_permissions_list_returned(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump({"name": "Ext", "version": "1.0", "host_permissions": ["https://*.example.com/*"]}, fh)
            path = fh.name
        try:
            result = _read_extension_manifest(path, "Chrome", "abc123", [])
        finally:
            os.unlink(path)
        assert result is not None
        assert result["host_permissions"] == ["https://*.example.com/*"]

    def test_missing_permissions_returns_empty_list(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump({"name": "Ext", "version": "1.0"}, fh)
            path = fh.name
        try:
            result = _read_extension_manifest(path, "Chrome", "abc123", [])
        finally:
            os.unlink(path)
        assert result is not None
        assert result["permissions"] == []
        assert result["host_permissions"] == []

    def test_name_none_when_absent(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump({"version": "1.0"}, fh)
            path = fh.name
        try:
            result = _read_extension_manifest(path, "Chrome", "abc123", [])
        finally:
            os.unlink(path)
        assert result is not None
        assert result["name"] is None


# ---------------------------------------------------------------------------
# _candidate_dirs unit tests
# ---------------------------------------------------------------------------


class TestCandidateDirs:
    def test_returns_list(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la"}):
            result = _candidate_dirs()
        assert isinstance(result, list)

    def test_chrome_present(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la"}):
            result = _candidate_dirs()
        browsers = [b for b, _ in result]
        assert "Chrome" in browsers

    def test_edge_present(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la"}):
            result = _candidate_dirs()
        browsers = [b for b, _ in result]
        assert "Edge" in browsers

    def test_brave_present(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la"}):
            result = _candidate_dirs()
        browsers = [b for b, _ in result]
        assert "Brave" in browsers

    def test_empty_localappdata_returns_empty_list(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "LOCALAPPDATA"}
        with patch.dict(os.environ, env, clear=True):
            result = _candidate_dirs()
        assert result == []

    def test_path_includes_extensions_segment(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la"}):
            result = _candidate_dirs()
        paths = [p for _, p in result]
        assert all("Extensions" in p for p in paths)


# ---------------------------------------------------------------------------
# _scan_extensions_dir unit tests
# ---------------------------------------------------------------------------


class TestScanExtensionsDir:
    def test_missing_directory_returns_false(self) -> None:
        result = _scan_extensions_dir("/nonexistent/path", "Chrome", [], [])
        assert result is False

    def test_permission_error_returns_true(self) -> None:
        with patch(
            "cemi.collectors.browser_extensions.os.scandir",
            side_effect=PermissionError("access denied"),
        ):
            result = _scan_extensions_dir("/some/path", "Chrome", [], [])
        assert result is True

    def test_oserror_records_error_returns_false(self) -> None:
        errors: list[str] = []
        with patch(
            "cemi.collectors.browser_extensions.os.scandir",
            side_effect=OSError("disk full"),
        ):
            result = _scan_extensions_dir("/some/path", "Chrome", [], errors)
        assert result is False
        assert len(errors) >= 1
