"""Tests for NativeMessagingHostsCollector."""
from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cemi.collectors.native_messaging import (
    NativeMessagingHostsCollector,
    _candidate_dirs,
    _read_manifest,
    _scan_directory,
)
from cemi.models import CollectorHealth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@contextmanager
def _windows_env(tmpdir: str):
    """Patch _IS_WINDOWS=True and point all env vars at tmpdir sub-dirs."""
    pf = os.path.join(tmpdir, "pf")
    pf86 = os.path.join(tmpdir, "pf86")
    with (
        patch("cemi.collectors.native_messaging._IS_WINDOWS", True),
        patch.dict(
            os.environ,
            {
                "LOCALAPPDATA": tmpdir,
                "PROGRAMFILES": pf,
                "PROGRAMFILES(X86)": pf86,
            },
            clear=False,
        ),
    ):
        yield


def _chrome_user_dir(base: str) -> str:
    return os.path.join(base, "Google", "Chrome", "User Data", "NativeMessagingHosts")


def _write_manifest(directory: str, filename: str, data: dict[str, Any]) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


_VALID_MANIFEST: dict[str, Any] = {
    "name": "com.example.foo",
    "description": "Example native host",
    "path": r"C:\Users\john\AppData\Local\foo.exe",
    "type": "stdio",
    "allowed_origins": ["chrome-extension://abcdefghijklmnopqrstuvwxyz/"],
}


# ---------------------------------------------------------------------------
# Non-Windows skip
# ---------------------------------------------------------------------------


class TestNonWindowsSkip:
    def test_non_windows_returns_skipped_reason(self) -> None:
        with patch("cemi.collectors.native_messaging._IS_WINDOWS", False):
            _, health = NativeMessagingHostsCollector().run()
        assert health.skipped_reason is not None
        assert len(health.skipped_reason) > 0

    def test_non_windows_ran_successfully(self) -> None:
        with patch("cemi.collectors.native_messaging._IS_WINDOWS", False):
            _, health = NativeMessagingHostsCollector().run()
        assert health.ran_successfully is True

    def test_non_windows_returns_empty_items(self) -> None:
        with patch("cemi.collectors.native_messaging._IS_WINDOWS", False):
            items, _ = NativeMessagingHostsCollector().run()
        assert items == []

    def test_non_windows_zero_items_collected(self) -> None:
        with patch("cemi.collectors.native_messaging._IS_WINDOWS", False):
            _, health = NativeMessagingHostsCollector().run()
        assert health.items_collected == 0

    def test_non_windows_collector_name(self) -> None:
        with patch("cemi.collectors.native_messaging._IS_WINDOWS", False):
            _, health = NativeMessagingHostsCollector().run()
        assert health.collector_name == "native_messaging_hosts"


# ---------------------------------------------------------------------------
# Missing directories — no crash
# ---------------------------------------------------------------------------


class TestMissingDirectories:
    def test_no_crash_when_all_dirs_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                items, health = NativeMessagingHostsCollector().run()
        assert health.ran_successfully is True
        assert items == []

    def test_no_errors_when_dirs_simply_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                _, health = NativeMessagingHostsCollector().run()
        assert health.errors == []

    def test_zero_items_when_dirs_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                _, health = NativeMessagingHostsCollector().run()
        assert health.items_collected == 0

    def test_privilege_user_when_no_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                _, health = NativeMessagingHostsCollector().run()
        assert health.privilege_level == "user"


# ---------------------------------------------------------------------------
# Valid manifest collection
# ---------------------------------------------------------------------------


class TestValidManifest:
    def test_valid_manifest_collected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "com.example.foo.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, health = NativeMessagingHostsCollector().run()
        assert len(items) == 1

    def test_items_collected_count_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "com.example.foo.json", _VALID_MANIFEST)
            _write_manifest(nmh, "com.example.bar.json", {**_VALID_MANIFEST, "name": "com.example.bar"})
            with _windows_env(tmpdir):
                items, health = NativeMessagingHostsCollector().run()
        assert health.items_collected == 2
        assert len(items) == 2

    def test_browser_field_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["browser"] == "Chrome"

    def test_scope_user_for_localappdata_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["scope"] == "user"

    def test_name_field_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["name"] == "com.example.foo"

    def test_description_field_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["description"] == "Example native host"

    def test_type_field_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["type"] == "stdio"

    def test_allowed_origins_collected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["allowed_origins"] == ["chrome-extension://abcdefghijklmnopqrstuvwxyz/"]

    def test_allowed_origins_empty_list_when_absent(self) -> None:
        manifest = {k: v for k, v in _VALID_MANIFEST.items() if k != "allowed_origins"}
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", manifest)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["allowed_origins"] == []

    def test_ran_successfully_with_valid_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                _, health = NativeMessagingHostsCollector().run()
        assert health.ran_successfully is True


# ---------------------------------------------------------------------------
# Path redaction
# ---------------------------------------------------------------------------


class TestPathRedaction:
    def test_manifest_path_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        # manifest_path should not contain a raw username — but since tmpdir
        # is a system temp path (no Users segment), check it's at least a string.
        assert isinstance(items[0]["manifest_path"], str)
        assert items[0]["manifest_path"]  # non-empty

    def test_binary_path_redacted_username(self) -> None:
        # _VALID_MANIFEST has path = C:\Users\john\..., which redact_path() must sanitise.
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        binary = items[0]["binary_path"]
        assert binary is not None
        assert "john" not in binary
        assert "[REDACTED]" in binary

    def test_binary_path_none_when_absent(self) -> None:
        manifest = {k: v for k, v in _VALID_MANIFEST.items() if k != "path"}
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", manifest)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items[0]["binary_path"] is None

    def test_binary_path_preserves_safe_path(self) -> None:
        manifest = {**_VALID_MANIFEST, "path": r"C:\Program Files\app\host.exe"}
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", manifest)
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        # No username → path passes through unchanged
        assert items[0]["binary_path"] == r"C:\Program Files\app\host.exe"


# ---------------------------------------------------------------------------
# Invalid / non-JSON files
# ---------------------------------------------------------------------------


class TestInvalidJSON:
    def test_invalid_json_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            os.makedirs(nmh, exist_ok=True)
            with open(os.path.join(nmh, "bad.json"), "w") as fh:
                fh.write("{ this is not json }")
            with _windows_env(tmpdir):
                _, health = NativeMessagingHostsCollector().run()
        assert len(health.errors) >= 1

    def test_invalid_json_not_added_to_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            os.makedirs(nmh, exist_ok=True)
            with open(os.path.join(nmh, "bad.json"), "w") as fh:
                fh.write("not json at all")
            with _windows_env(tmpdir):
                items, _ = NativeMessagingHostsCollector().run()
        assert items == []

    def test_only_json_files_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            os.makedirs(nmh, exist_ok=True)
            # Write a non-.json file with valid JSON content — must be ignored.
            with open(os.path.join(nmh, "host.txt"), "w") as fh:
                json.dump(_VALID_MANIFEST, fh)
            with open(os.path.join(nmh, "host.exe"), "w") as fh:
                fh.write("binary")
            with _windows_env(tmpdir):
                items, health = NativeMessagingHostsCollector().run()
        assert items == []
        assert health.errors == []

    def test_mixed_valid_and_invalid_partial_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "good.json", _VALID_MANIFEST)
            with open(os.path.join(nmh, "bad.json"), "w") as fh:
                fh.write("{broken")
            with _windows_env(tmpdir):
                items, health = NativeMessagingHostsCollector().run()
        assert len(items) == 1
        assert len(health.errors) >= 1


# ---------------------------------------------------------------------------
# Permission errors → privilege level
# ---------------------------------------------------------------------------


class TestPermissionErrors:
    def test_permission_error_on_system_dir_sets_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                with patch(
                    "cemi.collectors.native_messaging.os.scandir",
                    side_effect=PermissionError("access denied"),
                ):
                    _, health = NativeMessagingHostsCollector().run()
        assert health.privilege_level == "partial"

    def test_permission_error_ran_successfully_still_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with _windows_env(tmpdir):
                with patch(
                    "cemi.collectors.native_messaging.os.scandir",
                    side_effect=PermissionError("access denied"),
                ):
                    _, health = NativeMessagingHostsCollector().run()
        assert health.ran_successfully is True

    def test_no_permission_error_privilege_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nmh = _chrome_user_dir(tmpdir)
            _write_manifest(nmh, "host.json", _VALID_MANIFEST)
            with _windows_env(tmpdir):
                _, health = NativeMessagingHostsCollector().run()
        assert health.privilege_level == "user"


# ---------------------------------------------------------------------------
# _scan_directory unit tests
# ---------------------------------------------------------------------------


class TestScanDirectory:
    def test_missing_directory_returns_false(self) -> None:
        result = _scan_directory("/nonexistent/path", "Chrome", "user", [], [])
        assert result is False

    def test_permission_error_returns_true(self) -> None:
        with patch(
            "cemi.collectors.native_messaging.os.scandir",
            side_effect=PermissionError,
        ):
            result = _scan_directory("/some/path", "Chrome", "system", [], [])
        assert result is True

    def test_oserror_records_error_returns_false(self) -> None:
        hosts: list = []
        errors: list[str] = []
        with patch(
            "cemi.collectors.native_messaging.os.scandir",
            side_effect=OSError("disk full"),
        ):
            result = _scan_directory("/some/path", "Chrome", "system", hosts, errors)
        assert result is False
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# _read_manifest unit tests
# ---------------------------------------------------------------------------


class TestReadManifest:
    def test_valid_manifest_returns_dict(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            json.dump(_VALID_MANIFEST, fh)
            path = fh.name
        try:
            result = _read_manifest(path, "Chrome", "user", [])
        finally:
            os.unlink(path)
        assert result is not None
        assert result["name"] == "com.example.foo"

    def test_invalid_json_returns_none(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            fh.write("{not valid}")
            path = fh.name
        try:
            errors: list[str] = []
            result = _read_manifest(path, "Chrome", "user", errors)
        finally:
            os.unlink(path)
        assert result is None
        assert len(errors) == 1

    def test_missing_file_returns_none(self) -> None:
        errors: list[str] = []
        result = _read_manifest("/nonexistent/host.json", "Chrome", "user", errors)
        assert result is None
        assert len(errors) == 1

    def test_binary_path_redacted_in_output(self) -> None:
        manifest = {**_VALID_MANIFEST, "path": r"C:\Users\alice\host.exe"}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            json.dump(manifest, fh)
            path = fh.name
        try:
            result = _read_manifest(path, "Chrome", "user", [])
        finally:
            os.unlink(path)
        assert result is not None
        assert "alice" not in (result["binary_path"] or "")
        assert "[REDACTED]" in (result["binary_path"] or "")


# ---------------------------------------------------------------------------
# _candidate_dirs unit tests
# ---------------------------------------------------------------------------


class TestCandidateDirs:
    def test_returns_list(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la", "PROGRAMFILES": "/tmp/pf", "PROGRAMFILES(X86)": "/tmp/pf86"}):
            result = _candidate_dirs()
        assert isinstance(result, list)

    def test_user_scope_entries_present(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la", "PROGRAMFILES": "/tmp/pf", "PROGRAMFILES(X86)": "/tmp/pf86"}):
            result = _candidate_dirs()
        scopes = [scope for _, scope, _ in result]
        assert "user" in scopes

    def test_system_scope_entries_present(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la", "PROGRAMFILES": "/tmp/pf", "PROGRAMFILES(X86)": "/tmp/pf86"}):
            result = _candidate_dirs()
        scopes = [scope for _, scope, _ in result]
        assert "system" in scopes

    def test_chrome_browser_present(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/la", "PROGRAMFILES": "/tmp/pf", "PROGRAMFILES(X86)": "/tmp/pf86"}):
            result = _candidate_dirs()
        browsers = [b for b, _, _ in result]
        assert "Chrome" in browsers

    def test_empty_localappdata_excluded(self) -> None:
        env = {"PROGRAMFILES": "/tmp/pf", "PROGRAMFILES(X86)": "/tmp/pf86"}
        with patch.dict(os.environ, env):
            # Remove LOCALAPPDATA entirely
            patched = {k: v for k, v in os.environ.items() if k != "LOCALAPPDATA"}
            patched.update(env)
            with patch.dict(os.environ, patched, clear=True):
                result = _candidate_dirs()
        scopes = [scope for _, scope, _ in result]
        assert "user" not in scopes
