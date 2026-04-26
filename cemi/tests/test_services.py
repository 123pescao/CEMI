"""Tests for cemi.collectors.services."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cemi.collectors.services import (
    ServicesCollector,
    _redact_service_username,
)
from cemi.models import CollectorHealth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_svc_mock(
    name: str = "TestSvc",
    display_name: str = "Test Service",
    status: str = "running",
    start_type: str = "automatic",
    binpath: str = r"C:\Windows\System32\test.exe",
    username: str = "LocalSystem",
) -> MagicMock:
    svc = MagicMock()
    svc.name.return_value = name
    svc.display_name.return_value = display_name
    svc.status.return_value = status
    svc.start_type.return_value = start_type
    svc.binpath.return_value = binpath
    svc.username.return_value = username
    return svc


def _make_psutil(services: list[MagicMock] | None = None) -> MagicMock:
    """Build a mock psutil module with win_service_iter."""
    mock = MagicMock()
    mock.win_service_iter.return_value = iter(services or [])
    # Use real built-in exceptions as stand-ins so except clauses work.
    mock.AccessDenied = PermissionError
    mock.NoSuchProcess = ProcessLookupError
    return mock


def _patch_services(mock_psutil: MagicMock):
    """Context manager: patch _psutil and _PSUTIL_AVAILABLE in the module."""
    return (
        patch("cemi.collectors.services._psutil", mock_psutil),
        patch("cemi.collectors.services._PSUTIL_AVAILABLE", True),
    )


# ---------------------------------------------------------------------------
# Non-Windows / non-mocked — runs on any platform
# ---------------------------------------------------------------------------


class TestServicesCollectorPlatformSafe:
    """Verify graceful behaviour regardless of platform or psutil state."""

    def test_returns_list_and_health(self) -> None:
        collector = ServicesCollector()
        items, health = collector.run()
        assert isinstance(items, list)
        assert isinstance(health, CollectorHealth)

    def test_does_not_crash(self) -> None:
        ServicesCollector().run()

    def test_items_collected_non_negative(self) -> None:
        _, health = ServicesCollector().run()
        assert health.items_collected >= 0

    def test_ran_successfully_is_true(self) -> None:
        _, health = ServicesCollector().run()
        # On non-Windows the collector skips; it does not fail.
        assert health.ran_successfully is True

    def test_skips_when_win_service_iter_absent(self) -> None:
        """Simulate psutil present but on a non-Windows platform."""
        mock_no_svc = MagicMock(spec=["AccessDenied", "NoSuchProcess"])
        p1 = patch("cemi.collectors.services._psutil", mock_no_svc)
        p2 = patch("cemi.collectors.services._PSUTIL_AVAILABLE", True)
        with p1, p2:
            _, health = ServicesCollector().collect()
        assert health.skipped_reason is not None
        assert health.ran_successfully is True

    def test_skips_when_psutil_unavailable(self) -> None:
        with patch("cemi.collectors.services._PSUTIL_AVAILABLE", False):
            _, health = ServicesCollector().collect()
        assert health.skipped_reason is not None
        assert health.ran_successfully is True


# ---------------------------------------------------------------------------
# Mocked psutil — Windows service logic on any platform
# ---------------------------------------------------------------------------


class TestServicesCollectorMocked:
    """Service collection logic exercised through a mocked psutil."""

    def test_collects_services(self) -> None:
        svc = _make_svc_mock()
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, health = ServicesCollector().collect()
        assert len(items) == 1
        assert health.items_collected == 1
        assert health.ran_successfully is True

    def test_service_fields_present(self) -> None:
        svc = _make_svc_mock(
            name="MySvc",
            display_name="My Service",
            status="running",
            start_type="automatic",
            binpath=r"C:\Windows\System32\svchost.exe",
            username="LocalSystem",
        )
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, _ = ServicesCollector().collect()
        entry = items[0]
        assert entry["name"] == "MySvc"
        assert entry["display_name"] == "My Service"
        assert entry["status"] == "running"
        assert entry["start_type"] == "automatic"
        assert "binary_path" in entry
        assert "username" in entry

    def test_user_path_in_binary_path_is_redacted(self) -> None:
        svc = _make_svc_mock(binpath=r"C:\Users\alice\AppData\mysvc.exe")
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, _ = ServicesCollector().collect()
        bp = items[0]["binary_path"]
        assert bp is not None
        assert "alice" not in bp
        assert "[REDACTED]" in bp

    def test_user_account_in_username_is_redacted(self) -> None:
        svc = _make_svc_mock(username=r"DOMAIN\john")
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, _ = ServicesCollector().collect()
        assert "john" not in (items[0]["username"] or "")
        assert "[REDACTED]" in (items[0]["username"] or "")

    def test_system_account_not_redacted(self) -> None:
        svc = _make_svc_mock(username="LocalSystem")
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, _ = ServicesCollector().collect()
        assert items[0]["username"] == "LocalSystem"

    def test_nt_authority_account_not_redacted(self) -> None:
        svc = _make_svc_mock(username="NT AUTHORITY\\LocalService")
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, _ = ServicesCollector().collect()
        assert items[0]["username"] == "NT AUTHORITY\\LocalService"

    def test_access_denied_on_field_does_not_crash(self) -> None:
        svc = _make_svc_mock()
        svc.binpath.side_effect = PermissionError("access denied")
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, health = ServicesCollector().collect()
        # Service is still collected (name succeeded); binary_path is None.
        assert len(items) == 1
        assert items[0]["binary_path"] is None

    def test_access_denied_sets_partial_privilege(self) -> None:
        svc = _make_svc_mock()
        svc.binpath.side_effect = PermissionError("access denied")
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            _, health = ServicesCollector().collect()
        assert health.privilege_level == "partial"

    def test_no_access_denied_keeps_user_privilege(self) -> None:
        mock_ps = _make_psutil([_make_svc_mock()])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            _, health = ServicesCollector().collect()
        assert health.privilege_level == "user"

    def test_errors_from_iteration_are_redacted(self) -> None:
        """Errors containing user paths must be redacted before storage."""
        mock_ps = _make_psutil()
        mock_ps.win_service_iter.side_effect = OSError(
            r"Cannot iterate C:\Users\carol\NTUSER.DAT"
        )
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            _, health = ServicesCollector().collect()
        assert health.errors
        for msg in health.errors:
            assert "carol" not in msg

    def test_empty_service_list_returns_zero(self) -> None:
        mock_ps = _make_psutil([])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, health = ServicesCollector().collect()
        assert items == []
        assert health.items_collected == 0

    def test_service_without_name_is_skipped(self) -> None:
        svc = _make_svc_mock()
        svc.name.return_value = ""
        mock_ps = _make_psutil([svc])
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, health = ServicesCollector().collect()
        assert items == []
        assert health.items_collected == 0

    def test_multiple_services_collected(self) -> None:
        svcs = [_make_svc_mock(name=f"Svc{i}") for i in range(5)]
        mock_ps = _make_psutil(svcs)
        p1, p2 = _patch_services(mock_ps)
        with p1, p2:
            items, health = ServicesCollector().collect()
        assert len(items) == 5
        assert health.items_collected == 5


# ---------------------------------------------------------------------------
# _redact_service_username unit tests
# ---------------------------------------------------------------------------


class TestRedactServiceUsername:
    def test_none_returns_none(self) -> None:
        assert _redact_service_username(None) is None

    def test_empty_returns_empty(self) -> None:
        assert _redact_service_username("") == ""

    def test_local_system_preserved(self) -> None:
        assert _redact_service_username("LocalSystem") == "LocalSystem"

    def test_nt_authority_system_preserved(self) -> None:
        assert _redact_service_username("NT AUTHORITY\\SYSTEM") == "NT AUTHORITY\\SYSTEM"

    def test_nt_authority_localservice_preserved(self) -> None:
        assert _redact_service_username("NT AUTHORITY\\LocalService") == "NT AUTHORITY\\LocalService"

    def test_nt_service_preserved(self) -> None:
        assert _redact_service_username("NT SERVICE\\SomeSvc") == "NT SERVICE\\SomeSvc"

    def test_domain_user_redacted(self) -> None:
        result = _redact_service_username(r"CORP\john")
        assert "john" not in result
        assert "[REDACTED]" in result
        assert "CORP" in result

    def test_local_user_redacted(self) -> None:
        result = _redact_service_username(r".\alice")
        assert "alice" not in result
        assert "[REDACTED]" in result

    def test_bare_username_redacted(self) -> None:
        result = _redact_service_username("john")
        assert result == "[REDACTED]"
