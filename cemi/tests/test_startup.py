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

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows only")
    def test_collect_windows(self) -> None:
        collector = StartupCollector()
        items, health = collector.collect()

        assert isinstance(items, list)
        assert health.collector_name == "startup"
        assert health.ran_successfully is True
        # Check that items have expected fields
        for item in items:
            assert "name" in item
            assert "source" in item
            assert "command" in item
            assert "path_redacted" in item
            assert "scope" in item