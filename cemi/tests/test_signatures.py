"""Tests for signatures collector."""
from __future__ import annotations

import platform

import pytest

from cemi.collectors.signatures import SignaturesCollector


class TestSignaturesCollector:
    def test_name(self) -> None:
        collector = SignaturesCollector()
        assert collector.name == "signatures"

    def test_privilege_level(self) -> None:
        collector = SignaturesCollector()
        assert collector.privilege_level == "user"

    def test_collect_non_windows(self) -> None:
        import platform
        if platform.system() == "Windows":
            pytest.skip("Test for non-Windows only")

        collector = SignaturesCollector()
        items, health = collector.collect()

        assert items == []
        assert health.collector_name == "signatures"
        assert health.ran_successfully is True
        assert health.items_collected == 0
        assert health.skipped_reason is not None
        assert "safe raw-path isolation" in health.skipped_reason

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows only")
    def test_collect_windows(self) -> None:
        collector = SignaturesCollector()
        items, health = collector.collect()

        assert isinstance(items, list)
        assert items == []
        assert health.collector_name == "signatures"
        assert health.ran_successfully is True
        assert health.items_collected == 0
        assert health.skipped_reason is not None
        # Signature collection is deferred; verify it's skipped