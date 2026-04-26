"""Tests for cemi.collectors.base."""
from __future__ import annotations

from typing import Any

from CEMI.cemi.src.cemi.collectors.base import BaseCollector
from CEMI.cemi.src.cemi.models import CollectorHealth


class _FailingCollector(BaseCollector):
    name = "failing"
    privilege_level = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        raise RuntimeError("sk-secret1234567890secret error occurred in collector")


class TestBaseCollectorFailure:
    def test_failure_never_raises(self) -> None:
        collector = _FailingCollector()
        items, health = collector.run()
        assert items == []
        assert health.ran_successfully is False

    def test_duration_always_measured(self) -> None:
        collector = _FailingCollector()
        _, health = collector.run()
        assert health.duration_seconds >= 0.0

    def test_redacts_exception_messages(self) -> None:
        collector = _FailingCollector()
        _, health = collector.run()
        assert health.errors
        assert "sk-secret1234567890secret" not in health.errors[0]
        assert "[REDACTED_TOKEN]" in health.errors[0]
