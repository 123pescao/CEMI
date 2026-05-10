"""Tests for scheduled tasks collector."""
from __future__ import annotations

from cemi.collectors.scheduled_tasks import ScheduledTasksCollector


class TestScheduledTasksCollector:
    def test_name(self) -> None:
        collector = ScheduledTasksCollector()
        assert collector.name == "scheduled_tasks"

    def test_privilege_level(self) -> None:
        collector = ScheduledTasksCollector()
        assert collector.privilege_level == "admin"

    def test_collect(self) -> None:
        collector = ScheduledTasksCollector()
        items, health = collector.collect()

        assert items == []
        assert health.collector_name == "scheduled_tasks"
        assert health.ran_successfully is True
        assert health.items_collected == 0
        assert "not implemented safely yet" in health.skipped_reason