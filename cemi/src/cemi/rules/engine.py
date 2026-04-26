"""Rule engine base classes for CEMÍ.

:class:`RuleEngine` accepts a list of :class:`BaseRule` implementations,
runs each against the collected items, and returns merged findings.

Each rule is isolated — an exception thrown by one rule is caught so that
the remaining rules still execute.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from cemi.models import Finding


class BaseRule(ABC):
    """Abstract base for every deterministic CEMÍ rule."""

    @abstractmethod
    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        """Inspect collected items and return any findings.

        Implementations MUST:
        * Use only already-redacted values in evidence.
        * Never perform I/O (no network, no filesystem, no subprocess).
        * Never raise — swallow and return ``[]`` on unexpected errors.
        """
        raise NotImplementedError


class RuleEngine:
    """Orchestrate one or more rules against a snapshot of collected items."""

    def __init__(self, rules: list[BaseRule]) -> None:
        self._rules = rules

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        """Run all rules and return the merged finding list.

        A crash inside a single rule is caught; the other rules continue
        to execute.  Callers that want fail-closed behaviour should wrap
        this method in their own ``try/except``.
        """
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                findings.extend(rule.evaluate(items_by_collector, scan_id))
            except Exception:  # noqa: BLE001 — rule isolation is deliberate
                pass
        return findings


__all__ = ["BaseRule", "RuleEngine"]
