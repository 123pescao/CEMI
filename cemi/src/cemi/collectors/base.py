"""Abstract base class for collectors.

A *collector* is a small, focused component that reads system metadata
and returns a structured list of items plus a :class:`CollectorHealth`
report. Collectors must:

* Never raise out of :meth:`BaseCollector.run`. Any failure is captured
  and reported as a health record with ``ran_successfully=False``.
* Never perform network I/O.
* Never read personal user files.
* Redact any path- or token-like value before including it in their
  output items.

The base class provides the safety wrapper (timing, exception capture,
health synthesis). Subclasses only need to implement :meth:`collect`.
"""
from __future__ import annotations

import time
import traceback
from abc import ABC, abstractmethod
from typing import Any, ClassVar, get_args

from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_string


class BaseCollector(ABC):
    """Abstract base class for all CEMÍ collectors."""

    #: Human-readable identifier for this collector.
    name: ClassVar[str] = "base"

    #: Declared privilege level. Subclasses override.
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    # ---- subclass API --------------------------------------------------

    @abstractmethod
    def collect(self) -> tuple[list[Any], CollectorHealth]:
        """Perform the actual collection.

        Implementations return the collected items together with a
        :class:`CollectorHealth` describing the outcome. Implementations
        SHOULD populate ``items_collected`` and ``duration_seconds`` in
        their returned health — :meth:`run` will backfill any missing
        fields on failure.
        """
        raise NotImplementedError

    # ---- safety wrapper ------------------------------------------------

    def run(self) -> tuple[list[Any], CollectorHealth]:
        """Execute :meth:`collect` with a hard safety net.

        * Measures wall-clock duration.
        * Catches *every* exception (including ``BaseException`` subclasses
          except :class:`KeyboardInterrupt` and :class:`SystemExit`, which
          remain propagatable for user control).
        * Never raises. Returns an empty items list and a failure-shaped
          :class:`CollectorHealth` if anything goes wrong.
        """
        start = time.perf_counter()
        try:
            items, health = self.collect()
        except (KeyboardInterrupt, SystemExit):
            # Intentionally re-raised — the user (or runtime) asked to stop.
            raise
        except Exception as exc:  # noqa: BLE001 — this is deliberate
            duration = time.perf_counter() - start
            # ``traceback`` info is kept short and contains no paths that
            # haven't already been generated from our own code. We do
            # NOT include the full traceback in user-facing output.
            error_line = redact_string(f"{type(exc).__name__}: {exc}")
            health = CollectorHealth(
                collector_name=self.name,
                ran_successfully=False,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason=None,
                duration_seconds=duration,
                errors=[error_line],
            )
            return [], health

        # Success path: we still want to ensure the returned health
        # reflects our identity fields, in case a subclass forgot to set
        # them correctly.
        return items, health


__all__ = ["BaseCollector"]
