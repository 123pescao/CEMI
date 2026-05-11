"""Digital signature collector for CEMÍ.

Deferred: Honest skip pending a safe raw-path isolation architecture.

Signature verification requires access to filesystem paths. To avoid
introducing raw (unredacted) paths into collector outputs where they
might leak into findings, JSON, HTML, CLI, or history, signature
collection is deferred until a privacy-safe pipeline is designed.

Current approach (Option A):
- Skip gracefully with clear reason.
- Do not crawl filesystem.
- Do not execute files.
- Do not compute hashes on arbitrary files.
- Do not upload or call reputation services.

Future approach (Option B, deferred):
- Establish a safe path isolation architecture.
- Never expose raw paths in collector items.
- Rules extract paths from source collectors directly if needed.
"""
from __future__ import annotations

import time
from typing import Any, ClassVar

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel


class SignaturesCollector(BaseCollector):
    """Collect digital signature information for executable paths.
    
    Currently deferred: See module docstring for design rationale.
    """

    name: ClassVar[str] = "signatures"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        """Return empty items with skipped reason."""
        start = time.perf_counter()

        return [], CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=self.privilege_level,
            items_collected=0,
            skipped_reason="Signature verification skipped: safe raw-path isolation architecture not yet implemented",
            duration_seconds=time.perf_counter() - start,
            errors=[],
        )


__all__ = ["SignaturesCollector"]