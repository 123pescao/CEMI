"""Collector framework for CEMÍ.

This phase ships only the abstract base class. Concrete collectors that
inspect the operating system arrive in a later phase and MUST obey the
privacy-first rules documented in ``privacy.md`` and ``SECURITY.md``.
"""
from cemi.collectors.base import BaseCollector

__all__ = ["BaseCollector"]
