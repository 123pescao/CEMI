"""CEMÍ — Computer Evidence Monitoring Inspector.

Local-first, privacy-first desktop security tool.
"""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__: str = _pkg_version("cemi")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
