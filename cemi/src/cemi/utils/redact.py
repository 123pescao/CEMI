"""Pure redaction utilities for CEMÍ.

These functions are intentionally free of side effects:

* They do not touch the filesystem.
* They do not read environment variables.
* They do not call out to the OS or the network.
* They never mutate their inputs.

Redaction is deliberately conservative — when in doubt, redact. The goal
is that no value that leaves these functions should contain a username,
a long opaque token, a hex digest, or an API key.
"""
from __future__ import annotations

import re
from typing import Final

from cemi.models import EvidenceItem

# Public markers. These also appear in ``cemi.config`` and are re-declared
# here so this module remains usable even with a stripped-down config.
REDACTED: Final[str] = "[REDACTED]"
REDACTED_TOKEN: Final[str] = "[REDACTED_TOKEN]"


# ``Users\<name>`` or ``Users/<name>`` (one or more separators, case-insensitive).
# Captures:
#   group(1) = literal "Users" (preserves casing)
#   group(2) = separator run (preserves slash style)
#   group(3) = username segment up to the next slash
_USERS_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(Users)([\\/]+)([^\\/]+)",
    re.IGNORECASE,
)

# API-key prefixed secrets. Tail must be at least 8 chars so short false
# positives like ``sk-1`` don't get redacted.
_SK_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}")
_GHP_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\bghp_[A-Za-z0-9_\-]{8,}")

# ``api_key = <value>``, ``token: <value>``, ``password=<value>``, etc.
# Requires an explicit ``=`` or ``:`` so prose like "the auth token is
# required" is not mangled.
_KV_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(api_key|token|password)\s*[=:]\s*\S+",
    re.IGNORECASE,
)

# Long hex digests (SHA-1 = 40, SHA-256 = 64, ...).
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"\b[a-fA-F0-9]{40,}\b")

# Base64-like runs over 20 characters that contain at least one digit or
# a base64 special character (+, /, =). The digit/special-char requirement
# prevents normal English words (all letters, no digits) from being redacted.
# Hex is handled first so already-redacted hex values are not re-matched.
_BASE64_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?=[A-Za-z0-9+/=]*[0-9+/=])[A-Za-z0-9+/=]{21,}\b"
)


def redact_path(path: str) -> str:
    """Redact a user path so the username segment is masked.

    Handles:

    * Backslash Windows paths         ``C:\\Users\\john\\...``
    * Forward-slash paths             ``C:/Users/john/...``
    * Mixed separator paths           ``C:/Users\\john/...``
    * Usernames containing spaces     ``C:\\Users\\John Doe\\...``
    * UNC paths                       ``\\\\server\\share\\Users\\john\\...``
    * Lowercase / mixed-case ``Users``
    * Already-redacted inputs (idempotent)

    The function returns a new string; the input is never mutated.
    """
    if not path:
        return path

    def _sub(match: re.Match[str]) -> str:
        users, sep, username = match.group(1), match.group(2), match.group(3)
        if username == REDACTED:
            return match.group(0)
        return f"{users}{sep}{REDACTED}"

    return _USERS_PATH_RE.sub(_sub, path)


def redact_string(value: str) -> str:
    """Redact tokens / secrets from an arbitrary string.

    Applied in order so that earlier replacements cannot be clobbered by
    later, more aggressive patterns:

    1. ``sk-...`` API keys
    2. ``ghp_...`` GitHub personal-access tokens
    3. ``api_key=...`` / ``token=...`` key-value pairs
    4. 40+ char hex digests
    5. 21+ char base64-like runs

    Returns a new string; the original is not modified.
    """
    if not value:
        return value

    value = _SK_TOKEN_RE.sub(REDACTED_TOKEN, value)
    value = _GHP_TOKEN_RE.sub(REDACTED_TOKEN, value)
    value = _KV_TOKEN_RE.sub(REDACTED_TOKEN, value)
    value = _HEX_RE.sub(REDACTED_TOKEN, value)
    value = _BASE64_RE.sub(REDACTED_TOKEN, value)
    return value


def redact_evidence_item(item: EvidenceItem) -> EvidenceItem:
    """Return a *new* ``EvidenceItem`` whose ``value`` has been fully redacted.

    Both path redaction (for any embedded user directory) and token
    redaction (for any embedded hex / base64 / API key) are applied.
    The input item is never mutated — ``EvidenceItem`` is frozen by
    Pydantic config, but the non-mutation contract is also an explicit
    part of this function's guarantee.
    """
    redacted_value = redact_string(redact_path(item.value))
    return EvidenceItem(
        type=item.type,
        value=redacted_value,
        label=item.label,
    )


__all__ = [
    "REDACTED",
    "REDACTED_TOKEN",
    "redact_evidence_item",
    "redact_path",
    "redact_string",
]
