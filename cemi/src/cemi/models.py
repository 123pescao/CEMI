"""Core data models for CEMÍ.

All models are Pydantic v2 and frozen (immutable) by default. Models
intentionally describe *data already redacted* — the redaction utilities
in ``cemi.utils.redact`` are the only sanctioned way to produce values
for the fields that could contain user-identifying content.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- Enums --------------------------------------------------------------------


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceType(str, Enum):
    FILE_PATH = "FILE_PATH"
    REGISTRY_KEY = "REGISTRY_KEY"
    PROCESS = "PROCESS"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    PERMISSION = "PERMISSION"
    HASH = "HASH"
    SIGNATURE_STATUS = "SIGNATURE_STATUS"
    METADATA = "METADATA"


PrivilegeLevel = Literal["user", "admin", "partial"]


# --- Models -------------------------------------------------------------------


class EvidenceItem(BaseModel):
    """A single redacted evidence datum that supports a finding.

    ``value`` MUST already be redacted before being placed in this model.
    Use ``cemi.utils.redact.redact_evidence_item`` to produce instances
    from raw values.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: EvidenceType
    value: str
    label: str


class CollectorHealth(BaseModel):
    """The outcome of running a single collector.

    Collectors must never raise; they must produce a ``CollectorHealth``
    instance describing whether they succeeded, why they might have
    skipped, and how long they took.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    collector_name: str
    ran_successfully: bool
    privilege_level: PrivilegeLevel
    items_collected: int
    skipped_reason: Optional[str] = None
    duration_seconds: float
    errors: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A single, actionable finding surfaced by the rule engine."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    instance_id: UUID
    rule_version: str
    title: str
    severity: Severity
    confidence: Confidence
    app: Optional[str] = None
    category: str
    official_explanation: str
    in_other_words: str
    why_this_matters: str
    evidence: list[EvidenceItem]
    recommended_action: str
    safe_to_ignore_when: Optional[str] = None
    false_positive_risk: str
    requires_admin_to_verify: bool
    created_at: datetime
    scan_id: str


class ScanResult(BaseModel):
    """The top-level artifact produced by one run of CEMÍ."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str
    scan_version: str
    started_at: datetime
    completed_at: datetime
    hostname_redacted: str
    privilege_level: PrivilegeLevel
    collector_health: list[CollectorHealth]
    findings: list[Finding]
    total_apps_scanned: int


__all__ = [
    "Confidence",
    "CollectorHealth",
    "EvidenceItem",
    "EvidenceType",
    "Finding",
    "PrivilegeLevel",
    "ScanResult",
    "Severity",
]
