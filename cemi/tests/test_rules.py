"""Tests for the CEMÍ rule engine and built-in rules."""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from cemi.models import CollectorHealth, Confidence, EvidenceType, Finding, Severity
from cemi.rules.engine import BaseRule, RuleEngine
from cemi.rules.native_messaging_host import (
    RULE_ID as NMH_RULE_ID,
    RULE_VERSION as NMH_RULE_VERSION,
    NativeMessagingHostRule,
)
from cemi.rules.service_user_path import (
    RULE_ID,
    RULE_VERSION,
    ServiceUserPathRule,
)
from cemi.scan_engine import ScanEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCAN_ID = "test-scan-id-0001"

_USER_PATH_SVC = {
    "name": "EvilPersist",
    "binary_path": r"C:\Users\[REDACTED]\AppData\Local\evil.exe",
    "state": "running",
    "start_type": "auto",
    "username": "[REDACTED]",
}

_SYSTEM_PATH_SVC = {
    "name": "LegitSvc",
    "binary_path": r"C:\Program Files\LegitApp\svc.exe",
    "state": "running",
    "start_type": "auto",
    "username": "LocalSystem",
}


def _make_items(**kwargs: list[Any]) -> dict[str, list[Any]]:
    return dict(kwargs)


def _mock_collector(name: str, items: list[Any], privilege: str = "user") -> MagicMock:
    health = CollectorHealth(
        collector_name=name,
        ran_successfully=True,
        privilege_level=privilege,  # type: ignore[arg-type]
        items_collected=len(items),
        duration_seconds=0.01,
    )
    inst = MagicMock()
    inst.run.return_value = (items, health)
    return inst


# ---------------------------------------------------------------------------
# RuleEngine — empty / structural
# ---------------------------------------------------------------------------


class TestRuleEngineEmpty:
    def test_no_rules_returns_empty(self) -> None:
        engine = RuleEngine([])
        result = engine.evaluate({}, _SCAN_ID)
        assert result == []

    def test_no_data_returns_empty(self) -> None:
        engine = RuleEngine([ServiceUserPathRule()])
        result = engine.evaluate({}, _SCAN_ID)
        assert result == []

    def test_empty_services_list_returns_empty(self) -> None:
        engine = RuleEngine([ServiceUserPathRule()])
        result = engine.evaluate({"services": []}, _SCAN_ID)
        assert result == []

    def test_returns_list_type(self) -> None:
        engine = RuleEngine([ServiceUserPathRule()])
        result = engine.evaluate({}, _SCAN_ID)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# RuleEngine — isolation / fail-closed
# ---------------------------------------------------------------------------


class TestRuleEngineIsolation:
    def test_crashing_rule_does_not_propagate(self) -> None:
        class BoomRule(BaseRule):
            def evaluate(self, items_by_collector, scan_id):
                raise RuntimeError("intentional crash")

        engine = RuleEngine([BoomRule()])
        result = engine.evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)
        assert result == []

    def test_crashing_rule_does_not_block_other_rules(self) -> None:
        class BoomRule(BaseRule):
            def evaluate(self, items_by_collector, scan_id):
                raise RuntimeError("intentional crash")

        engine = RuleEngine([BoomRule(), ServiceUserPathRule()])
        result = engine.evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)
        assert len(result) == 1

    def test_multiple_rules_results_are_merged(self) -> None:
        rule = ServiceUserPathRule()
        engine = RuleEngine([rule, rule])  # same rule twice → two findings
        result = engine.evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# ServiceUserPathRule — detection
# ---------------------------------------------------------------------------


class TestServiceUserPathRuleDetection:
    def _rule(self) -> ServiceUserPathRule:
        return ServiceUserPathRule()

    def test_fires_on_redacted_user_path(self) -> None:
        findings = self._rule().evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)
        assert len(findings) == 1

    def test_does_not_fire_on_program_files_path(self) -> None:
        findings = self._rule().evaluate({"services": [_SYSTEM_PATH_SVC]}, _SCAN_ID)
        assert findings == []

    def test_does_not_fire_on_windows_system32(self) -> None:
        svc = {**_SYSTEM_PATH_SVC, "binary_path": r"C:\Windows\System32\svchost.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert findings == []

    def test_does_not_fire_on_programdata(self) -> None:
        svc = {**_SYSTEM_PATH_SVC, "binary_path": r"C:\ProgramData\app\svc.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert findings == []

    # --- raw (unredacted) username paths ----------------------------------------

    def test_fires_on_raw_username_backslashes(self) -> None:
        svc = {**_USER_PATH_SVC, "binary_path": r"C:\Users\john\AppData\Local\evil.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert len(findings) == 1

    def test_fires_on_raw_username_forward_slashes(self) -> None:
        svc = {**_USER_PATH_SVC, "binary_path": "C:/Users/alice/AppData/evil.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert len(findings) == 1

    def test_fires_on_raw_username_mixed_slashes(self) -> None:
        svc = {**_USER_PATH_SVC, "binary_path": r"C:/Users\bob\evil.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert len(findings) == 1

    def test_fires_on_raw_username_case_insensitive_drive(self) -> None:
        svc = {**_USER_PATH_SVC, "binary_path": r"c:\Users\john\evil.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert len(findings) == 1

    def test_fires_with_forward_slashes(self) -> None:
        svc = {**_USER_PATH_SVC, "binary_path": "C:/Users/[REDACTED]/AppData/Local/evil.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert len(findings) == 1

    def test_fires_case_insensitive_drive(self) -> None:
        svc = {**_USER_PATH_SVC, "binary_path": r"c:\Users\[REDACTED]\evil.exe"}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert len(findings) == 1

    def test_no_fire_on_missing_binary_path(self) -> None:
        svc = {"name": "NoPath", "binary_path": None}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert findings == []

    def test_no_fire_on_empty_binary_path(self) -> None:
        svc = {"name": "EmptyPath", "binary_path": ""}
        findings = self._rule().evaluate({"services": [svc]}, _SCAN_ID)
        assert findings == []

    def test_no_services_key_returns_empty(self) -> None:
        findings = self._rule().evaluate({"installed_apps": []}, _SCAN_ID)
        assert findings == []

    def test_multiple_matching_services_all_flagged(self) -> None:
        svc2 = {**_USER_PATH_SVC, "name": "AnotherEvil"}
        findings = self._rule().evaluate(
            {"services": [_USER_PATH_SVC, svc2]}, _SCAN_ID
        )
        assert len(findings) == 2

    def test_mixed_services_only_matching_flagged(self) -> None:
        findings = self._rule().evaluate(
            {"services": [_USER_PATH_SVC, _SYSTEM_PATH_SVC]}, _SCAN_ID
        )
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# ServiceUserPathRule — finding shape
# ---------------------------------------------------------------------------


class TestServiceUserPathRuleFindingShape:
    def _finding(self) -> Finding:
        rule = ServiceUserPathRule()
        findings = rule.evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)
        return findings[0]

    def test_finding_rule_id(self) -> None:
        assert self._finding().id == RULE_ID

    def test_finding_rule_version(self) -> None:
        assert self._finding().rule_version == RULE_VERSION

    def test_finding_has_official_explanation(self) -> None:
        f = self._finding()
        assert f.official_explanation
        assert len(f.official_explanation) > 10

    def test_finding_has_in_other_words(self) -> None:
        f = self._finding()
        assert f.in_other_words
        assert len(f.in_other_words) > 10

    def test_finding_has_why_this_matters(self) -> None:
        assert self._finding().why_this_matters

    def test_finding_has_recommended_action(self) -> None:
        assert self._finding().recommended_action

    def test_finding_severity_medium(self) -> None:
        from cemi.models import Severity
        assert self._finding().severity == Severity.MEDIUM

    def test_finding_confidence_medium(self) -> None:
        from cemi.models import Confidence
        assert self._finding().confidence == Confidence.MEDIUM

    def test_finding_category_service(self) -> None:
        assert self._finding().category == "Service"

    def test_finding_requires_admin_to_verify(self) -> None:
        assert self._finding().requires_admin_to_verify is True

    def test_finding_app_matches_service_name(self) -> None:
        assert self._finding().app == "EvilPersist"

    def test_finding_scan_id_matches(self) -> None:
        assert self._finding().scan_id == _SCAN_ID

    def test_finding_instance_id_is_uuid(self) -> None:
        from uuid import UUID
        f = self._finding()
        assert isinstance(f.instance_id, UUID)

    def test_finding_instance_ids_unique_per_call(self) -> None:
        rule = ServiceUserPathRule()
        f1 = rule.evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)[0]
        f2 = rule.evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)[0]
        assert f1.instance_id != f2.instance_id


# ---------------------------------------------------------------------------
# ServiceUserPathRule — evidence privacy
# ---------------------------------------------------------------------------


class TestServiceUserPathRuleEvidence:
    def _finding(self) -> Finding:
        rule = ServiceUserPathRule()
        findings = rule.evaluate({"services": [_USER_PATH_SVC]}, _SCAN_ID)
        return findings[0]

    def test_finding_has_evidence(self) -> None:
        assert len(self._finding().evidence) >= 1

    def test_evidence_type_is_file_path(self) -> None:
        from cemi.models import EvidenceType
        assert self._finding().evidence[0].type == EvidenceType.FILE_PATH

    def test_evidence_value_contains_redacted_not_raw_username(self) -> None:
        value = self._finding().evidence[0].value
        assert "[REDACTED]" in value

    def test_evidence_value_does_not_contain_real_username(self) -> None:
        value = self._finding().evidence[0].value
        assert "batman" not in value.lower()
        assert "admin" not in value.lower() or "[REDACTED]" in value

    def test_evidence_label_describes_field(self) -> None:
        label = self._finding().evidence[0].label
        assert label  # non-empty string


# ---------------------------------------------------------------------------
# ServiceUserPathRule — evidence redaction for raw (unredacted) paths
# ---------------------------------------------------------------------------


class TestServiceUserPathRuleEvidenceRedaction:
    """Rule must redact evidence values even when given a raw (pre-redaction) path."""

    def _findings_for_path(self, binary_path: str) -> list[Finding]:
        rule = ServiceUserPathRule()
        svc = {**_USER_PATH_SVC, "binary_path": binary_path}
        return rule.evaluate({"services": [svc]}, _SCAN_ID)

    def test_raw_username_not_in_evidence(self) -> None:
        findings = self._findings_for_path(r"C:\Users\john\AppData\evil.exe")
        assert len(findings) == 1
        assert "john" not in findings[0].evidence[0].value

    def test_redacted_marker_present_for_raw_path(self) -> None:
        findings = self._findings_for_path(r"C:\Users\alice\AppData\evil.exe")
        assert "[REDACTED]" in findings[0].evidence[0].value

    def test_already_redacted_path_unchanged_in_evidence(self) -> None:
        findings = self._findings_for_path(r"C:\Users\[REDACTED]\AppData\evil.exe")
        assert "[REDACTED]" in findings[0].evidence[0].value

    def test_raw_forward_slash_username_not_in_evidence(self) -> None:
        findings = self._findings_for_path("C:/Users/charlie/AppData/evil.exe")
        assert "charlie" not in findings[0].evidence[0].value
        assert "[REDACTED]" in findings[0].evidence[0].value

    def test_evidence_path_prefix_preserved(self) -> None:
        findings = self._findings_for_path(r"C:\Users\john\AppData\evil.exe")
        value = findings[0].evidence[0].value
        assert value.startswith("C:")
        assert "Users" in value


# ---------------------------------------------------------------------------
# ScanEngine integration with rules
# ---------------------------------------------------------------------------


class TestScanEngineFindings:
    def test_scan_engine_populates_findings_from_rule(self) -> None:
        svc_col = _mock_collector("services", [_USER_PATH_SVC])
        result = ScanEngine([svc_col]).run_scan()
        assert len(result.findings) >= 1

    def test_scan_engine_no_findings_for_safe_service(self) -> None:
        svc_col = _mock_collector("services", [_SYSTEM_PATH_SVC])
        result = ScanEngine([svc_col]).run_scan()
        assert result.findings == []

    def test_scan_engine_findings_are_finding_instances(self) -> None:
        svc_col = _mock_collector("services", [_USER_PATH_SVC])
        result = ScanEngine([svc_col]).run_scan()
        for f in result.findings:
            assert isinstance(f, Finding)

    def test_scan_engine_no_raw_items_in_scan_result(self) -> None:
        svc_col = _mock_collector("services", [_USER_PATH_SVC])
        result = ScanEngine([svc_col]).run_scan()
        result_dict = result.model_dump()
        # Raw items must not appear anywhere in serialised output
        for value in result_dict.values():
            assert value != [_USER_PATH_SVC]

    def test_scan_engine_does_not_crash_on_rule_error(self) -> None:
        svc_col = _mock_collector("services", [_USER_PATH_SVC])
        # Patch rule engine to simulate crash
        import cemi.scan_engine as se
        original = se._build_rule_engine

        class CrashEngine:
            def evaluate(self, *_a, **_kw):
                raise RuntimeError("simulated rule engine crash")

        se._build_rule_engine = lambda: CrashEngine()
        try:
            result = ScanEngine([svc_col]).run_scan()
            assert result.findings == []
        finally:
            se._build_rule_engine = original

    def test_scan_engine_findings_carry_correct_scan_id(self) -> None:
        svc_col = _mock_collector("services", [_USER_PATH_SVC])
        result = ScanEngine([svc_col]).run_scan()
        for f in result.findings:
            assert f.scan_id == result.scan_id


# ===========================================================================
# NativeMessagingHostRule (NMH-001)
# ===========================================================================

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_NORMAL_HOST: dict[str, Any] = {
    "browser": "Chrome",
    "scope": "user",
    "name": "com.example.foo",
    "description": "Example native host",
    "manifest_path": r"C:\Users\[REDACTED]\AppData\Local\Google\Chrome\User Data\NativeMessagingHosts\com.example.foo.json",
    "binary_path": r"C:\Users\[REDACTED]\AppData\Local\foo.exe",
    "type": "stdio",
    "allowed_origins": ["chrome-extension://abcdefghijklmnopqrstuvwxyz/"],
}

_SYSTEM_HOST: dict[str, Any] = {
    **_NORMAL_HOST,
    "scope": "system",
    "manifest_path": r"C:\Program Files\Google\Chrome\Application\NativeMessagingHosts\com.example.foo.json",
    "binary_path": r"C:\Program Files\foo\host.exe",
}


def _nmh_col(hosts: list[dict[str, Any]]) -> MagicMock:
    return _mock_collector("native_messaging_hosts", hosts)


# ---------------------------------------------------------------------------
# NativeMessagingHostRule — basic firing
# ---------------------------------------------------------------------------


class TestNMHRuleBasicFiring:
    def _rule(self) -> NativeMessagingHostRule:
        return NativeMessagingHostRule()

    def test_no_finding_when_no_hosts(self) -> None:
        findings = self._rule().evaluate({}, _SCAN_ID)
        assert findings == []

    def test_no_finding_empty_host_list(self) -> None:
        findings = self._rule().evaluate({"native_messaging_hosts": []}, _SCAN_ID)
        assert findings == []

    def test_one_finding_for_one_host(self) -> None:
        findings = self._rule().evaluate({"native_messaging_hosts": [_NORMAL_HOST]}, _SCAN_ID)
        assert len(findings) == 1

    def test_two_findings_for_two_hosts(self) -> None:
        host2 = {**_NORMAL_HOST, "name": "com.example.bar"}
        findings = self._rule().evaluate(
            {"native_messaging_hosts": [_NORMAL_HOST, host2]}, _SCAN_ID
        )
        assert len(findings) == 2

    def test_no_finding_when_key_absent(self) -> None:
        findings = self._rule().evaluate({"services": []}, _SCAN_ID)
        assert findings == []

    def test_findings_are_finding_instances(self) -> None:
        findings = self._rule().evaluate({"native_messaging_hosts": [_NORMAL_HOST]}, _SCAN_ID)
        assert isinstance(findings[0], Finding)


# ---------------------------------------------------------------------------
# NativeMessagingHostRule — severity
# ---------------------------------------------------------------------------


class TestNMHRuleSeverity:
    def _rule(self) -> NativeMessagingHostRule:
        return NativeMessagingHostRule()

    def _finding(self, host: dict[str, Any]) -> Finding:
        return self._rule().evaluate({"native_messaging_hosts": [host]}, _SCAN_ID)[0]

    def test_medium_severity_for_normal_host(self) -> None:
        assert self._finding(_NORMAL_HOST).severity == Severity.MEDIUM

    def test_high_severity_when_binary_path_missing(self) -> None:
        host = {**_NORMAL_HOST, "binary_path": None}
        assert self._finding(host).severity == Severity.HIGH

    def test_high_severity_when_allowed_origins_empty(self) -> None:
        host = {**_NORMAL_HOST, "allowed_origins": []}
        assert self._finding(host).severity == Severity.HIGH

    def test_high_severity_when_allowed_origins_absent(self) -> None:
        host = {k: v for k, v in _NORMAL_HOST.items() if k != "allowed_origins"}
        assert self._finding(host).severity == Severity.HIGH

    def test_high_severity_when_type_not_stdio(self) -> None:
        host = {**_NORMAL_HOST, "type": "socket"}
        assert self._finding(host).severity == Severity.HIGH

    def test_high_severity_when_type_none(self) -> None:
        host = {**_NORMAL_HOST, "type": None}
        assert self._finding(host).severity == Severity.HIGH


# ---------------------------------------------------------------------------
# NativeMessagingHostRule — confidence
# ---------------------------------------------------------------------------


class TestNMHRuleConfidence:
    def _rule(self) -> NativeMessagingHostRule:
        return NativeMessagingHostRule()

    def _finding(self, host: dict[str, Any]) -> Finding:
        return self._rule().evaluate({"native_messaging_hosts": [host]}, _SCAN_ID)[0]

    def test_high_confidence_with_manifest_and_binary(self) -> None:
        assert self._finding(_NORMAL_HOST).confidence == Confidence.HIGH

    def test_medium_confidence_when_binary_missing(self) -> None:
        host = {**_NORMAL_HOST, "binary_path": None}
        assert self._finding(host).confidence == Confidence.MEDIUM

    def test_medium_confidence_when_manifest_missing(self) -> None:
        host = {**_NORMAL_HOST, "manifest_path": None}
        assert self._finding(host).confidence == Confidence.MEDIUM

    def test_medium_confidence_when_both_missing(self) -> None:
        host = {**_NORMAL_HOST, "manifest_path": None, "binary_path": None}
        assert self._finding(host).confidence == Confidence.MEDIUM


# ---------------------------------------------------------------------------
# NativeMessagingHostRule — finding shape
# ---------------------------------------------------------------------------


class TestNMHRuleFindingShape:
    def _finding(self) -> Finding:
        return NativeMessagingHostRule().evaluate(
            {"native_messaging_hosts": [_NORMAL_HOST]}, _SCAN_ID
        )[0]

    def test_rule_id(self) -> None:
        assert self._finding().id == NMH_RULE_ID

    def test_rule_version(self) -> None:
        assert self._finding().rule_version == NMH_RULE_VERSION

    def test_title(self) -> None:
        assert self._finding().title == "Browser Native Messaging Host Detected"

    def test_category(self) -> None:
        assert self._finding().category == "Browser Integration"

    def test_official_explanation_present(self) -> None:
        assert len(self._finding().official_explanation) > 10

    def test_in_other_words_present(self) -> None:
        assert len(self._finding().in_other_words) > 10

    def test_why_this_matters_present(self) -> None:
        assert self._finding().why_this_matters

    def test_recommended_action_present(self) -> None:
        assert self._finding().recommended_action

    def test_app_field_is_host_name(self) -> None:
        assert self._finding().app == "com.example.foo"

    def test_scan_id_matches(self) -> None:
        assert self._finding().scan_id == _SCAN_ID

    def test_instance_ids_unique(self) -> None:
        from uuid import UUID
        rule = NativeMessagingHostRule()
        f1 = rule.evaluate({"native_messaging_hosts": [_NORMAL_HOST]}, _SCAN_ID)[0]
        f2 = rule.evaluate({"native_messaging_hosts": [_NORMAL_HOST]}, _SCAN_ID)[0]
        assert f1.instance_id != f2.instance_id

    def test_requires_admin_false_for_user_scope(self) -> None:
        assert self._finding().requires_admin_to_verify is False

    def test_requires_admin_true_for_system_scope(self) -> None:
        f = NativeMessagingHostRule().evaluate(
            {"native_messaging_hosts": [_SYSTEM_HOST]}, _SCAN_ID
        )[0]
        assert f.requires_admin_to_verify is True


# ---------------------------------------------------------------------------
# NativeMessagingHostRule — evidence
# ---------------------------------------------------------------------------


class TestNMHRuleEvidence:
    def _finding(self, host: dict[str, Any] = _NORMAL_HOST) -> Finding:
        return NativeMessagingHostRule().evaluate(
            {"native_messaging_hosts": [host]}, _SCAN_ID
        )[0]

    def _evidence_by_label(self, host: dict[str, Any] = _NORMAL_HOST) -> dict[str, str]:
        return {item.label: item.value for item in self._finding(host).evidence}

    def test_evidence_is_not_empty(self) -> None:
        assert len(self._finding().evidence) >= 1

    def test_evidence_contains_browser(self) -> None:
        ev = self._evidence_by_label()
        assert "browser" in ev
        assert ev["browser"] == "Chrome"

    def test_evidence_contains_scope(self) -> None:
        ev = self._evidence_by_label()
        assert "scope" in ev
        assert ev["scope"] == "user"

    def test_evidence_contains_host_name(self) -> None:
        ev = self._evidence_by_label()
        assert "host name" in ev
        assert ev["host name"] == "com.example.foo"

    def test_evidence_contains_manifest_path(self) -> None:
        ev = self._evidence_by_label()
        assert "manifest path" in ev
        assert ev["manifest path"]

    def test_evidence_contains_binary_path_when_present(self) -> None:
        ev = self._evidence_by_label()
        assert "binary path" in ev

    def test_evidence_no_binary_path_when_absent(self) -> None:
        host = {**_NORMAL_HOST, "binary_path": None}
        ev = self._evidence_by_label(host)
        assert "binary path" not in ev

    def test_evidence_contains_allowed_origins_count(self) -> None:
        ev = self._evidence_by_label()
        assert "allowed origins count" in ev
        assert ev["allowed origins count"] == "1"

    def test_evidence_count_zero_when_origins_empty(self) -> None:
        host = {**_NORMAL_HOST, "allowed_origins": []}
        ev = self._evidence_by_label(host)
        assert ev["allowed origins count"] == "0"

    def test_allowed_origin_values_not_in_evidence(self) -> None:
        # Raw extension IDs must not appear in any evidence value.
        finding = self._finding()
        all_values = " ".join(item.value for item in finding.evidence)
        assert "chrome-extension://abcdefghijklmnopqrstuvwxyz/" not in all_values

    def test_manifest_path_uses_file_path_type(self) -> None:
        mp_items = [i for i in self._finding().evidence if i.label == "manifest path"]
        assert len(mp_items) == 1
        assert mp_items[0].type == EvidenceType.FILE_PATH

    def test_browser_uses_metadata_type(self) -> None:
        b_items = [i for i in self._finding().evidence if i.label == "browser"]
        assert b_items[0].type == EvidenceType.METADATA

    def test_manifest_path_redacted_when_user_path(self) -> None:
        host = {
            **_NORMAL_HOST,
            "manifest_path": r"C:\Users\alice\AppData\Local\Chrome\NativeMessagingHosts\host.json",
        }
        ev = self._evidence_by_label(host)
        assert "alice" not in ev["manifest path"]
        assert "[REDACTED]" in ev["manifest path"]

    def test_binary_path_redacted_when_user_path(self) -> None:
        # Collector already redacts, but rule applies redact_path() again (defence-in-depth).
        host = {**_NORMAL_HOST, "binary_path": r"C:\Users\alice\AppData\foo.exe"}
        ev = self._evidence_by_label(host)
        assert "alice" not in ev.get("binary path", "")
        assert "[REDACTED]" in ev.get("binary path", "")


# ---------------------------------------------------------------------------
# NativeMessagingHostRule — ScanEngine integration
# ---------------------------------------------------------------------------


class TestScanEngineNMHFindings:
    def test_scan_engine_populates_nmh_findings(self) -> None:
        nmh_col = _nmh_col([_NORMAL_HOST])
        result = ScanEngine([nmh_col]).run_scan()
        nmh_findings = [f for f in result.findings if f.id == NMH_RULE_ID]
        assert len(nmh_findings) == 1

    def test_scan_engine_two_hosts_two_findings(self) -> None:
        host2 = {**_NORMAL_HOST, "name": "com.example.bar"}
        nmh_col = _nmh_col([_NORMAL_HOST, host2])
        result = ScanEngine([nmh_col]).run_scan()
        nmh_findings = [f for f in result.findings if f.id == NMH_RULE_ID]
        assert len(nmh_findings) == 2

    def test_scan_engine_no_nmh_finding_when_no_hosts(self) -> None:
        nmh_col = _nmh_col([])
        result = ScanEngine([nmh_col]).run_scan()
        nmh_findings = [f for f in result.findings if f.id == NMH_RULE_ID]
        assert nmh_findings == []

    def test_scan_engine_findings_have_correct_scan_id(self) -> None:
        nmh_col = _nmh_col([_NORMAL_HOST])
        result = ScanEngine([nmh_col]).run_scan()
        for f in result.findings:
            assert f.scan_id == result.scan_id
