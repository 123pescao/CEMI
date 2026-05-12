"""Tests for cemi.utils.redact."""
from __future__ import annotations

import pytest

from cemi.models import EvidenceItem, EvidenceType
from cemi.utils.redact import (
    REDACTED,
    REDACTED_TOKEN,
    redact_evidence_item,
    redact_path,
    redact_string,
)


# --- redact_path --------------------------------------------------------------


class TestRedactPath:
    def test_normal_windows_path(self) -> None:
        assert (
            redact_path(r"C:\Users\john\Documents\file.txt")
            == r"C:\Users\[REDACTED]\Documents\file.txt"
        )

    def test_path_with_spaces_in_username(self) -> None:
        assert (
            redact_path(r"C:\Users\John Doe\Documents")
            == r"C:\Users\[REDACTED]\Documents"
        )

    def test_already_redacted_is_idempotent(self) -> None:
        original = r"C:\Users\[REDACTED]\Documents"
        assert redact_path(original) == original
        # Running twice must still be stable.
        assert redact_path(redact_path(original)) == original

    def test_unc_path(self) -> None:
        assert (
            redact_path(r"\\fileserver\share\Users\john\reports")
            == r"\\fileserver\share\Users\[REDACTED]\reports"
        )

    def test_mixed_slashes(self) -> None:
        assert (
            redact_path("C:/Users/john\\Documents")
            == "C:/Users/[REDACTED]\\Documents"
        )

    def test_forward_slashes_only(self) -> None:
        assert (
            redact_path("C:/Users/john/Documents")
            == "C:/Users/[REDACTED]/Documents"
        )

    def test_case_insensitive_users_keyword(self) -> None:
        # Input case is preserved, but username is redacted regardless of case.
        assert (
            redact_path(r"c:\users\john\documents")
            == r"c:\users\[REDACTED]\documents"
        )

    def test_path_without_users_segment_unchanged(self) -> None:
        assert redact_path(r"C:\Windows\System32") == r"C:\Windows\System32"

    def test_empty_string(self) -> None:
        assert redact_path("") == ""

    def test_function_does_not_mutate_input(self) -> None:
        # Python strings are immutable, but we assert behavioral contract:
        # the return value is not the same object identity-guaranteed but
        # the caller's variable is unchanged.
        original = r"C:\Users\alice\file"
        _ = redact_path(original)
        assert original == r"C:\Users\alice\file"


# --- redact_string ------------------------------------------------------------


class TestRedactString:
    def test_normal_string_unchanged(self) -> None:
        assert redact_string("hello world") == "hello world"

    def test_empty_string(self) -> None:
        assert redact_string("") == ""

    def test_sk_token_is_redacted(self) -> None:
        result = redact_string("my key is sk-ABCdef1234567890xyz please keep safe")
        assert "sk-ABCdef1234567890xyz" not in result
        assert REDACTED_TOKEN in result

    def test_ghp_token_is_redacted(self) -> None:
        result = redact_string("export GH=ghp_ABCdef1234567890QQQQ")
        assert "ghp_ABCdef1234567890QQQQ" not in result
        assert REDACTED_TOKEN in result

    def test_api_key_kv_pair_is_redacted(self) -> None:
        result = redact_string('api_key="super-secret-value-here"')
        assert "super-secret-value-here" not in result
        assert REDACTED_TOKEN in result

    def test_token_kv_pair_is_redacted(self) -> None:
        result = redact_string("token = abc12345deadbeef")
        assert "abc12345deadbeef" not in result
        assert REDACTED_TOKEN in result

    def test_prose_token_not_mangled(self) -> None:
        # The word "token" appearing in prose (no '=' or ':') should
        # NOT be redacted aggressively.
        s = "Your auth token is required for this operation"
        assert redact_string(s) == s

    def test_long_hex_string_redacted(self) -> None:
        sha256 = "a" * 64
        result = redact_string(f"sha256 = {sha256}")
        # Note: "sha256 =" is a kv pattern with "sha256" as the key — not
        # one we match — so only the hex itself is redacted.
        assert sha256 not in result
        assert REDACTED_TOKEN in result

    def test_short_hex_not_redacted(self) -> None:
        # 8 chars is common in version hashes and should pass through.
        assert redact_string("commit deadbeef done") == "commit deadbeef done"

    def test_base64_like_redacted(self) -> None:
        blob = "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbg=="
        result = redact_string(f"blob={blob}")
        assert blob not in result
        assert REDACTED_TOKEN in result

    def test_long_normal_word_not_redacted(self) -> None:
        word = "supercalifragilisticexpialidocious"
        assert redact_string(word) == word

    def test_password_kv_pair_is_redacted(self) -> None:
        result = redact_string("password=mysecretpassword123")
        assert "mysecretpassword123" not in result
        assert REDACTED_TOKEN in result

    def test_multiple_tokens_in_string(self) -> None:
        result = redact_string("sk-abc123456789 and ghp_ABCdef123456789 in one string")
        assert "sk-abc123456789" not in result
        assert "ghp_ABCdef123456789" not in result
        assert result.count(REDACTED_TOKEN) == 2

    def test_token_with_quotes_redacted(self) -> None:
        result = redact_string('token="sk-abc123456789"')
        assert "sk-abc123456789" not in result
        assert REDACTED_TOKEN in result

    def test_hex_in_url_redacted(self) -> None:
        url = "https://api.example.com/v1/keys/a1b2c3d4e5f678901234567890abcdef"
        result = redact_string(url)
        assert "a1b2c3d4e5f678901234567890abcdef" not in result
        assert REDACTED_TOKEN in result

    def test_base64_in_json_redacted(self) -> None:
        json_str = '{"data": "SGVsbG8gV29ybGQgVGhpcyBpcyBhIGxvbmdlciBzdHJpbmc="}'
        result = redact_string(json_str)
        assert "SGVsbG8gV29ybGQgVGhpcyBpcyBhIGxvbmdlciBzdHJpbmc=" not in result
        assert REDACTED_TOKEN in result

    def test_case_insensitive_token_detection(self) -> None:
        result = redact_string("API_KEY=SK-ABC123456789")
        assert "SK-ABC123456789" not in result
        assert REDACTED_TOKEN in result


# --- redact_evidence_item -----------------------------------------------------


class TestRedactEvidenceItem:
    def test_value_is_redacted(self) -> None:
        item = EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=r"C:\Users\alice\Documents\report.docx",
            label="install path",
        )
        redacted = redact_evidence_item(item)
        assert "alice" not in redacted.value
        assert REDACTED in redacted.value

    def test_original_not_modified(self) -> None:
        item = EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=r"C:\Users\alice\file.txt",
            label="file",
        )
        before = item.value
        _ = redact_evidence_item(item)
        assert item.value == before

    def test_returns_new_instance(self) -> None:
        item = EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=r"C:\Users\[REDACTED]\file.txt",
            label="file",
        )
        redacted = redact_evidence_item(item)
        # Even when no textual change is needed, a fresh instance is
        # returned — callers can rely on the return value alone.
        assert redacted is not item
        assert redacted == item

    def test_preserves_non_value_fields(self) -> None:
        item = EvidenceItem(
            type=EvidenceType.REGISTRY_KEY,
            value=r"HKCU\Software\Example\Users\bob\setting",
            label="startup entry",
        )
        redacted = redact_evidence_item(item)
        assert redacted.type == EvidenceType.REGISTRY_KEY
        assert redacted.label == "startup entry"
        assert "bob" not in redacted.value

    def test_redacts_embedded_token_inside_path(self) -> None:
        item = EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=r"C:\Users\alice\tokens\sk-ABCdef1234567890xyz.txt",
            label="file",
        )
        redacted = redact_evidence_item(item)
        assert "alice" not in redacted.value
        assert "sk-ABCdef1234567890xyz" not in redacted.value
