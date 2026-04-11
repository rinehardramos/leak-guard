"""Tests for proxy.py core redaction engine (Task 1)."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

PROXY_MODULE = Path(__file__).resolve().parent.parent / "plugins" / "leak-guard" / "hooks"
sys.path.insert(0, str(PROXY_MODULE))
import proxy as px
import scanner as sc


# ──────────────────────────────────────────────────────────────────────────
# TestUserTextExtraction
# ──────────────────────────────────────────────────────────────────────────

class TestUserTextExtraction:
    def test_plain_string_content(self):
        payload = {
            "messages": [
                {"role": "user", "content": "Hello world"},
            ]
        }
        assert px.get_last_user_text(payload) == "Hello world"

    def test_content_blocks_skips_system_reminders(self):
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "<system-reminder>ignore me</system-reminder>"},
                        {"type": "text", "text": "actual user text"},
                    ],
                }
            ]
        }
        assert px.get_last_user_text(payload) == "actual user text"

    def test_multiple_user_messages_returns_last(self):
        payload = {
            "messages": [
                {"role": "user", "content": "first message"},
                {"role": "assistant", "content": "reply"},
                {"role": "user", "content": "second message"},
            ]
        }
        assert px.get_last_user_text(payload) == "second message"

    def test_all_system_reminders_returns_none(self):
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "<system-reminder>block 1</system-reminder>"},
                        {"type": "text", "text": "<system-reminder>block 2</system-reminder>"},
                    ],
                }
            ]
        }
        assert px.get_last_user_text(payload) is None

    def test_empty_messages_list(self):
        payload = {"messages": []}
        assert px.get_last_user_text(payload) is None

    def test_no_messages_key(self):
        payload = {}
        assert px.get_last_user_text(payload) is None


# ──────────────────────────────────────────────────────────────────────────
# TestChoiceDetection
# ──────────────────────────────────────────────────────────────────────────

class TestChoiceDetection:
    def test_allow_keywords(self):
        for kw in ("a", "allow", "yes", "y"):
            assert px.is_allow_response(kw) == "allow", f"Expected 'allow' for {kw!r}"

    def test_redact_keywords(self):
        for kw in ("r", "redact", "no", "n"):
            assert px.is_allow_response(kw) == "redact", f"Expected 'redact' for {kw!r}"

    def test_case_insensitive(self):
        assert px.is_allow_response("YES") == "allow"
        assert px.is_allow_response("Allow") == "allow"
        assert px.is_allow_response("NO") == "redact"
        assert px.is_allow_response("REDACT") == "redact"

    def test_strips_whitespace(self):
        assert px.is_allow_response("  yes  ") == "allow"
        assert px.is_allow_response("\tn\t") == "redact"

    def test_long_text_returns_none(self):
        long_text = "a" * 51
        assert px.is_allow_response(long_text) is None

    def test_empty_returns_none(self):
        assert px.is_allow_response("") is None
        assert px.is_allow_response("   ") is None

    def test_unknown_short_returns_none(self):
        assert px.is_allow_response("maybe") is None
        assert px.is_allow_response("ok") is None


# ──────────────────────────────────────────────────────────────────────────
# TestProxyScanAndRedact
# ──────────────────────────────────────────────────────────────────────────

class TestProxyScanAndRedact:
    def _empty_allowlist(self) -> sc.Allowlist:
        return sc.Allowlist()

    def test_ssn_in_string_content(self):
        payload = {
            "messages": [
                {"role": "user", "content": "My SSN is 123-45-6789."},
            ]
        }
        modified, findings = px.scan_and_redact_payload(payload, self._empty_allowlist())
        assert findings, "Expected at least one finding for SSN"
        text = modified["messages"][0]["content"]
        assert "123-45-6789" not in text

    def test_ssn_in_content_blocks(self):
        # Use a well-formed SSN that passes the scanner's validity checks
        ssn = "456-78-9012"
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": f"SSN: {ssn}"},
                    ],
                }
            ]
        }
        modified, findings = px.scan_and_redact_payload(payload, self._empty_allowlist())
        assert findings, "Expected SSN finding in content blocks"
        text = modified["messages"][0]["content"][0]["text"]
        assert ssn not in text

    def test_system_reminder_not_scanned(self):
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "<system-reminder>SSN: 111-22-3333</system-reminder>"},
                        {"type": "text", "text": "clean text"},
                    ],
                }
            ]
        }
        modified, findings = px.scan_and_redact_payload(payload, self._empty_allowlist())
        # The system-reminder block should be untouched
        reminder_block = modified["messages"][0]["content"][0]["text"]
        assert "111-22-3333" in reminder_block
        # No findings because only the system-reminder had the SSN
        assert not findings

    def test_clean_payload_no_findings(self):
        payload = {
            "messages": [
                {"role": "user", "content": "Hello, how are you?"},
            ]
        }
        modified, findings = px.scan_and_redact_payload(payload, self._empty_allowlist())
        assert findings == []
        assert modified["messages"][0]["content"] == "Hello, how are you?"

    def test_allowlisted_value_not_redacted(self):
        payload = {
            "messages": [
                {"role": "user", "content": "My SSN is 123-45-6789."},
            ]
        }
        allowlist = sc.Allowlist()
        allowlist.literal = {"123-45-6789"}
        modified, findings = px.scan_and_redact_payload(payload, allowlist)
        # The allowlisted value should NOT be in findings and NOT be redacted
        assert not any(f["raw"] == "123-45-6789" for f in findings)
        assert "123-45-6789" in modified["messages"][0]["content"]

    def test_assistant_messages_not_scanned(self):
        payload = {
            "messages": [
                {"role": "assistant", "content": "SSN: 555-44-3333"},
                {"role": "user", "content": "OK thanks"},
            ]
        }
        modified, findings = px.scan_and_redact_payload(payload, self._empty_allowlist())
        # Assistant message should be untouched regardless
        assert "555-44-3333" in modified["messages"][0]["content"]
        assert not findings


# ──────────────────────────────────────────────────────────────────────────
# TestSystemNoteInjection
# ──────────────────────────────────────────────────────────────────────────

class TestSystemNoteInjection:
    def _sample_findings(self) -> list[dict]:
        return [
            {
                "type": "pii",
                "raw": "123-45-6789",
                "tag": "[REDACTED:us-ssn]",
                "rule_id": "us-ssn",
                "confidence": 0.95,
            }
        ]

    def test_string_system_field(self):
        payload = {"system": "You are helpful.", "messages": []}
        findings = self._sample_findings()
        result = px.inject_system_note_with_question(payload, findings)
        assert result["system"].startswith("You are helpful.")
        assert "[leak-guard]" in result["system"]

    def test_list_system_field(self):
        payload = {
            "system": [{"type": "text", "text": "You are helpful."}],
            "messages": [],
        }
        findings = self._sample_findings()
        result = px.inject_system_note_with_question(payload, findings)
        assert isinstance(result["system"], list)
        last_block = result["system"][-1]
        assert last_block["type"] == "text"
        assert "[leak-guard]" in last_block["text"]

    def test_no_system_field(self):
        payload = {"messages": []}
        findings = self._sample_findings()
        result = px.inject_system_note_with_question(payload, findings)
        assert "[leak-guard]" in result["system"]

    def test_allow_confirmation(self):
        payload = {"messages": []}
        result = px.inject_allow_confirmation(payload, ["[REDACTED:us-ssn]"])
        assert "Allowlisted" in result["system"]
        assert "[REDACTED:us-ssn]" in result["system"]

    def test_redact_confirmation(self):
        payload = {"messages": []}
        result = px.inject_redact_confirmation(payload)
        assert "redact" in result["system"].lower() or "redacted" in result["system"].lower()

    def test_raw_values_not_in_note(self):
        """The system note must never include raw (un-redacted) values."""
        payload = {"messages": []}
        findings = self._sample_findings()
        result = px.inject_system_note_with_question(payload, findings)
        system_text = (
            result["system"]
            if isinstance(result["system"], str)
            else " ".join(b.get("text", "") for b in result["system"] if isinstance(b, dict))
        )
        # The raw SSN must not appear in the note
        assert "123-45-6789" not in system_text


# ──────────────────────────────────────────────────────────────────────────
# TestPendingState
# ──────────────────────────────────────────────────────────────────────────

class TestPendingState:
    def _sample_findings(self) -> list[dict]:
        return [
            {
                "type": "pii",
                "raw": "123-45-6789",
                "tag": "[REDACTED:us-ssn]",
                "rule_id": "us-ssn",
                "confidence": 0.95,
            }
        ]

    def test_write_and_read(self):
        findings = self._sample_findings()
        px.write_pending(findings)
        result = px.read_and_clear_pending()
        assert result == findings

    def test_read_clears_file(self):
        px.write_pending(self._sample_findings())
        px.read_and_clear_pending()
        # File should be gone
        assert not px.PENDING_FILE.exists()

    def test_expired_returns_none(self):
        findings = self._sample_findings()
        # Write with an old timestamp
        sc.ensure_state_dir()
        record = {"ts": time.time() - (px._PENDING_TTL + 10), "findings": findings}
        px.PENDING_FILE.write_text(json.dumps(record), encoding="utf-8")
        px.PENDING_FILE.chmod(0o600)
        result = px.read_and_clear_pending()
        assert result is None

    def test_missing_returns_none(self):
        # Ensure file does not exist
        if px.PENDING_FILE.exists():
            px.PENDING_FILE.unlink()
        result = px.read_and_clear_pending()
        assert result is None
