"""Tests for proxy.py core redaction engine (Task 1) and HTTP server (Task 2)."""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest

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


# ──────────────────────────────────────────────────────────────────────────
# Helpers for Task 2 tests
# ──────────────────────────────────────────────────────────────────────────

def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def proxy_server(tmp_path, monkeypatch):
    """Start a proxy server on a random port for testing."""
    port = _find_free_port()
    monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")
    monkeypatch.setattr(px, "STATE_DIR", tmp_path)
    server = px.ThreadedHTTPServer(("127.0.0.1", port), px.ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port, server
    server.shutdown()


# ──────────────────────────────────────────────────────────────────────────
# TestHealthEndpoint
# ──────────────────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_status_ok(self, proxy_server):
        port, _ = proxy_server
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/lg-status")
        data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert "allowlist_size" in data
        assert "requests_redacted" in data

    def test_allowlist_size_is_int(self, proxy_server):
        port, _ = proxy_server
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/lg-status")
        data = json.loads(resp.read())
        assert isinstance(data["allowlist_size"], int)
        assert data["allowlist_size"] >= 0

    def test_requests_redacted_is_int(self, proxy_server):
        port, _ = proxy_server
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/lg-status")
        data = json.loads(resp.read())
        assert isinstance(data["requests_redacted"], int)
        assert data["requests_redacted"] >= 0


# ──────────────────────────────────────────────────────────────────────────
# TestProxyAllowlist
# ──────────────────────────────────────────────────────────────────────────

class TestProxyAllowlist:
    """Allow choice persists to allowlist, subsequent requests skip allowed values."""

    def test_allow_updates_allowlist(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")
        monkeypatch.setattr(px, "STATE_DIR", tmp_path)
        monkeypatch.setattr(sc, "USER_ALLOWLIST", tmp_path / "allowlist.toml")

        # Turn 1: write pending with a test SSN-like value
        ssn_value = "456-78-9012"
        findings = [
            {
                "type": "us-ssn",
                "raw": ssn_value,
                "tag": "[REDACTED:us-ssn]",
                "rule_id": "us-ssn",
                "confidence": 0.90,
            }
        ]
        px.write_pending(findings)

        # Turn 2: user says "a" (allow)
        pending = px.read_and_clear_pending()
        assert pending is not None
        choice = px.is_allow_response("a")
        assert choice == "allow"
        for f in pending:
            sc._append_literal(f["raw"], "test allow")

        # Verify allowlist contains the raw value
        al = sc.load_allowlist()
        assert ssn_value in al.literal

        # Turn 3: same value should not be redacted
        payload = {
            "messages": [
                {"role": "user", "content": f"My SSN is {ssn_value}"},
            ]
        }
        result, new_findings = px.scan_and_redact_payload(payload, al)
        assert len(new_findings) == 0
        assert ssn_value in result["messages"][0]["content"]

    def test_redact_choice_clears_pending(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")
        monkeypatch.setattr(px, "STATE_DIR", tmp_path)

        findings = [
            {
                "type": "us-ssn",
                "raw": "456-78-9012",
                "tag": "[REDACTED:us-ssn]",
                "rule_id": "us-ssn",
                "confidence": 0.90,
            }
        ]
        px.write_pending(findings)

        # Simulate Turn 2: user says "r"
        pending = px.read_and_clear_pending()
        assert pending is not None
        choice = px.is_allow_response("r")
        assert choice == "redact"

        # Pending file should now be gone
        assert not (tmp_path / "pending.json").exists()

    def test_none_choice_does_not_consume_pending(self, tmp_path, monkeypatch):
        """When user sends unrecognised text, pending should still be re-writable."""
        monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")
        monkeypatch.setattr(px, "STATE_DIR", tmp_path)

        findings = [
            {
                "type": "us-ssn",
                "raw": "456-78-9012",
                "tag": "[REDACTED:us-ssn]",
                "rule_id": "us-ssn",
                "confidence": 0.90,
            }
        ]
        px.write_pending(findings)

        # is_allow_response returns None for unrecognised text
        choice = px.is_allow_response("what does that mean?")
        assert choice is None


# ──────────────────────────────────────────────────────────────────────────
# TestThreadedHTTPServer
# ──────────────────────────────────────────────────────────────────────────

class TestThreadedHTTPServer:
    def test_server_starts_and_responds(self, proxy_server):
        port, _ = proxy_server
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/lg-status")
        assert resp.status == 200

    def test_server_handles_concurrent_requests(self, proxy_server):
        port, _ = proxy_server
        results = []

        def fetch():
            try:
                resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/lg-status")
                results.append(resp.status)
            except Exception as e:
                results.append(str(e))

        threads = [threading.Thread(target=fetch) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(results) == 5
        assert all(r == 200 for r in results), f"Unexpected results: {results}"


# ──────────────────────────────────────────────────────────────────────────
# TestProxyLifecycle
# ──────────────────────────────────────────────────────────────────────────

class TestProxyLifecycle:
    def test_write_pid_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PID_FILE", tmp_path / "proxy.pid")
        monkeypatch.setattr(px, "STATE_DIR", tmp_path)
        px._write_pid(12345)
        assert (tmp_path / "proxy.pid").exists()
        assert (tmp_path / "proxy.pid").read_text().strip() == "12345"

    def test_read_pid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PID_FILE", tmp_path / "proxy.pid")
        (tmp_path / "proxy.pid").write_text("12345")
        assert px._read_pid() == 12345

    def test_read_pid_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PID_FILE", tmp_path / "proxy.pid")
        assert px._read_pid() is None

    def test_is_proxy_running_false_when_no_pid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PID_FILE", tmp_path / "proxy.pid")
        monkeypatch.setattr(px, "LISTEN_PORT", 19999)  # unused port for fallback check
        assert px.is_proxy_running() is False

    def test_cleanup_pid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PID_FILE", tmp_path / "proxy.pid")
        monkeypatch.setattr(px, "STATE_DIR", tmp_path)
        px._write_pid(99999)
        px._cleanup_pid()
        assert not (tmp_path / "proxy.pid").exists()


class TestGeminiPayloadScan:
    """Tests for Gemini-format (contents/parts) payload scanning."""

    def _gemini_payload(self, user_text, role="user"):
        return {
            "contents": [
                {"role": role, "parts": [{"text": user_text}]}
            ],
            "generationConfig": {"temperature": 0.7},
        }

    def _multi_turn(self, *texts):
        contents = []
        for i, text in enumerate(texts):
            role = "user" if i % 2 == 0 else "model"
            contents.append({"role": role, "parts": [{"text": text}]})
        return {"contents": contents}

    def test_aws_key_redacted_in_gemini_payload(self):
        key = "AKIA" + "Y3FDSNDK" + "FKSIDJSW"
        payload = self._gemini_payload(f"my key is {key}")
        redacted, findings = px.scan_and_redact_gemini_payload(payload, sc.Allowlist())
        assert key not in json.dumps(redacted)
        assert len(findings) > 0

    def test_clean_gemini_payload_passes_through(self):
        payload = self._gemini_payload("Hello, how are you?")
        redacted, findings = px.scan_and_redact_gemini_payload(payload, sc.Allowlist())
        assert findings == []
        assert redacted["contents"][0]["parts"][0]["text"] == "Hello, how are you?"

    def test_multi_turn_user_turns_scanned(self):
        key = "AKIA" + "Y3FDSNDK" + "FKSIDJSW"
        payload = self._multi_turn(
            f"store this key: {key}",
            "Sure, I stored it.",
            "Thanks, now use it.",
        )
        redacted, findings = px.scan_and_redact_gemini_payload(payload, sc.Allowlist())
        # User turn 0 had the key — should be redacted
        assert key not in json.dumps(redacted)
        assert len(findings) > 0
        # Model turn should be untouched
        assert redacted["contents"][1]["parts"][0]["text"] == "Sure, I stored it."

    def test_system_instruction_scanned(self):
        ssn = "078-05-1120"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
            "systemInstruction": {"parts": [{"text": f"SSN is {ssn}"}]},
        }
        redacted, findings = px.scan_and_redact_gemini_payload(payload, sc.Allowlist())
        assert ssn not in json.dumps(redacted)
        assert len(findings) > 0

    def test_model_turns_not_scanned(self):
        key = "AKIA" + "Y3FDSNDK" + "FKSIDJSW"
        payload = self._gemini_payload(key, role="model")
        redacted, findings = px.scan_and_redact_gemini_payload(payload, sc.Allowlist())
        # Model messages are not scanned
        assert findings == []
        assert redacted["contents"][0]["parts"][0]["text"] == key

    def test_empty_contents_no_crash(self):
        payload = {"contents": [], "generationConfig": {}}
        redacted, findings = px.scan_and_redact_gemini_payload(payload, sc.Allowlist())
        assert findings == []

    def test_non_text_parts_ignored(self):
        payload = {
            "contents": [
                {"role": "user", "parts": [
                    {"inlineData": {"mimeType": "image/png", "data": "base64..."}},
                    {"text": "describe this image"},
                ]}
            ]
        }
        redacted, findings = px.scan_and_redact_gemini_payload(payload, sc.Allowlist())
        assert findings == []
        assert redacted["contents"][0]["parts"][1]["text"] == "describe this image"
