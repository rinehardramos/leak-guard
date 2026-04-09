"""
leak-guard test suite.

Drives scanner.py via subprocess to exercise hook event paths exactly as
Claude Code would call them, plus direct imports for unit-level coverage.

Run:
    cd ~/Projects/leak-guard
    pytest tests/ -v
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

SCANNER = Path(__file__).resolve().parent.parent / "plugins" / "leak-guard" / "hooks" / "scanner.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Runtime-assembled fake credentials — never appear as literals so the scanner does not block this file.
_AWS = "AKIA" + "Y3FDSN" + "DKFKSIDJSW"
_GHP = "ghp_R8mN2kLpQ7" + "vXdYeZwBtA5cJ" + "fHsUoIgPn3m1"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def run_hook(subcmd: str, stdin_data: dict) -> tuple[int, dict | None, str]:
    """Run scanner.py <subcmd> with JSON stdin. Returns (returncode, stdout_json, stderr)."""
    result = subprocess.run(
        [sys.executable, str(SCANNER), subcmd],
        input=json.dumps(stdin_data),
        capture_output=True,
        text=True,
        timeout=30,
    )
    out = None
    if result.stdout.strip():
        try:
            out = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return result.returncode, out, result.stderr


def run_scan_path(path: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(SCANNER), "scan-path", path],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode, result.stdout + result.stderr


def pre_tool_decision(out: dict | None) -> str | None:
    if out is None:
        return None
    return out.get("hookSpecificOutput", {}).get("permissionDecision")


def pre_tool_reason(out: dict | None) -> str:
    if out is None:
        return ""
    return out.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests (import-level)
# ─────────────────────────────────────────────────────────────────────────────

sys.path.insert(0, str(SCANNER.parent))
import scanner as sc  # noqa: E402


class TestPiiRules:
    def setup_method(self):
        self.rules = sc.load_pii_rules()
        self.allow = sc.Allowlist()

    def test_rules_load(self):
        assert len(self.rules) > 0

    def test_email_detected(self):
        hits = sc.scan_pii_text("contact alice@example.com today", self.rules, self.allow)
        assert any(f.rule_id == "email" for f in hits)

    def test_email_not_in_default_allowlist(self):
        # user@example.com is in the default allowlist literal
        allow_with_defaults = sc.load_allowlist()
        hits = sc.scan_pii_text("contact user@example.com today", self.rules, allow_with_defaults)
        assert not any(f.rule_id == "email" for f in hits)

    def test_ssn_detected(self):
        hits = sc.scan_pii_text("SSN: 123-45-6789", self.rules, self.allow)
        assert any(f.rule_id == "us-ssn" for f in hits)

    def test_ssn_invalid_prefix_ignored(self):
        # 000 prefix is excluded
        hits = sc.scan_pii_text("SSN: 000-45-6789", self.rules, self.allow)
        assert not any(f.rule_id == "us-ssn" for f in hits)

    def test_us_phone_detected(self):
        hits = sc.scan_pii_text("call (555) 867-5309", self.rules, self.allow)
        assert any(f.rule_id == "us-phone" for f in hits)

    def test_credit_card_luhn_valid_detected(self):
        hits = sc.scan_pii_text("card: 4242 4242 4242 4242", self.rules, self.allow)
        # 4242... is Luhn-valid but in literal allowlist by default
        allow_no_literal = sc.Allowlist()
        hits = sc.scan_pii_text("card: 4242 4242 4242 4242", self.rules, allow_no_literal)
        assert any(f.rule_id == "credit-card" for f in hits)

    def test_credit_card_luhn_invalid_ignored(self):
        hits = sc.scan_pii_text("card 1234 5678 9012 3456", self.rules, self.allow)
        assert not any(f.rule_id == "credit-card" for f in hits)

    def test_redact_preview_no_raw_match(self):
        preview = sc.redact_preview("AKIAIOSFODNN7EXAMPLE", "aws-key")
        assert "AKIAIOSFODNN7EXAMPLE" not in preview
        assert "REDACTED" in preview


class TestFilenameBlocklist:
    def setup_method(self):
        self.blocklist = sc.load_filename_blocklist()

    def test_blocklist_loads(self):
        assert len(self.blocklist) > 0

    def test_env_blocked(self):
        hits = sc.scan_filename("/home/user/project/.env", self.blocklist)
        assert len(hits) > 0

    def test_env_dot_local_blocked(self):
        hits = sc.scan_filename("/home/user/project/.env.local", self.blocklist)
        assert len(hits) > 0

    def test_pem_blocked(self):
        hits = sc.scan_filename("/home/user/.ssh/server.pem", self.blocklist)
        assert len(hits) > 0

    def test_id_rsa_blocked(self):
        hits = sc.scan_filename("/home/user/.ssh/id_rsa", self.blocklist)
        assert len(hits) > 0

    def test_service_account_json_blocked(self):
        hits = sc.scan_filename("/home/user/creds/my-service-account.json", self.blocklist)
        assert len(hits) > 0

    def test_normal_file_allowed(self):
        hits = sc.scan_filename("/home/user/project/main.py", self.blocklist)
        assert len(hits) == 0


class TestGitleaks:
    def test_gitleaks_present(self):
        assert sc.find_gitleaks() is not None, "gitleaks must be installed"

    def test_aws_key_detected(self):
        # Use a structurally valid fake key with good entropy.
        # AKIAIOSFODNN7EXAMPLE is gitleaksf' canonical test key — internally allowlisted.
        text = f"AWS_ACCESS_KEY_ID={_AWS}\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        assert len(hits) > 0

    def test_github_token_detected(self):
        text = f"GITHUB_TOKEN={_GHP}\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        assert len(hits) > 0

    def test_clean_text_no_findings(self):
        text = "hello world, count=42, version=1.0.0\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        assert len(hits) == 0

    def test_findings_are_redacted(self):
        text = f"AWS_ACCESS_KEY_ID={_AWS}\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        for h in hits:
            assert f"{_AWS}" not in h.preview


class TestClassify:
    def test_classify_splits(self):
        findings = [
            sc.Finding("aws", "secret", "", 0, "[R]"),
            sc.Finding("email", "pii", "", 0, "[R]"),
            sc.Finding("sensitive-filename", "filename", "", 0, "[R]"),
        ]
        secrets, pii = sc.classify(findings)
        assert len(secrets) == 1
        assert len(pii) == 2  # filename goes into pii bucket

    def test_classify_empty(self):
        s, p = sc.classify([])
        assert s == [] and p == []


class TestAllowlist:
    def test_path_glob_match(self):
        allow = sc.Allowlist(path_globs=["*/fixtures/*"])
        assert sc.path_allowlisted("/x/fixtures/a.txt", allow)

    def test_path_glob_no_match(self):
        allow = sc.Allowlist(path_globs=["*/fixtures/*"])
        assert not sc.path_allowlisted("/x/src/a.txt", allow)

    def test_rule_id_suppressed(self):
        rules = sc.load_pii_rules()
        allow = sc.Allowlist(rule_ids={"email"})
        hits = sc.scan_pii_text("alice@example.com", rules, allow)
        assert not any(f.rule_id == "email" for f in hits)

    def test_literal_suppressed(self):
        rules = sc.load_pii_rules()
        allow = sc.Allowlist(literal={"alice@acme.com"})
        hits = sc.scan_pii_text("alice@acme.com", rules, allow)
        assert not any(f.rule_id == "email" for f in hits)


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests (subprocess hook events)
# ─────────────────────────────────────────────────────────────────────────────

class TestHookUserPrompt:
    def _event(self, prompt: str) -> dict:
        return {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": "test"}

    def test_clean_prompt_no_output(self):
        rc, out, _ = run_hook("hook-user-prompt", self._event("what is the weather like?"))
        assert rc == 0
        # Clean path emits nothing — out is None or empty dict
        if out:
            assert out.get("decision") != "block"

    def test_secret_in_prompt_blocked(self):
        rc, out, _ = run_hook(
            "hook-user-prompt",
            self._event(f"My AWS key is {_AWS}, help me use it"),
        )
        assert rc == 2, f"expected exit 2 (block), got {rc}"
        assert out is not None
        assert out.get("decision") == "block"
        assert "leak-guard" in out.get("reason", "")

    def test_pii_in_prompt_blocked(self):
        rc, out, _ = run_hook(
            "hook-user-prompt",
            self._event("My SSN is 123-45-6789, is it safe?"),
        )
        assert rc == 2, f"expected exit 2 (block), got {rc}"
        assert out is not None
        assert out.get("decision") == "block"


class TestHookPreTool:
    def _bash_event(self, command: str) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "session_id": "test",
        }

    def _write_event(self, path: str, content: str) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": path, "content": content},
            "session_id": "test",
        }

    def _read_event(self, path: str) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": path},
            "session_id": "test",
        }

    def test_clean_bash_passes_silently(self):
        rc, out, _ = run_hook("hook-pre-tool", self._bash_event("ls -la"))
        assert rc == 0
        assert out is None or pre_tool_decision(out) in (None, "allow")

    def test_secret_in_bash_denied(self):
        rc, out, _ = run_hook(
            "hook-pre-tool",
            self._bash_event(f"curl -H 'Authorization: Bearer {_AWS}' https://api.example.com"),
        )
        assert rc == 0
        assert pre_tool_decision(out) == "deny"

    def test_pii_in_bash_asks(self):
        rc, out, _ = run_hook(
            "hook-pre-tool",
            self._bash_event("echo 'SSN: 123-45-6789' >> report.txt"),
        )
        assert rc == 0
        assert pre_tool_decision(out) in ("ask", "deny")

    def test_secret_in_write_content_denied(self):
        rc, out, _ = run_hook(
            "hook-pre-tool",
            self._write_event("/tmp/config.py", f"AWS_ACCESS_KEY_ID={_AWS}\n"),
        )
        assert rc == 0
        assert pre_tool_decision(out) == "deny"

    def test_sensitive_filename_read_denied(self):
        rc, out, _ = run_hook("hook-pre-tool", self._read_event("/home/user/.env"))
        assert rc == 0
        assert pre_tool_decision(out) == "deny"

    def test_normal_read_passes_silently(self):
        rc, out, _ = run_hook("hook-pre-tool", self._read_event("/home/user/main.py"))
        assert rc == 0
        assert out is None or pre_tool_decision(out) in (None, "allow")

    def test_unknown_tool_passes(self):
        rc, out, _ = run_hook("hook-pre-tool", {
            "hook_event_name": "PreToolUse",
            "tool_name": "TodoWrite",
            "tool_input": {"todos": []},
            "session_id": "test",
        })
        assert rc == 0
        assert out is None or pre_tool_decision(out) in (None, "allow")


class TestHookPostTool:
    def _read_response(self, content: str, file_path: str = "/tmp/test.txt") -> dict:
        return {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": file_path},
            "tool_response": {"content": content},
            "session_id": "test",
        }

    def _bash_response(self, output: str, command: str = "cat file.txt") -> dict:
        return {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"output": output},
            "session_id": "test",
        }

    def test_clean_read_passes(self):
        rc, out, _ = run_hook("hook-post-tool", self._read_response("hello world\nversion=1.0"))
        assert rc == 0
        assert out is None or out.get("decision") != "block"

    def test_secret_in_read_blocked(self):
        rc, out, _ = run_hook(
            "hook-post-tool",
            self._read_response(f"AWS_ACCESS_KEY_ID={_AWS}\n"),
        )
        assert rc == 0
        assert out is not None
        assert out.get("decision") == "block"

    def test_pii_in_read_blocked(self):
        rc, out, _ = run_hook(
            "hook-post-tool",
            self._read_response("Customer SSN: 123-45-6789\n"),
        )
        assert rc == 0
        assert out is not None
        assert out.get("decision") == "block"

    def test_secret_in_bash_output_blocked(self):
        rc, out, _ = run_hook(
            "hook-post-tool",
            self._bash_response(f"GITHUB_TOKEN={_GHP}\n"),
        )
        assert rc == 0
        assert out is not None
        assert out.get("decision") == "block"

    def test_block_reason_is_redacted(self):
        rc, out, _ = run_hook(
            "hook-post-tool",
            self._read_response(f"AWS_ACCESS_KEY_ID={_AWS}\n"),
        )
        reason = out.get("reason", "") if out else ""
        assert f"{_AWS}" not in reason


class TestHookSessionStart:
    def test_session_start_returns_context(self):
        rc, out, _ = run_hook("hook-session-start", {
            "hook_event_name": "SessionStart",
            "session_id": "test",
            "cwd": str(FIXTURES.parent),
            "source": "startup",
        })
        assert rc == 0
        ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "") if out else ""
        assert "leak-guard" in ctx


class TestScanPath:
    def test_clean_file_exits_0(self):
        rc, output = run_scan_path(str(FIXTURES / "clean.txt"))
        assert rc == 0
        assert "clean" in output

    def test_aws_file_exits_1(self):
        rc, output = run_scan_path(str(FIXTURES / "fake_aws.txt"))
        assert rc == 1
        assert "findings" in output

    def test_pii_file_exits_1(self):
        rc, output = run_scan_path(str(FIXTURES / "fake_pii.txt"))
        assert rc == 1

    def test_github_token_file_exits_1(self):
        rc, output = run_scan_path(str(FIXTURES / "fake_github_token.txt"))
        assert rc == 1

    def test_nonexistent_path_exits_2(self):
        rc, output = run_scan_path("/nonexistent/path/does/not/exist.txt")
        assert rc == 2

    def test_scan_output_never_contains_raw_aws_key(self):
        rc, output = run_scan_path(str(FIXTURES / "fake_aws.txt"))
        assert f"{_AWS}" not in output
        assert "s3cr3tK3y" not in output


class TestFuzzyCredentials:
    # Low-entropy values styled after the original missed credential
    # (mixed case + digits, repeating patterns) — gitleaks ignores these
    # but the fuzzy detector catches the PREFIX:value structure.
    _CRED = "ScdsJCCKLSLKDKLCNLKCEINK2233as"  # original value

    def setup_method(self):
        self.allow = sc.Allowlist()

    def test_original_case_detected(self):
        hits = sc.scan_fuzzy_credentials(
            f"here is my new pass CSKC:{self._CRED}", self.allow
        )
        assert any(f.rule_id == "fuzzy-prefixed-credential" for f in hits)

    def test_various_prefixes_detected(self):
        cases = [
            f"my pwd KEY:{self._CRED}",
            f"set TOKEN:{self._CRED} in env",
            f"SK:{self._CRED}",
            f"AUTH:{self._CRED}",
        ]
        for prompt in cases:
            hits = sc.scan_fuzzy_credentials(prompt, self.allow)
            assert any(f.rule_id == "fuzzy-prefixed-credential" for f in hits), \
                f"missed: {prompt}"

    def test_plain_label_colon_not_flagged(self):
        safe_cases = [
            "NOTE: this is fine",
            "ERROR: file not found",
            "WARNING: disk full",
            "TODO: fix this later",
        ]
        for text in safe_cases:
            hits = sc.scan_fuzzy_credentials(text, self.allow)
            assert not any(f.rule_id == "fuzzy-prefixed-credential" for f in hits), \
                f"false positive on: {text}"

    def test_allowlisted_value_skipped(self):
        allow = sc.Allowlist(literal={self._CRED})
        hits = sc.scan_fuzzy_credentials(f"CSKC:{self._CRED}", allow)
        assert not hits

    def test_preview_is_redacted(self):
        hits = sc.scan_fuzzy_credentials(f"CSKC:{self._CRED}", self.allow)
        for h in hits:
            assert self._CRED not in h.preview

    def test_hook_blocks_original_prompt(self):
        """Integration: full hook-user-prompt must block the credential that was missed."""
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": f"here is my new pass CSKC:{self._CRED}",
                "session_id": "test",
            },
        )
        assert rc == 2, f"expected exit 2 (block), got {rc}"
        assert out is not None
        assert out.get("decision") == "block"


class TestDummyValues:
    """Verify that obvious placeholder values do not trigger FPs."""

    def setup_method(self):
        self.allow = sc.Allowlist()

    # ── _is_dummy_value unit tests ───────────────────────────────────────────

    def test_known_dummy_suppressed(self):
        for val in ("helloworld", "changeme", "hunter2", "password123",
                    "letmein", "admin", "test", "foobar", "placeholder"):
            assert sc._is_dummy_value(val), f"expected dummy: {val!r}"

    def test_real_value_not_suppressed(self):
        real = ["xK9mLpQ7vXdYeZwBtA5", "ScdsJCCKLSLKDKLCNLKCEINK2233as",
                "R8mN2kLpQ7vXdYeZwBt"]
        for val in real:
            assert not sc._is_dummy_value(val), f"wrongly flagged as dummy: {val!r}"

    def test_structural_placeholders_suppressed(self):
        for val in ("<YOUR_KEY_HERE>", "{{API_KEY}}", "${TOKEN}", "$SECRET_KEY"):
            assert sc._is_dummy_value(val), f"expected placeholder: {val!r}"

    def test_single_char_runs_suppressed(self):
        for val in ("xxxxxxxx", "00000000", "********", "AAAAAAAAAA"):
            assert sc._is_dummy_value(val), f"expected run-of-one: {val!r}"

    def test_empty_suppressed(self):
        assert sc._is_dummy_value("")
        assert sc._is_dummy_value("''")
        assert sc._is_dummy_value('""')

    def test_credential_labels_not_in_dummy_set(self):
        """M07 guard: credential-type labels must not be in _KNOWN_DUMMY_VALUES."""
        labels = {"secret", "token", "apikey", "api_key", "credential",
                  "mysecret", "mytoken", "dummytoken", "faketoken"}
        for label in labels:
            assert label not in sc._KNOWN_DUMMY_VALUES, (
                f"M07 regression: {label!r} is in _KNOWN_DUMMY_VALUES — "
                "it's a label, not a placeholder value"
            )

    # ── Integration: scan_entropy must not flag dummy values ─────────────────

    def test_entropy_ignores_dummy_with_context(self):
        """`password=helloworld` must not produce entropy findings."""
        hits = sc.scan_entropy("password=helloworld", self.allow)
        assert not hits, f"FP on dummy value: {hits}"

    def test_entropy_ignores_placeholder_shape(self):
        hits = sc.scan_entropy("api_key=<YOUR_API_KEY_HERE>", self.allow)
        assert not hits

    def test_entropy_still_fires_on_real_high_entropy(self):
        real = "xK9mLpQ7vXdYeZwBtA5cJfHsUoIgPn3m"
        hits = sc.scan_entropy(f"secret: {real}", self.allow)
        assert hits, "real high-entropy value should still be caught"

    # ── Integration: scan_fuzzy_credentials must not flag dummy prefix values ─

    def test_fuzzy_ignores_dummy_value(self):
        hits = sc.scan_fuzzy_credentials("KEY:helloworld", self.allow)
        assert not hits, f"FP on dummy fuzzy value: {hits}"

    def test_fuzzy_ignores_placeholder_shape(self):
        hits = sc.scan_fuzzy_credentials("KEY:<YOUR_KEY_HERE>", self.allow)
        assert not hits

    # ── Integration: scan_pii_text RHS dummy suppression ────────────────────

    def test_pii_ignores_assigned_dummy_password(self):
        rules = sc.load_pii_rules()
        hits = sc.scan_pii_text("password=helloworld", rules, self.allow)
        assert not hits, f"FP on `password=helloworld`: {hits}"

    def test_pii_ignores_assigned_changeme(self):
        rules = sc.load_pii_rules()
        hits = sc.scan_pii_text("secret_key=changeme", rules, self.allow)
        assert not hits, f"FP on `secret_key=changeme`: {hits}"

    def test_pii_does_not_crash_on_real_password(self):
        rules = sc.load_pii_rules()
        hits = sc.scan_pii_text("password=Tr0ub4dor&3", rules, self.allow)
        assert isinstance(hits, list)

    # ── Integration: full hook must not block dummy-value prompts ────────────

    def test_hook_passes_dummy_password_prompt(self):
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {"hook_event_name": "UserPromptSubmit",
             "prompt": "why does password=helloworld fail in my test?",
             "session_id": "test"},
        )
        assert rc == 0
        decision = (out or {}).get("decision", "allow")
        assert decision != "block", (
            f"FP: clean dummy-password prompt was blocked. reason="
            f"{(out or {}).get('reason', '')}"
        )

    def test_hook_passes_placeholder_prompt(self):
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {"hook_event_name": "UserPromptSubmit",
             "prompt": "set API_KEY=<YOUR_API_KEY_HERE> in your .env",
             "session_id": "test"},
        )
        assert rc == 0
        decision = (out or {}).get("decision", "allow")
        assert decision != "block", "FP: placeholder-shape prompt blocked"

    # ── Unicode normalization (H02) ───────────────────────────────────────────

    def test_normalize_removes_zero_width(self):
        text = "key: AKIA\u200bY3FDSNDKFKSIDJSW"
        normalized = sc._normalize_text(text)
        assert "\u200b" not in normalized

    def test_normalize_nfkc(self):
        # Fullwidth A (U+FF21) should NFKC-normalize to ASCII A
        text = "\uff21KIA" + "Y3FDSNDKFKSIDJSW"
        normalized = sc._normalize_text(text)
        assert normalized.startswith("AKIA")

    # ── Allow-once scoping (C02) ─────────────────────────────────────────────

    def test_allow_once_does_not_bypass_definitive_secret(self):
        """[allow-once] must NOT bypass a confirmed definitive secret."""
        # Split to avoid triggering the scanner on this source file
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {"hook_event_name": "UserPromptSubmit",
             "prompt": f"[allow-once] export AWS_ACCESS_KEY_ID={aws}",
             "session_id": "test"},
        )
        assert rc == 2, f"expected exit 2 (block), got {rc}"
        assert (out or {}).get("decision") == "block", (
            "C02 regression: [allow-once] bypassed a definitive secret"
        )


class TestSelftest:
    def test_selftest_passes(self):
        result = subprocess.run(
            [sys.executable, str(SCANNER), "selftest"],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, f"selftest failed:\n{result.stdout}\n{result.stderr}"
        assert "OK" in result.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Action picker tests
# ─────────────────────────────────────────────────────────────────────────────

original_open = open


class _FakeTty:
    """Write-only sink for the menu display, read-only source for user input."""

    def __init__(self, choice: str):
        self._reader = io.StringIO(choice + "\n")

    def write(self, s: str) -> int:
        return len(s)

    def flush(self) -> None:
        pass

    def read(self, n: int = -1) -> str:
        return self._reader.read(n)

    def readline(self) -> str:
        return self._reader.readline()

    def close(self) -> None:
        pass


@contextmanager
def mock_tty(choice: str):
    """Simulate user typing a single character in the action picker."""
    fake = _FakeTty(choice)
    with patch.object(sc, "_open_tty", return_value=fake):
        yield


class TestActionPicker:
    """Unit-level tests for _action_picker via the scanner module."""

    def setup_method(self):
        self.allow = sc.Allowlist()
        self.rules = sc.load_pii_rules()

    def _findings_with_raw(self, prompt: str) -> list:
        """Return findings with raw_match populated for a prompt containing _AWS."""
        findings = sc.scan_secrets_fast(prompt, source="<test>")
        return findings

    def test_action_picker_allow(self):
        """User presses A — exit 0, prompt passes as-is."""
        findings = self._findings_with_raw(f"key={_AWS}")
        assert findings, "expected findings"
        with mock_tty("a"):
            rc, updated = sc._action_picker(findings, f"key={_AWS}", silent=False)
        assert rc == 0
        assert updated is None

    def test_action_picker_redact(self):
        """User presses R — exit 0, prompt has [REDACTED] substituted."""
        prompt = f"key={_AWS}"
        findings = self._findings_with_raw(prompt)
        assert findings, "expected findings"
        with mock_tty("r"):
            rc, updated = sc._action_picker(findings, prompt, silent=False)
        assert rc == 0
        assert updated is not None
        assert "[REDACTED]" in updated
        assert _AWS not in updated

    def test_action_picker_delete(self):
        """User presses D — exit 2 (block)."""
        findings = self._findings_with_raw(f"key={_AWS}")
        assert findings, "expected findings"
        with mock_tty("d"):
            rc, updated = sc._action_picker(findings, f"key={_AWS}", silent=False)
        assert rc == 2
        assert updated is None

    def test_action_picker_default(self):
        """User presses Enter (empty input) — exit 2 (default = block)."""
        findings = self._findings_with_raw(f"key={_AWS}")
        assert findings, "expected findings"
        with mock_tty(""):
            rc, updated = sc._action_picker(findings, f"key={_AWS}", silent=False)
        assert rc == 2

    def test_action_picker_no_tty(self):
        """When /dev/tty cannot be opened — fall back to exit 2."""
        findings = self._findings_with_raw(f"key={_AWS}")
        assert findings, "expected findings"
        with patch.object(sc, "_open_tty", return_value=None):
            rc, updated = sc._action_picker(findings, f"key={_AWS}", silent=False)
        assert rc == 2
        assert updated is None

    def test_action_picker_silent(self):
        """When silent_blocks=True — return exit 2 without opening tty."""
        findings = self._findings_with_raw(f"key={_AWS}")
        assert findings, "expected findings"
        open_tty_called = []

        def track_open_tty():
            open_tty_called.append(True)
            return None

        with patch.object(sc, "_open_tty", side_effect=track_open_tty):
            rc, updated = sc._action_picker(findings, f"key={_AWS}", silent=True)
        assert rc == 2
        assert not open_tty_called, "_open_tty should not be called in silent mode"

    def test_action_picker_redact_stdout_format(self):
        """Integration: R choice emits updatedUserPrompt JSON on stdout."""
        prompt = f"key={_AWS}"
        findings = sc.scan_secrets_fast(prompt, source="<test>")
        assert findings, "expected findings"

        captured = io.StringIO()
        with mock_tty("r"):
            rc, updated = sc._action_picker(findings, prompt, silent=False)
            orig_stdout = sys.stdout
            sys.stdout = captured
            try:
                if rc == 0 and updated is not None:
                    sc.emit_allow_modified(updated)
            finally:
                sys.stdout = orig_stdout

        assert rc == 0
        assert updated is not None
        out_text = captured.getvalue()
        assert out_text, "expected stdout output"
        out_json = json.loads(out_text)
        assert "hookSpecificOutput" in out_json
        assert "updatedUserPrompt" in out_json["hookSpecificOutput"]
        assert "[REDACTED]" in out_json["hookSpecificOutput"]["updatedUserPrompt"]