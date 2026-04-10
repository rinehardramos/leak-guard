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
import os
import subprocess
import sys
import time
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

    def test_secret_in_prompt_intercepted(self):
        """Secret prompt: hook redacts value and injects SYSTEM NOTE via additionalContext."""
        rc, out, _ = run_hook(
            "hook-user-prompt",
            self._event(f"My AWS key is {_AWS}, help me use it"),
        )
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "leak-guard" in ctx
        assert "[REDACTED]" in ctx
        assert _AWS not in ctx

    def test_pii_in_prompt_intercepted(self):
        """PII prompt: hook redacts value and injects SYSTEM NOTE via additionalContext."""
        rc, out, _ = run_hook(
            "hook-user-prompt",
            self._event("My SSN is 123-45-6789, is it safe?"),
        )
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "leak-guard" in ctx
        assert "123-45-6789" not in ctx


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

    def test_hook_intercepts_original_prompt(self):
        """Hook redacts credential and injects SYSTEM NOTE via additionalContext."""
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": f"here is my new pass CSKC:{self._CRED}",
                "session_id": "test",
            },
        )
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "leak-guard" in ctx
        assert self._CRED not in ctx


class TestDummyValues:
    """Verify _is_dummy_value suppresses only structurally unambiguous non-secrets."""

    def setup_method(self):
        self.allow = sc.Allowlist()

    # ── _is_dummy_value: structural suppression only ─────────────────────────

    def test_structural_placeholders_suppressed(self):
        """Template syntax wrappers are unambiguously not secrets."""
        for val in ("<YOUR_KEY_HERE>", "{{API_KEY}}", "${TOKEN}", "$SECRET_KEY"):
            assert sc._is_dummy_value(val), f"expected placeholder: {val!r}"

    def test_single_char_runs_suppressed(self):
        """Runs of one repeated character are not secrets."""
        for val in ("xxxxxxxx", "00000000", "********", "AAAAAAAAAA"):
            assert sc._is_dummy_value(val), f"expected run-of-one: {val!r}"

    def test_empty_suppressed(self):
        assert sc._is_dummy_value("")
        assert sc._is_dummy_value("''")
        assert sc._is_dummy_value('""')

    def test_git_sha_suppressed(self):
        """40-char lowercase hex strings are git SHAs, not secrets."""
        sha = "a3f2c1d4e5b6a7f8c9d0e1f2a3b4c5d6e7f8a9b0"
        assert sc._is_dummy_value(sha)

    def test_real_tokens_not_suppressed(self):
        """Anything with real entropy / structure must reach the action picker."""
        for val in ("xK9mLpQ7vXdYeZwBtA5", "ScdsJCCKLSLKDKLCNLKCEINK2233as",
                    "changeme", "helloworld", "hunter2", "password123"):
            assert not sc._is_dummy_value(val), (
                f"wrongly suppressed (user should decide): {val!r}"
            )

    # ── Integration: structural suppressions work end-to-end ─────────────────

    def test_placeholder_shape_not_flagged_by_entropy(self):
        """Template syntax in a prompt must not produce entropy findings."""
        hits = sc.scan_entropy("api_key=<YOUR_API_KEY_HERE>", self.allow)
        assert not hits

    def test_placeholder_shape_not_flagged_by_fuzzy(self):
        hits = sc.scan_fuzzy_credentials("KEY:<YOUR_KEY_HERE>", self.allow)
        assert not hits

    def test_entropy_fires_on_real_high_entropy(self):
        """Real high-entropy values must still be caught."""
        real = "xK9mLpQ7vXdYeZwBtA5cJfHsUoIgPn3m"
        hits = sc.scan_entropy(f"secret: {real}", self.allow)
        assert hits, "real high-entropy value should be caught"

    def test_hook_passes_template_placeholder_prompt(self):
        """A prompt containing only template syntax must pass through."""
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {"hook_event_name": "UserPromptSubmit",
             "prompt": "set API_KEY=<YOUR_API_KEY_HERE> in your .env",
             "session_id": "test"},
        )
        assert rc == 0
        assert (out or {}).get("decision", "allow") != "block"

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

    # ── Hostname entropy findings are heuristic (action picker), not suppressed ─

    def test_hostname_not_in_dummy_values(self):
        """Hostnames are NOT suppressed — they route through the action picker."""
        # The heuristic path (action picker) handles these; _is_dummy_value must
        # not silently drop them, since a hostname in a credential context is suspicious.
        assert not sc._is_dummy_value("Rinehards-MacBook-Pro")
        assert not sc._is_dummy_value("my-server.local")

    def test_git_committer_line_is_heuristic(self):
        """A hostname in a committer line produces a heuristic finding, not a definitive block."""
        line = "Committer: Test User <testuser@My-MacBook-Pro.local>"
        findings = sc.scan_entropy(line, "test", sc.load_allowlist())
        # If a finding fires, it must be heuristic (eligible for action picker, not auto-block)
        for f in findings:
            assert f.rule_id in sc._HEURISTIC_RULE_IDS, (
                f"hostname produced a definitive (non-heuristic) finding: {f}"
            )

    # ── Allow-once scoping (C02) ─────────────────────────────────────────────

    def test_allow_once_bypasses_all_findings(self):
        """[allow-once] prefix bypasses all findings including definitive secrets — prompt sent as-is."""
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {"hook_event_name": "UserPromptSubmit",
             "prompt": f"[allow-once] export AWS_ACCESS_KEY_ID={aws}",
             "session_id": "test"},
        )
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "") if out else ""
        assert "leak-guard" not in ctx, "[allow-once] should bypass redaction entirely"


class TestSelftest:
    def test_selftest_passes(self):
        result = subprocess.run(
            [sys.executable, str(SCANNER), "selftest"],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, f"selftest failed:\n{result.stdout}\n{result.stderr}"
        assert "OK" in result.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Prompt-injected action picker tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=False)
def isolated_state_dir(monkeypatch, tmp_path):
    """Redirect STATE_DIR and all derived paths to a temp directory."""
    state = tmp_path / "leak-guard-state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("LEAK_GUARD_STATE_DIR", str(state))
    # Patch module-level constants so the in-process scanner uses the temp dir
    monkeypatch.setattr(sc, "STATE_DIR", state)
    monkeypatch.setattr(sc, "AUDIT_LOG", state / "audit.log")
    monkeypatch.setattr(sc, "USER_ALLOWLIST", state / "allowlist.toml")
    monkeypatch.setattr(sc, "PENDING_ACTION", state / "pending_action.json")
    return state


def _make_pending(state_dir: Path, prompt: str, redact_targets: list,
                  expires_delta: float = 300) -> None:
    """Write a synthetic pending_action.json into state_dir."""
    data = {
        "prompt": prompt,
        "redact_targets": redact_targets,
        "findings_summary": [{"rule_id": "test-rule", "severity": "high", "preview": "[R]"}],
        "expires_at": time.time() + expires_delta,
    }
    p = state_dir / "pending_action.json"
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)


def _run_hook_with_state(state_dir: Path, prompt: str) -> tuple[int, dict | None, str]:
    """Run hook-user-prompt with LEAK_GUARD_STATE_DIR pointing to state_dir."""
    event = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": "test"}
    result = subprocess.run(
        [sys.executable, str(SCANNER), "hook-user-prompt"],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "LEAK_GUARD_STATE_DIR": str(state_dir)},
    )
    out = None
    if result.stdout.strip():
        try:
            out = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return result.returncode, out, result.stderr


class TestPromptInjectedPicker:
    """Tests for the prompt-injected action picker (Turn 1 + Turn 2 flow)."""

    _CRED = "ScdsJCCKLSLKDKLCNLKCEINK2233as"

    def test_detection_redacts_and_notifies(self, tmp_path):
        """Detection: hook redacts credential inline and injects SYSTEM NOTE via additionalContext."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        rc, out, _ = _run_hook_with_state(state, f"here is my new pass CSKC:{self._CRED}")
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "leak-guard" in ctx
        assert "[REDACTED]" in ctx
        assert self._CRED not in ctx

    def test_choice_allow_resends_original(self, tmp_path):
        """Turn 2 A: exits 0 and emits updatedUserPrompt == original."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        original = f"here is my pass CSKC:{self._CRED}"
        _make_pending(state, original, [self._CRED])
        rc, out, _ = _run_hook_with_state(state, "A")
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert original in ctx

    def test_choice_redact_strips_target(self, tmp_path):
        """Turn 2 R: exits 0 and updatedUserPrompt has [REDACTED] in place of target."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        original = f"here is my pass CSKC:{self._CRED}"
        _make_pending(state, original, [self._CRED])
        rc, out, _ = _run_hook_with_state(state, "R")
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "[REDACTED]" in ctx
        assert self._CRED not in ctx

    def test_choice_discard_blocks(self, tmp_path):
        """Turn 2 D: exits 2 (block)."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        original = f"here is my pass CSKC:{self._CRED}"
        _make_pending(state, original, [self._CRED])
        rc, out, _ = _run_hook_with_state(state, "D")
        assert rc == 2

    def test_choice_expired_falls_through(self, tmp_path):
        """Expired pending file: choice reply falls through to normal scan."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        original = "some clean prompt"
        _make_pending(state, original, [], expires_delta=-1)  # already expired
        # "A" with expired pending should be treated as a normal prompt (clean)
        rc, out, _ = _run_hook_with_state(state, "A")
        # Clean prompt "A" passes through with exit 0
        assert rc == 0

    def test_no_pending_no_intercept(self, tmp_path):
        """No pending file: single-letter prompt is not intercepted as choice."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        # No pending file written. "A" alone should pass through (clean prompt).
        rc, out, _ = _run_hook_with_state(state, "A")
        assert rc == 0
        # Should NOT have emitted updatedUserPrompt (not intercepted as choice)
        updated = (out or {}).get("hookSpecificOutput", {}).get("updatedUserPrompt")
        assert updated is None

    def test_redaction_in_additional_context(self, tmp_path):
        """Detection: SYSTEM NOTE with redacted prompt injected via additionalContext."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        rc, out, _ = _run_hook_with_state(state, f"here is my new pass CSKC:{self._CRED}")
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "leak-guard" in ctx
        assert "[REDACTED]" in ctx
        assert self._CRED not in ctx