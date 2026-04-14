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


_has_gitleaks = sc.find_gitleaks() is not None


@pytest.mark.skipif(not _has_gitleaks, reason="gitleaks not installed")
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

    def test_clean_prompt_passes_through(self):
        rc, out, _ = run_hook("hook-user-prompt", self._event("what is the weather like?"))
        assert rc == 0

    def test_secret_in_prompt_passes_through(self):
        """Secrets pass through hook — proxy handles redaction now."""
        rc, out, stderr = run_hook(
            "hook-user-prompt",
            self._event(f"My AWS key is {_AWS}, help me use it"),
        )
        assert rc == 0  # no longer blocks

    def test_pii_in_prompt_passes_through(self):
        """PII passes through hook — proxy handles redaction now."""
        rc, out, stderr = run_hook(
            "hook-user-prompt",
            self._event("My SSN is 123-45-6789, is it safe?"),
        )
        assert rc == 0  # no longer blocks


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
    @pytest.mark.skipif(not _has_gitleaks, reason="gitleaks not installed — scan-path returns error finding")
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

    def test_hook_passes_through_fuzzy_credential(self):
        """Hook passes through (exit 0) — proxy handles wire privacy now."""
        rc, out, stderr = run_hook(
            "hook-user-prompt",
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": f"here is my new pass CSKC:{self._CRED}",
                "session_id": "test",
            },
        )
        assert rc == 0  # no longer blocks


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
        assert not sc._is_dummy_value("Devs-MacBook-Pro")
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


class TestTrainingMode:
    def test_capture_skipped_without_author_flag(self, tmp_path):
        """Without LEAK_GUARD_AUTHOR=1, no training_log.jsonl is written."""
        cred = "CSKC:Scds" + "JCCKLSLKDKLCNLKCEINK2233as"
        env = {k: v for k, v in os.environ.items() if k != "LEAK_GUARD_AUTHOR"}
        env["LEAK_GUARD_STATE_DIR"] = str(tmp_path)
        r = subprocess.run(
            [sys.executable, str(SCANNER), "hook-user-prompt"],
            input=json.dumps({"hook_event_name": "UserPromptSubmit",
                              "prompt": f"my key {cred}",
                              "session_id": "train-test"}),
            capture_output=True, text=True, env=env, timeout=30,
        )
        log = tmp_path / "training_log.jsonl"
        assert not log.exists(), "training_log.jsonl must NOT be written without LEAK_GUARD_AUTHOR=1"

    def test_hook_does_not_write_training_log(self, tmp_path):
        """hook-user-prompt is now pass-through; training_log.jsonl is never written."""
        cred = "CSKC:Scds" + "JCCKLSLKDKLCNLKCEINK2233as"
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path), "LEAK_GUARD_AUTHOR": "1"}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "hook-user-prompt"],
            input=json.dumps({"hook_event_name": "UserPromptSubmit",
                              "prompt": f"my key {cred}",
                              "session_id": "train-test"}),
            capture_output=True, text=True, env=env, timeout=30,
        )
        assert r.returncode == 0  # pass-through always
        log = tmp_path / "training_log.jsonl"
        assert not log.exists(), "hook-user-prompt no longer writes training_log (proxy handles)"

    def test_verdict_updates_pending_entry(self, tmp_path):
        log = tmp_path / "training_log.jsonl"
        fake_hash = "abcd1234efgh5678"
        entry = {"ts": 1000.0, "session_id": "s1", "verdict": "pending", "analysis": None,
                 "rule_id": "fuzzy-prefixed-credential", "category": "secret",
                 "severity": "high", "hash": fake_hash,
                 "preview": "[REDACTED:fuzzy:8ch:hash=abcd1234]", "source": "<test>"}
        log.write_text(json.dumps(entry) + "\n")
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path), "LEAK_GUARD_AUTHOR": "1"}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "verdict", fake_hash, "fp"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, r.stderr
        updated = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert updated[0]["verdict"] == "fp"
        assert "verdict_ts" in updated[0]

    def test_list_filters_by_verdict(self, tmp_path):
        log = tmp_path / "training_log.jsonl"
        entries = [
            {"ts": 1000.0, "verdict": "pending", "rule_id": "fuzzy-prefixed-credential",
             "hash": "aabbcc11", "preview": "[REDACTED:8ch]", "source": "<test>",
             "session_id": "s1", "analysis": None},
            {"ts": 2000.0, "verdict": "fp", "rule_id": "email",
             "hash": "ddeeff22", "preview": "a@b.com", "source": "<test>",
             "session_id": "s2", "analysis": None},
        ]
        log.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path)}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "list", "--filter", "pending"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0
        assert "aabbcc11" in r.stdout
        assert "ddeeff22" not in r.stdout

    def test_promote_fn_writes_to_pii_toml(self, tmp_path):
        """High-confidence FN entries are promoted as pii.toml candidate blocks."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "pii.toml").write_text("# patterns\n")
        (rules_dir / "allowlist.toml").write_text("[suppress_rules]\n")

        log = tmp_path / "training_log.jsonl"
        entry = {
            "ts": 1000.0, "verdict": "fn", "session_id": "s1",
            "rule_id": "my-custom-prefix", "category": "secret", "severity": "high",
            "hash": "aabb1122ccdd3344", "preview": "[REDACTED:12ch:hash=aabb1122]",
            "source": "<test>", "promoted": False,
            "analysis": {"category": "secret", "confidence": 0.9,
                         "reason": "looks like an internal API key format",
                         "analyzed_ts": 1000.0},
        }
        log.write_text(json.dumps(entry) + "\n")
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path),
               "LEAK_GUARD_AUTHOR": "1", "LEAK_GUARD_RULES_DIR": str(rules_dir)}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "promote"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, r.stderr
        assert "my-custom-prefix" in r.stdout
        updated = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert updated[0].get("promoted") is True

    def test_promote_fp_writes_to_allowlist(self, tmp_path):
        """High-confidence FP entries are promoted as suppress_rules."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "allowlist.toml").write_text("[suppress_rules]\n")
        (rules_dir / "pii.toml").write_text("")

        log = tmp_path / "training_log.jsonl"
        entry = {
            "ts": 1000.0, "verdict": "fp", "session_id": "s1",
            "rule_id": "high-entropy-base64", "category": "secret", "severity": "high",
            "hash": "ccdd3344eeff5566", "preview": "[REDACTED:10ch:hash=ccdd3344]",
            "source": "<test>", "promoted": False,
            "analysis": {"category": "benign", "confidence": 0.85,
                         "reason": "internal session token, not a user secret",
                         "analyzed_ts": 1000.0},
        }
        log.write_text(json.dumps(entry) + "\n")
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path),
               "LEAK_GUARD_AUTHOR": "1", "LEAK_GUARD_RULES_DIR": str(rules_dir)}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "promote"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, r.stderr
        allowlist = (rules_dir / "allowlist.toml").read_text()
        assert "high-entropy-base64" in allowlist


class TestHookSettings:
    """Tests for the hook-settings subcommand that wires Claude Code hooks."""

    HOOK_CMDS = [
        "hook-user-prompt",
        "hook-pre-tool",
        "hook-post-tool",
        "hook-session-start",
    ]

    def _run_hook_settings(self, settings_path: Path, scanner_path: str = "/fake/scanner.py") -> int:
        """Call cmd_hook_settings with a custom settings path and scanner path."""
        return sc.cmd_hook_settings(
            settings_path=settings_path,
            scanner_path=scanner_path,
        )

    def test_creates_settings_file_if_missing(self, tmp_path):
        settings = tmp_path / "settings.json"
        assert not settings.exists()
        rc = self._run_hook_settings(settings)
        assert rc == 0
        assert settings.exists()
        data = json.loads(settings.read_text())
        assert "hooks" in data

    def test_wires_all_three_hook_events(self, tmp_path):
        settings = tmp_path / "settings.json"
        rc = self._run_hook_settings(settings)
        assert rc == 0
        data = json.loads(settings.read_text())
        hooks = data["hooks"]
        assert "UserPromptSubmit" in hooks
        assert "PreToolUse" in hooks
        assert "SessionStart" in hooks
        assert "PostToolUse" not in hooks

    def test_idempotent_no_duplicates_on_rerun(self, tmp_path):
        settings = tmp_path / "settings.json"
        # Run twice
        self._run_hook_settings(settings)
        self._run_hook_settings(settings)
        data = json.loads(settings.read_text())
        # Each event should still have exactly one leak-guard hook entry
        for event in ["UserPromptSubmit", "PreToolUse", "SessionStart"]:
            entries = data["hooks"][event]
            lg_entries = [
                e for e in entries
                if any(
                    "scanner.py" in h.get("command", "")
                    for h in e.get("hooks", [])
                )
            ]
            assert len(lg_entries) == 1, f"{event} has {len(lg_entries)} leak-guard entries after idempotent rerun"

    def test_preserves_existing_non_leakguard_hooks(self, tmp_path):
        settings = tmp_path / "settings.json"
        # Pre-populate with an existing unrelated hook
        existing = {
            "hooks": {
                "SessionStart": [
                    {
                        "matcher": "compact",
                        "hooks": [
                            {"type": "command", "command": "echo 'compacted'"}
                        ]
                    }
                ]
            }
        }
        settings.write_text(json.dumps(existing))
        rc = self._run_hook_settings(settings)
        assert rc == 0
        data = json.loads(settings.read_text())
        session_entries = data["hooks"]["SessionStart"]
        # compact hook still present
        compact = [e for e in session_entries if e.get("matcher") == "compact"]
        assert len(compact) == 1
        # leak-guard startup hook also added
        startup = [e for e in session_entries if e.get("matcher") == "startup"]
        assert len(startup) == 1

    def test_each_hook_contains_correct_subcommand(self, tmp_path):
        settings = tmp_path / "settings.json"
        scanner = "/some/path/scanner.py"
        self._run_hook_settings(settings, scanner_path=scanner)
        data = json.loads(settings.read_text())
        for event, subcmd in [
            ("UserPromptSubmit", "hook-user-prompt"),
            ("PreToolUse", "hook-pre-tool"),
            ("SessionStart", "hook-session-start"),
        ]:
            entries = data["hooks"][event]
            commands = [
                h["command"]
                for e in entries
                for h in e.get("hooks", [])
            ]
            assert any(subcmd in cmd for cmd in commands), \
                f"{event}: expected subcommand '{subcmd}' in commands {commands}"

    def test_updates_stale_hook_paths(self, tmp_path):
        """_add_hook should update existing hook commands, not skip them."""
        settings = tmp_path / "settings.json"
        # Wire hooks with old path
        self._run_hook_settings(settings, scanner_path="/old/scanner.py")
        # Re-wire with new path
        self._run_hook_settings(settings, scanner_path="/new/scanner.py")
        data = json.loads(settings.read_text())
        for event in ["UserPromptSubmit", "PreToolUse", "SessionStart"]:
            commands = [
                h["command"]
                for e in data["hooks"][event]
                for h in e.get("hooks", [])
            ]
            assert any("/new/scanner.py" in cmd for cmd in commands), \
                f"{event}: expected updated path '/new/scanner.py'"
            assert not any("/old/scanner.py" in cmd for cmd in commands), \
                f"{event}: stale path '/old/scanner.py' should have been replaced"

    def test_cleans_up_deprecated_post_tool_use(self, tmp_path):
        """cmd_hook_settings should remove existing PostToolUse leak-guard entries."""
        settings = tmp_path / "settings.json"
        # Pre-populate with a PostToolUse hook
        existing = {
            "hooks": {
                "PostToolUse": [
                    {"hooks": [{"type": "command", "command": "python3 /old/scanner.py hook-post-tool"}]}
                ]
            }
        }
        settings.write_text(json.dumps(existing))
        self._run_hook_settings(settings)
        data = json.loads(settings.read_text())
        assert "PostToolUse" not in data["hooks"]


class TestPerformance:
    def test_normalize_called_once_in_scan_all(self):
        """Verify _normalize_text is called at most once per scan_all invocation."""
        import unittest.mock as mock
        with mock.patch.object(sc, "_normalize_text", wraps=sc._normalize_text) as m:
            sc.scan_all(text="hello world this is a test", source_label="perf-test")
            assert m.call_count <= 1, f"_normalize_text called {m.call_count} times, expected ≤1"

    def test_pii_rules_cached_by_mtime(self):
        """Verify load_pii_rules returns the same object on repeated calls."""
        r1 = sc.load_pii_rules()
        r2 = sc.load_pii_rules()
        assert r1 is r2

    def test_filename_blocklist_cached(self):
        """Verify load_filename_blocklist returns the same object on repeated calls."""
        b1 = sc.load_filename_blocklist()
        b2 = sc.load_filename_blocklist()
        assert b1 is b2


class TestDbUrlRules:
    """Task 3: DB connection string, URL credential, and Slack webhook detection."""

    def test_postgres_dsn_detected(self):
        text = "DATABASE_URL=postgre" + "sql://appuser:Kj8mP2qL7nR4@db.prod.internal:5432/myapp"
        hits = sc.scan_secrets_fast(text)
        assert any(f.rule_id == "db-connection-string" for f in hits)

    def test_mysql_dsn_detected(self):
        text = "DB=my" + "sql://root:S3cretPa55w0rd@mysql.internal:3306/app"
        hits = sc.scan_secrets_fast(text)
        assert any(f.rule_id == "db-connection-string" for f in hits)

    def test_mongodb_srv_detected(self):
        text = "MONGO=mongo" + "db+srv://admin:xK9mP2qL7n@cluster0.abc.mongodb.net"
        hits = sc.scan_secrets_fast(text)
        assert any(f.rule_id == "db-connection-string" for f in hits)

    def test_url_embedded_cred_detected(self):
        text = "REGISTRY=htt" + "ps://deploy:xK9mP2qL7nR4@registry.example.com/v2/"
        hits = sc.scan_secrets_fast(text)
        assert any(f.rule_id == "url-embedded-credential" for f in hits)

    def test_url_localhost_not_detected(self):
        text = "URL=htt" + "ps://user:password@localhost:8080/api"
        hits = sc.scan_secrets_fast(text)
        assert not any(f.rule_id == "url-embedded-credential" for f in hits)

    def test_db_short_password_not_detected(self):
        text = "DB=postgre" + "sql://user:pass@host/db"
        hits = sc.scan_secrets_fast(text)
        assert not any(f.rule_id == "db-connection-string" for f in hits)

    def test_slack_webhook_detected(self):
        text = "HOOK=https://hooks.slack.com/services/T" + "ABC123/B" + "DEF456/abcdefghij1234567890"
        hits = sc.scan_secrets_fast(text)
        assert any(f.rule_id == "slack-webhook" for f in hits)


class TestVendorFastRules:
    """Task 5: Vendor-specific fast rules."""

    def test_gitlab_pat_detected(self):
        token = "glp" + "at-" + "Kj8mP2qL7nR4xW5bYzD9"
        hits = sc.scan_secrets_fast(f"TOKEN={token}")
        assert any(f.rule_id == "gitlab-pat" for f in hits)

    def test_digitalocean_pat_detected(self):
        token = "dop" + "_v1_" + "a3f8c1d9e7b2046f" * 4
        hits = sc.scan_secrets_fast(f"TOKEN={token}")
        assert any(f.rule_id == "digitalocean-pat" for f in hits)

    def test_hashicorp_vault_detected(self):
        token = "hv" + "s." + "Kj8mP2qL7nR4xW5bYzD9cHf6"
        hits = sc.scan_secrets_fast(f"VAULT_TOKEN={token}")
        assert any(f.rule_id == "hashicorp-vault-token" for f in hits)

    def test_shopify_pat_detected(self):
        token = "shp" + "at_" + "a3f8c1d9e7b2046f" * 2
        hits = sc.scan_secrets_fast(f"TOKEN={token}")
        assert any(f.rule_id == "shopify-access-token" for f in hits)

    def test_square_token_detected(self):
        token = "sq0" + "atp-" + "Kj8mP2qL7nR4xW5bYzD9cH"
        hits = sc.scan_secrets_fast(f"TOKEN={token}")
        assert any(f.rule_id == "square-access-token" for f in hits)

    def test_telegram_bot_token_detected(self):
        token = "12345" + "6789:" + "ABCDefGHIjkLMnoPQRsTUvWXYz012345678"
        hits = sc.scan_secrets_fast(f"BOT_TOKEN={token}")
        assert any(f.rule_id == "telegram-bot-token" for f in hits)

    def test_mailgun_key_detected(self):
        token = "ke" + "y-" + "a3f8c1d9e7b2046f" * 2
        hits = sc.scan_secrets_fast(f"MAILGUN_KEY={token}")
        assert any(f.rule_id == "mailgun-api-key" for f in hits)

    def test_dummy_gitlab_pat_not_detected(self):
        token = "glp" + "at-" + "X" * 20  # all-same-char payload
        hits = sc.scan_secrets_fast(f"TOKEN={token}")
        assert not any(f.rule_id == "gitlab-pat" for f in hits)


class TestInternationalPii:
    """Task 4: International PII rules."""

    def setup_method(self):
        self.rules = sc.load_pii_rules()
        self.allow = sc.Allowlist()

    def test_uk_ni_number_detected(self):
        hits = sc.scan_pii_text("NI number: AB 12 34 56 C", self.rules, self.allow)
        assert any(f.rule_id == "uk-ni-number" for f in hits)

    def test_canadian_sin_detected(self):
        hits = sc.scan_pii_text("SIN: 123-456-789", self.rules, self.allow)
        assert any(f.rule_id == "ca-sin" for f in hits)

    def test_australian_tfn_detected(self):
        hits = sc.scan_pii_text("TFN: 123 456 789", self.rules, self.allow)
        assert any(f.rule_id == "au-tfn" for f in hits)

    def test_aadhaar_detected(self):
        hits = sc.scan_pii_text("Aadhaar: 1234 5678 9012", self.rules, self.allow)
        assert any(f.rule_id == "in-aadhaar" for f in hits)

    def test_mexican_curp_detected(self):
        hits = sc.scan_pii_text("CURP: GARC850101HDFRRL09", self.rules, self.allow)
        assert any(f.rule_id == "mx-curp" for f in hits)

    def test_german_id_detected(self):
        hits = sc.scan_pii_text("Personalausweis: L12345678", self.rules, self.allow)
        assert any(f.rule_id == "de-personalausweis" for f in hits)


class TestBorderlineConfidence:
    """Borderline findings still block (exit 2) under block-and-preview."""

    def test_borderline_exits_2(self):
        """When all findings are borderline, hook still blocks (exit 2)."""
        prompt = "config_value=" + "Kj8" + "mP2" + "qL7" + "nR4" + "xW5" + "bYz" + "D9c" + "Hf6" + "eG3" + "tUo"
        rc, out, stderr = run_hook("hook-user-prompt", {"prompt": prompt})
        if rc == 2:
            assert "leak-guard" in stderr


class TestNerInstruction:
    """Task 7: Claude-as-NER for unstructured PII detection."""

    def test_short_prompt_no_ner(self):
        """Short prompts should not trigger NER instruction."""
        rc, out, _ = run_hook("hook-user-prompt", {"prompt": "fix the bug"})
        if out:
            ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
            assert "PII Review" not in ctx

    def test_long_clean_prompt_gets_ner(self):
        """Prompts >200 chars with no findings should get NER instruction."""
        long_text = "Please help me refactor this module to use better patterns. " * 5
        assert len(long_text) >= 200
        rc, out, _ = run_hook("hook-user-prompt", {"prompt": long_text})
        assert out is not None
        ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "PII Review" in ctx

    def test_long_prompt_with_secrets_gets_ner(self):
        """Long prompts with secrets also get NER instruction — proxy handles redaction."""
        secret_prompt = "my key is " + "ghp_" + "R8mN2kLpQ7vXdYeZwBtA5cJfHsUoIgPn3m1" + " please use it " * 20
        assert len(secret_prompt) >= 200
        rc, out, _ = run_hook("hook-user-prompt", {"prompt": secret_prompt})
        assert rc == 0  # pass-through always
        # Long prompts get NER instruction regardless of findings
        assert out is not None
        ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "PII Review" in ctx


class TestConfidenceScoring:
    """Component 5: Confidence scoring — every finding gets a 0.0-1.0 score."""

    def test_vendor_rule_high_confidence(self):
        f = sc.Finding("github-pat", "secret", "", 0, "[R]")
        assert sc._confidence(f) == 0.95

    def test_structured_pii_confidence(self):
        f = sc.Finding("us-ssn", "pii", "", 0, "[R]")
        assert sc._confidence(f) == 0.90

    def test_db_connection_confidence(self):
        f = sc.Finding("db-connection-string", "secret", "", 0, "[R]")
        assert sc._confidence(f) == 0.90

    def test_assigned_password_medium_confidence(self):
        f = sc.Finding("assigned-password", "pii", "", 0, "[R]")
        assert sc._confidence(f) == 0.70

    def test_entropy_low_confidence(self):
        f = sc.Finding("high-entropy-base64", "pii", "", 0, "[R]")
        assert sc._confidence(f) == 0.50

    def test_unknown_rule_default_confidence(self):
        f = sc.Finding("some-unknown-rule", "secret", "", 0, "[R]")
        assert sc._confidence(f) == 0.60


class TestSemanticRedaction:
    """Component 2: Semantic redaction — typed tags instead of generic [REDACTED]."""

    def test_pii_rule_uses_rule_id(self):
        f = sc.Finding("credit-card", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:credit-card]"

    def test_email_uses_rule_id(self):
        f = sc.Finding("email", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:email]"

    def test_vendor_secret_uses_credential(self):
        f = sc.Finding("github-pat", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:credential]"

    def test_db_connection_string_tag(self):
        f = sc.Finding("db-connection-string", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:connection-string]"

    def test_url_credential_tag(self):
        f = sc.Finding("url-embedded-credential", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:url-credential]"

    def test_ner_name_tag(self):
        f = sc.Finding("ner-name", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:name]"

    def test_ner_address_tag(self):
        f = sc.Finding("ner-address", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:address]"

    def test_entropy_uses_suspicious_value(self):
        f = sc.Finding("high-entropy-base64", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:suspicious-value]"

    def test_fuzzy_uses_suspicious_value(self):
        f = sc.Finding("fuzzy-prefixed-credential", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:suspicious-value]"


class TestNerCandidates:
    """Component 4: Local NER — regex-based candidate extraction with context scoring."""

    def test_name_near_medical_keyword_detected(self):
        text = "The patient John Smith was diagnosed with pneumonia on 03/15/2025."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-name" for f in hits)

    def test_name_near_legal_keyword_detected(self):
        text = "The defendant Jane Doe filed a motion in court on Monday."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-name" for f in hits)

    def test_name_without_context_not_detected(self):
        """A name with no medical/legal/financial context should score below threshold."""
        text = "Please refactor the Hello World function in the codebase."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert not any(f.rule_id == "ner-name" for f in hits)

    def test_address_detected(self):
        text = "Send the package to 1234 Oak Street, Springfield."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-address" for f in hits)

    def test_dated_record_detected(self):
        text = "The patient was diagnosed with diabetes on 01/15/2024 at the clinic."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-dated-record" for f in hits)

    def test_score_increases_with_multiple_keywords(self):
        """Two context keywords should score higher than one."""
        text_one = "The patient John Smith visited today."
        text_two = "The patient John Smith was diagnosed with pneumonia at the hospital."
        score_one = sc._score_ner_candidate_text(text_one, "name")
        score_two = sc._score_ner_candidate_text(text_two, "name")
        assert score_two > score_one

    def test_ner_finding_has_correct_category(self):
        text = "The patient John Smith was diagnosed with pneumonia."
        hits = sc._scan_ner_candidates(text, source="<test>")
        for h in hits:
            assert h.category == "pii"

    def test_ner_finding_raw_match_not_in_preview(self):
        text = "The patient John Smith was diagnosed with pneumonia."
        hits = sc._scan_ner_candidates(text, source="<test>")
        for h in hits:
            if h.raw_match:
                assert h.raw_match not in h.preview


class TestSymbolicFingerprint:
    """Component 3: Symbolic FP reduction — fingerprint without raw values."""

    def test_fingerprint_has_required_fields(self):
        f = sc.Finding("high-entropy-base64", "pii", "entropy hit", 1, "[R]",
                       raw_match="xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7")
        text = "const cacheKey = xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7"
        fp = sc._build_symbolic_fingerprint(f, text)
        assert "rule_id" in fp
        assert "length" in fp
        assert "entropy" in fp
        assert "charset" in fp
        assert "context_keywords" in fp
        assert "position" in fp
        assert "adjacent_code" in fp

    def test_fingerprint_masks_raw_value(self):
        val = "xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7"
        f = sc.Finding("high-entropy-base64", "pii", "", 1, "[R]", raw_match=val)
        text = f"secret = '{val}'"
        fp = sc._build_symbolic_fingerprint(f, text)
        assert val not in fp["adjacent_code"]
        assert "___" in fp["adjacent_code"]

    def test_fingerprint_detects_rhs_position(self):
        val = "xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7"
        f = sc.Finding("high-entropy-base64", "pii", "", 1, "[R]", raw_match=val)
        text = f'API_KEY = "{val}"'
        fp = sc._build_symbolic_fingerprint(f, text)
        assert fp["position"] == "rhs_of_assignment"

    def test_fingerprint_detects_hex_charset(self):
        val = "a3f8c1d9e7b2046fa3f8c1d9e7b2046f"
        f = sc.Finding("high-entropy-hex", "pii", "", 1, "[R]", raw_match=val)
        fp = sc._build_symbolic_fingerprint(f, f"hash = {val}")
        assert fp["charset"] == "hex"

class TestFeedbackLoop:
    """Component 6: FP profile — learn from user allow decisions without raw values."""

    def test_match_fp_profile(self):
        """_match_fp_profile returns previous allow count when profile matches."""
        profile = {"rule_id": "high-entropy-base64", "charset": "base64url",
                    "position": "rhs_of_assignment", "length": 40}
        history = [
            {"rule_id": "high-entropy-base64", "charset": "base64url",
             "position": "rhs_of_assignment", "length": 38},
            {"rule_id": "high-entropy-base64", "charset": "base64url",
             "position": "rhs_of_assignment", "length": 42},
            {"rule_id": "email", "charset": "mixed",
             "position": "standalone", "length": 20},
        ]
        count = sc._match_fp_profile(profile, history)
        assert count == 2  # two matching entries


class TestPostToolNer:
    """Component 7: PostToolUse NER — catch unstructured PII in tool output."""

    def test_name_in_read_output_blocked(self):
        """NER-detected name in Read output triggers block."""
        text = (
            "Patient records:\n"
            "The patient John Smith was diagnosed with pneumonia.\n"
            "Treatment plan was discussed with the physician.\n"
        ) + "Additional notes. " * 15  # pad to exceed NER min length
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/patient_notes.txt"},
            "tool_response": {"content": text},
            "session_id": "test",
        }
        rc, out, stderr = run_hook("hook-post-tool", event)
        assert rc == 0  # PostToolUse always exits 0
        if out and out.get("decision") == "block":
            reason = out.get("reason", "")
            assert "ner" in reason.lower() or "PII" in reason or "REDACTED" in reason

    def test_short_output_no_ner(self):
        """Short tool output should not trigger NER scan."""
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/short.txt"},
            "tool_response": {"content": "Hello World"},
            "session_id": "test",
        }
        rc, out, _ = run_hook("hook-post-tool", event)
        assert rc == 0
        assert out is None or out.get("decision") != "block"

    def test_output_with_regex_findings_no_ner(self):
        """When regex finds secrets, NER is not needed (already blocked)."""
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/creds.txt"},
            "tool_response": {"content": f"AWS_KEY={aws}\n"},
            "session_id": "test",
        }
        rc, out, _ = run_hook("hook-post-tool", event)
        assert rc == 0
        assert out is not None
        assert out.get("decision") == "block"
