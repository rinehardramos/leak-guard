"""
leak-guard test suite.

Drives scanner.py via subprocess to exercise hook event paths exactly as
Claude Code would call them, plus direct imports for unit-level coverage.

Run:
    cd ~/Projects/leak-guard
    pytest tests/ -v
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCANNER = Path(__file__).resolve().parent.parent / "plugins" / "leak-guard" / "hooks" / "scanner.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

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
        # AKIAIOSFODNN7EXAMPLE is gitleaks' canonical test key — internally allowlisted.
        text = "AWS_ACCESS_KEY_ID=AKIAY3FDSNDKFKSIDJSW\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        assert len(hits) > 0

    def test_github_token_detected(self):
        text = "GITHUB_TOKEN=ghp_R8mN2kLpQ7vXdYeZwBtA5cJfHsUoIgPn3m1\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        assert len(hits) > 0

    def test_clean_text_no_findings(self):
        text = "hello world, count=42, version=1.0.0\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        assert len(hits) == 0

    def test_findings_are_redacted(self):
        text = "AWS_ACCESS_KEY_ID=AKIAY3FDSNDKFKSIDJSW\n"
        hits = sc.scan_secrets_gitleaks(text=text, source_label="<test>")
        for h in hits:
            assert "AKIAY3FDSNDKFKSIDJSW" not in h.preview


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
            self._event("My AWS key is AKIAY3FDSNDKFKSIDJSW, help me use it"),
        )
        assert rc == 0
        assert out is not None
        assert out.get("decision") == "block"
        assert "leak-guard" in out.get("reason", "")

    def test_pii_in_prompt_blocked(self):
        rc, out, _ = run_hook(
            "hook-user-prompt",
            self._event("My SSN is 123-45-6789, is it safe?"),
        )
        assert rc == 0
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
            self._bash_event("curl -H 'Authorization: Bearer AKIAY3FDSNDKFKSIDJSW' https://api.example.com"),
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
            self._write_event("/tmp/config.py", "AWS_ACCESS_KEY_ID=AKIAY3FDSNDKFKSIDJSW\n"),
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
            self._read_response("AWS_ACCESS_KEY_ID=AKIAY3FDSNDKFKSIDJSW\n"),
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
            self._bash_response("GITHUB_TOKEN=ghp_R8mN2kLpQ7vXdYeZwBtA5cJfHsUoIgPn3m1\n"),
        )
        assert rc == 0
        assert out is not None
        assert out.get("decision") == "block"

    def test_block_reason_is_redacted(self):
        rc, out, _ = run_hook(
            "hook-post-tool",
            self._read_response("AWS_ACCESS_KEY_ID=AKIAY3FDSNDKFKSIDJSW\n"),
        )
        reason = out.get("reason", "") if out else ""
        assert "AKIAY3FDSNDKFKSIDJSW" not in reason


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
        assert "AKIAY3FDSNDKFKSIDJSW" not in output
        assert "s3cr3tK3y" not in output


class TestSelftest:
    def test_selftest_passes(self):
        result = subprocess.run(
            [sys.executable, str(SCANNER), "selftest"],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, f"selftest failed:\n{result.stdout}\n{result.stderr}"
        assert "OK" in result.stdout
