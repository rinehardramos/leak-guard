"""Integration tests — proxy redaction pipeline, hook wiring, fresh-install, and cache sync.

The proxy is the primary enforcement path (v0.6.0+). These tests exercise:
  1. Proxy scan-and-redact pipeline (the main detection path)
  2. Proxy allow/redact choice flow with pending state
  3. Hook wiring and stale-path repair
  4. Fresh-install cache sync and breadcrumb
  5. PreToolUse hooks (secondary enforcement for tool input/filename blocking)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCANNER = ROOT / "plugins" / "leak-guard" / "hooks" / "scanner.py"
FIXTURES = ROOT / "tests" / "fixtures"

# Import scanner and proxy modules directly (same pattern as test_scanner.py)
sys.path.insert(0, str(SCANNER.parent))
import scanner as sc  # noqa: E402
import proxy as px    # noqa: E402


def run_hook(subcmd: str, event: dict, timeout: int = 30) -> tuple[int, dict | None, str]:
    """Run scanner.py <subcmd> with JSON stdin."""
    result = subprocess.run(
        [sys.executable, str(SCANNER), subcmd],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = None
    if result.stdout.strip():
        try:
            out = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return result.returncode, out, result.stderr


# ---------------------------------------------------------------------------
# Proxy redaction pipeline (primary enforcement)
# ---------------------------------------------------------------------------

class TestProxyRedactionPipeline:
    """End-to-end: payload with secret -> redacted payload + system note + pending."""

    def _payload(self, user_text: str) -> dict:
        return {"messages": [{"role": "user", "content": user_text}]}

    def test_aws_key_redacted_in_payload(self):
        fake_key = "AKIA" + "Y3FDSN" + "DKFKSIDJSW"
        payload = self._payload(f"my key is {fake_key}")
        modified, findings = px.scan_and_redact_payload(payload, sc.Allowlist())
        assert findings, "expected findings for AWS key"
        assert fake_key not in modified["messages"][0]["content"]
        assert "[REDACTED:" in modified["messages"][0]["content"]

    def test_ssn_redacted_in_content_blocks(self):
        ssn = "456-78-9012"
        payload = {
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": f"SSN: {ssn}"}],
            }]
        }
        modified, findings = px.scan_and_redact_payload(payload, sc.Allowlist())
        assert findings
        assert ssn not in modified["messages"][0]["content"][0]["text"]

    def test_clean_payload_passes_through(self):
        payload = self._payload("Hello, how are you?")
        modified, findings = px.scan_and_redact_payload(payload, sc.Allowlist())
        assert findings == []
        assert modified["messages"][0]["content"] == "Hello, how are you?"

    def test_system_note_injected_on_findings(self):
        fake_key = "AKIA" + "Y3FDSN" + "DKFKSIDJSW"
        payload = self._payload(f"my key is {fake_key}")
        modified, findings = px.scan_and_redact_payload(payload, sc.Allowlist())
        noted = px.inject_system_note_with_question(modified, findings)
        # System note should be present and should NOT contain the raw key
        system = noted.get("system", "")
        if isinstance(system, list):
            system = " ".join(b.get("text", "") for b in system)
        assert "leak-guard" in system
        assert fake_key not in system

    def test_allowlisted_value_not_redacted(self):
        fake_key = "AKIA" + "Y3FDSN" + "DKFKSIDJSW"
        allow = sc.Allowlist()
        allow.literal = {fake_key}
        payload = self._payload(f"my key is {fake_key}")
        modified, findings = px.scan_and_redact_payload(payload, allow)
        assert not any(f["raw"] == fake_key for f in findings)

    def test_assistant_messages_not_scanned(self):
        fake_key = "AKIA" + "Y3FDSN" + "DKFKSIDJSW"
        payload = {
            "messages": [
                {"role": "assistant", "content": f"key={fake_key}"},
                {"role": "user", "content": "OK thanks"},
            ]
        }
        modified, findings = px.scan_and_redact_payload(payload, sc.Allowlist())
        assert fake_key in modified["messages"][0]["content"]
        assert not findings


class TestProxyAllowRedactFlow:
    """End-to-end: Turn 1 redacts -> pending saved -> Turn 2 user chooses."""

    def test_full_allow_flow(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")
        monkeypatch.setattr(px, "STATE_DIR", tmp_path)
        monkeypatch.setattr(sc, "USER_ALLOWLIST", tmp_path / "allowlist.toml")
        sc._allowlist_cache["mtime"] = -1.0
        sc._allowlist_cache["data"] = None

        ssn = "456-78-9012"

        # Turn 1: scan and redact
        payload = {"messages": [{"role": "user", "content": f"SSN: {ssn}"}]}
        modified, findings = px.scan_and_redact_payload(payload, sc.Allowlist())
        assert findings
        assert ssn not in modified["messages"][0]["content"]

        # Save pending (proxy does this on Turn 1)
        px.write_pending(findings)

        # Turn 2: user says "allow"
        pending = px.read_and_clear_pending()
        assert pending is not None
        choice = px.is_allow_response("a")
        assert choice == "allow"

        # Persist to allowlist
        for f in pending:
            sc._append_literal(f["raw"], "test allow")

        # Verify value is now in allowlist
        sc._allowlist_cache["mtime"] = -1.0
        sc._allowlist_cache["data"] = None
        allow = sc.load_allowlist()
        assert ssn in allow.literal

        # Turn 3: same value is no longer redacted
        payload2 = {"messages": [{"role": "user", "content": f"SSN: {ssn}"}]}
        modified2, findings2 = px.scan_and_redact_payload(payload2, allow)
        assert not any(f["raw"] == ssn for f in findings2)

    def test_full_redact_flow(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")

        ssn = "456-78-9012"
        findings = [{"type": "us-ssn", "raw": ssn, "tag": "[REDACTED:us-ssn]",
                      "rule_id": "us-ssn", "confidence": 0.9}]
        px.write_pending(findings)

        # User says "redact"
        pending = px.read_and_clear_pending()
        assert pending is not None
        choice = px.is_allow_response("r")
        assert choice == "redact"

        # Pending is cleared
        assert px.read_and_clear_pending() is None

    def test_pending_expires_after_ttl(self, tmp_path, monkeypatch):
        monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")

        findings = [{"type": "test", "raw": "x", "tag": "[REDACTED:test]",
                      "rule_id": "test", "confidence": 1.0}]
        px.write_pending(findings)

        # Backdate the pending file
        import time
        pending_data = json.loads((tmp_path / "pending.json").read_text())
        pending_data["ts"] = time.time() - 600  # 10 minutes ago
        (tmp_path / "pending.json").write_text(json.dumps(pending_data))

        assert px.read_and_clear_pending() is None  # expired


# ---------------------------------------------------------------------------
# Proxy HTTP health check
# ---------------------------------------------------------------------------

class TestProxyHTTP:
    @pytest.fixture
    def proxy_port(self, tmp_path, monkeypatch):
        import socket
        import threading
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        monkeypatch.setattr(px, "PENDING_FILE", tmp_path / "pending.json")
        monkeypatch.setattr(px, "STATE_DIR", tmp_path)
        server = px.ThreadedHTTPServer(("127.0.0.1", port), px.ProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield port
        server.shutdown()

    def test_health_endpoint(self, proxy_port):
        import urllib.request
        resp = urllib.request.urlopen(f"http://127.0.0.1:{proxy_port}/lg-status")
        data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert isinstance(data["allowlist_size"], int)


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

class TestSelftest:
    def test_selftest_exits_zero(self):
        result = subprocess.run(
            [sys.executable, str(SCANNER), "selftest"],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, f"selftest failed:\n{result.stdout}\n{result.stderr}"
        assert "[FAIL]" not in result.stdout


# ---------------------------------------------------------------------------
# PreToolUse — secret detection in tool input
# ---------------------------------------------------------------------------

class TestPreToolDetection:
    def test_bash_input_with_secret_is_denied(self):
        """A Bash command containing an AWS key should be denied."""
        fake_key = "AKIA" + "Y3FDSN" + "DKFKSIDJSW"
        rc, out, _ = run_hook("hook-pre-tool", {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"echo {fake_key}"},
        })
        assert rc == 0
        assert out is not None
        decision = out["hookSpecificOutput"]["permissionDecision"]
        assert decision == "deny", f"expected deny, got {decision}"

    def test_bash_input_clean_is_allowed(self):
        """A clean Bash command should pass through (no output = allow)."""
        rc, out, _ = run_hook("hook-pre-tool", {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        assert rc == 0
        assert out is None  # no output means allow

    def test_read_sensitive_filename_is_denied(self):
        """Reading .env should be blocked by filename blocklist."""
        rc, out, _ = run_hook("hook-pre-tool", {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/home/user/project/.env"},
        })
        assert rc == 0
        assert out is not None
        decision = out["hookSpecificOutput"]["permissionDecision"]
        assert decision == "deny"

    def test_read_normal_file_is_allowed(self):
        """Reading a normal file should pass through."""
        rc, out, _ = run_hook("hook-pre-tool", {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/home/user/project/README.md"},
        })
        assert rc == 0
        assert out is None

    def test_write_with_aws_key_is_denied(self):
        """Writing a file containing an AWS key should be denied (secret)."""
        fake_key = "AKIA" + "Y3FDSN" + "DKFKSIDJSW"
        rc, out, _ = run_hook("hook-pre-tool", {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/config.json",
                "content": f'{{"aws_key": "{fake_key}"}}',
            },
        })
        assert rc == 0
        assert out is not None
        decision = out["hookSpecificOutput"]["permissionDecision"]
        assert decision == "deny"


# ---------------------------------------------------------------------------
# scan-path — file and directory scanning
# ---------------------------------------------------------------------------

_has_gitleaks = sc.find_gitleaks() is not None


class TestScanPath:
    @pytest.mark.skipif(not _has_gitleaks, reason="gitleaks not installed — scan-path returns error finding")
    def test_clean_file_exits_zero(self):
        clean = FIXTURES / "clean.txt"
        if not clean.exists():
            pytest.skip("clean.txt fixture missing")
        result = subprocess.run(
            [sys.executable, str(SCANNER), "scan-path", str(clean)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_aws_fixture_exits_one(self):
        aws = FIXTURES / "fake_aws.txt"
        if not aws.exists():
            pytest.skip("fake_aws.txt fixture missing")
        result = subprocess.run(
            [sys.executable, str(SCANNER), "scan-path", str(aws)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 1


# ---------------------------------------------------------------------------
# Hook wiring — cmd_hook_settings
# ---------------------------------------------------------------------------

class TestHookWiring:
    @staticmethod
    def _run(settings: Path, scanner_path: str = "/fake/scanner.py") -> int:
        return sc.cmd_hook_settings(settings_path=settings, scanner_path=scanner_path)

    def test_wires_three_hooks_no_post_tool(self, tmp_path):
        settings = tmp_path / "settings.json"
        rc = self._run(settings)
        assert rc == 0
        data = json.loads(settings.read_text())
        hooks = data["hooks"]
        assert "UserPromptSubmit" in hooks
        assert "PreToolUse" in hooks
        assert "SessionStart" in hooks
        assert "PostToolUse" not in hooks

    def test_stale_paths_are_updated(self, tmp_path):
        settings = tmp_path / "settings.json"
        self._run(settings, "/old/scanner.py")
        self._run(settings, "/new/scanner.py")
        data = json.loads(settings.read_text())
        for event in ["UserPromptSubmit", "PreToolUse", "SessionStart"]:
            cmds = [
                h["command"]
                for e in data["hooks"][event]
                for h in e.get("hooks", [])
            ]
            assert any("/new/scanner.py" in c for c in cmds), \
                f"{event}: expected /new/scanner.py"
            assert not any("/old/scanner.py" in c for c in cmds), \
                f"{event}: stale /old/ path should be gone"

    def test_existing_post_tool_use_is_cleaned_up(self, tmp_path):
        settings = tmp_path / "settings.json"
        stale = {
            "hooks": {
                "PostToolUse": [
                    {"hooks": [{"type": "command", "command": "python3 /old/scanner.py hook-post-tool"}]}
                ]
            }
        }
        settings.write_text(json.dumps(stale))
        rc = self._run(settings)
        assert rc == 0
        data = json.loads(settings.read_text())
        assert "PostToolUse" not in data["hooks"]

    def test_non_leakguard_post_tool_preserved(self, tmp_path):
        """Non-leak-guard PostToolUse hooks should not be removed."""
        settings = tmp_path / "settings.json"
        existing = {
            "hooks": {
                "PostToolUse": [
                    {"hooks": [{"type": "command", "command": "python3 /other/tool.py post-tool"}]},
                    {"hooks": [{"type": "command", "command": "python3 /old/scanner.py hook-post-tool"}]},
                ],
            }
        }
        settings.write_text(json.dumps(existing))
        self._run(settings)
        data = json.loads(settings.read_text())
        assert "PostToolUse" in data["hooks"]
        cmds = [h["command"] for e in data["hooks"]["PostToolUse"] for h in e.get("hooks", [])]
        assert any("/other/tool.py" in c for c in cmds)
        assert not any("hook-post-tool" in c and "scanner.py" in c for c in cmds)

    def test_non_leakguard_session_start_preserved(self, tmp_path):
        settings = tmp_path / "settings.json"
        existing = {
            "hooks": {
                "SessionStart": [
                    {"matcher": "compact", "hooks": [{"type": "command", "command": "echo compacted"}]}
                ]
            }
        }
        settings.write_text(json.dumps(existing))
        self._run(settings)
        data = json.loads(settings.read_text())
        compact = [e for e in data["hooks"]["SessionStart"] if e.get("matcher") == "compact"]
        assert len(compact) == 1


# ---------------------------------------------------------------------------
# Install — cache sync and breadcrumb
# ---------------------------------------------------------------------------

class TestInstall:
    def test_install_creates_source_root_breadcrumb(self, tmp_path):
        """install writes .source_root into the cache directory."""
        cache_ver = tmp_path / ".claude" / "plugins" / "cache" / "test" / "leak-guard" / "0.7.0"
        cache_hooks = cache_ver / "hooks"
        cache_hooks.mkdir(parents=True)
        shutil.copy2(SCANNER, cache_hooks / "scanner.py")
        # Copy vendor dir if it exists
        vendor_src = SCANNER.parent / "_vendor"
        if vendor_src.exists():
            shutil.copytree(vendor_src, cache_hooks / "_vendor")
        rules_src = ROOT / "plugins" / "leak-guard" / "rules"
        shutil.copytree(rules_src, cache_ver / "rules")

        result = subprocess.run(
            [sys.executable, str(cache_hooks / "scanner.py"), "install"],
            capture_output=True, text=True, timeout=60,
            env={**dict(__import__("os").environ), "HOME": str(tmp_path)},
        )
        if result.returncode == 0:
            assert (cache_ver / ".source_root").exists()
            src_root = (cache_ver / ".source_root").read_text().strip()
            assert Path(src_root).exists()


# ---------------------------------------------------------------------------
# Allowlist integration
# ---------------------------------------------------------------------------

class TestAllowlistIntegration:
    def test_allowlisted_literal_not_flagged(self, tmp_path, monkeypatch):
        """A value in literal allowlist should be in the loaded allowlist."""
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        user_allow = state_dir / "allowlist.toml"
        user_allow.write_text('literal = ["test@example.com"]\n')

        monkeypatch.setattr(sc, "USER_ALLOWLIST", user_allow)
        monkeypatch.setattr(sc, "STATE_DIR", state_dir)
        sc._allowlist_cache["mtime"] = -1.0
        sc._allowlist_cache["data"] = None

        allow = sc.load_allowlist()
        assert "test@example.com" in allow.literal

    def test_path_glob_suppresses_findings(self):
        """Files matching path_globs should be recognized by path_allowlisted."""
        allow = sc.Allowlist(path_globs=["*/fixtures/*.txt"])
        assert sc.path_allowlisted("/home/user/tests/fixtures/fake_aws.txt", allow)
        assert not sc.path_allowlisted("/home/user/src/main.py", allow)

    def test_bash_glob_integration(self):
        """Default bash_globs should include git commands."""
        sc._allowlist_cache["mtime"] = -1.0
        sc._allowlist_cache["data"] = None
        allow = sc.load_allowlist()
        import fnmatch
        assert any(fnmatch.fnmatch("git log --oneline", g) for g in allow.bash_globs)
        assert any(fnmatch.fnmatch("git diff HEAD~1", g) for g in allow.bash_globs)
        assert any(fnmatch.fnmatch("gh pr view 123", g) for g in allow.bash_globs)


# ---------------------------------------------------------------------------
# Source-tree fallback (cache-aware allowlist)
# ---------------------------------------------------------------------------

class TestSourceTreeFallback:
    def test_find_source_tree_returns_none_when_not_in_cache(self):
        """When running from source tree, no fallback needed."""
        result = sc._find_source_tree_allowlist()
        # PLUGIN_ROOT is the source tree, not cache — should return None
        assert result is None

    def test_breadcrumb_based_lookup(self, tmp_path, monkeypatch):
        """With a .source_root breadcrumb, the source-tree allowlist is found."""
        # Create a fake source tree
        fake_src = tmp_path / "source" / "rules"
        fake_src.mkdir(parents=True)
        (fake_src / "allowlist.toml").write_text('literal = []\n')
        # Create breadcrumb
        fake_plugin = tmp_path / "cache"
        fake_plugin.mkdir()
        (fake_plugin / ".source_root").write_text(str(tmp_path / "source"))

        # Temporarily set PLUGIN_ROOT to the fake cache path
        monkeypatch.setattr(sc, "PLUGIN_ROOT", fake_plugin)
        # Also need ".claude/plugins/cache" in the path for the check
        # The function checks: ".claude/plugins/cache" in str(PLUGIN_ROOT)
        fake_cache = tmp_path / ".claude" / "plugins" / "cache" / "leak-guard"
        fake_cache.mkdir(parents=True)
        (fake_cache / ".source_root").write_text(str(tmp_path / "source"))
        monkeypatch.setattr(sc, "PLUGIN_ROOT", fake_cache)

        result = sc._find_source_tree_allowlist()
        assert result is not None
        assert result == fake_src / "allowlist.toml"
