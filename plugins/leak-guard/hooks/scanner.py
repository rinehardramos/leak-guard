#!/usr/bin/env python3
"""
leak-guard scanner — local-first PII & secret scanner for Claude Code.

Subcommands:
  hook-user-prompt     UserPromptSubmit hook (stdin=event JSON)
  hook-pre-tool        PreToolUse hook
  hook-post-tool       PostToolUse hook
  hook-session-start   SessionStart hook
  scan-path <path>     Scan a file or directory (for /scan-leaks skill)
  scan-text            Scan stdin text (for pre-push git hook)
  install-githook      Install pre-push git hook into current repo
  selftest             Run internal smoke tests

Fail-closed: any unhandled error blocks the action.
Stdlib only. Shells out to `gitleaks` for secret detection.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────────────────────────────────
# Paths & constants
# ──────────────────────────────────────────────────────────────────────────

PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", Path(__file__).resolve().parent.parent))
RULES_DIR = PLUGIN_ROOT / "rules"
GIT_HOOKS_DIR = PLUGIN_ROOT / "git-hooks"

STATE_DIR = Path(os.environ.get("LEAK_GUARD_STATE_DIR", Path.home() / ".claude" / "leak-guard"))
AUDIT_LOG = STATE_DIR / "audit.log"
USER_ALLOWLIST = STATE_DIR / "allowlist.toml"

# Severity → policy
SECRET_CATEGORIES = {"secret", "credential", "cloud-key", "private-key"}
PII_CATEGORIES = {"pii"}

# Claude Code tools we scan. Others pass through untouched.
PRE_TOOL_SCAN_INPUT = {"Bash", "Write", "Edit", "WebFetch", "WebSearch"}
PRE_TOOL_BLOCK_BY_PATH = {"Read", "NotebookEdit"}  # block sensitive filenames before reading
POST_TOOL_SCAN_OUTPUT = {"Read", "Grep", "Bash", "NotebookEdit"}


# ──────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    category: str          # "secret" | "pii" | "filename"
    description: str
    line: int              # 1-indexed; 0 if not applicable
    preview: str           # redacted preview, never raw match
    severity: str = "medium"
    source: str = ""       # file path or "<prompt>" / "<bash>" etc.

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "description": self.description,
            "line": self.line,
            "preview": self.preview,
            "severity": self.severity,
            "source": self.source,
        }


@dataclass
class PiiRule:
    id: str
    description: str
    regex: re.Pattern
    severity: str = "medium"
    luhn: bool = False  # credit card validation


@dataclass
class Allowlist:
    literal: set[str] = field(default_factory=set)
    rule_ids: set[str] = field(default_factory=set)        # globally suppressed rule ids
    path_globs: list[str] = field(default_factory=list)    # paths where all rules are suppressed


# ──────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────

def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not AUDIT_LOG.exists():
        AUDIT_LOG.touch()


def audit(event: str, payload: dict[str, Any]) -> None:
    """Append one JSON line to audit log. Never raises."""
    try:
        ensure_state_dir()
        entry = {"ts": time.time(), "event": event, **payload}
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:16]


def redact_preview(match: str, kind: str) -> str:
    """Produce a safe preview — never the raw match."""
    if len(match) <= 4:
        return f"[REDACTED:{kind}]"
    return f"[REDACTED:{kind}:{len(match)}ch:hash={sha256(match)[:8]}]"


def luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def find_gitleaks() -> str | None:
    return shutil.which("gitleaks")


# ──────────────────────────────────────────────────────────────────────────
# Rule loading
# ──────────────────────────────────────────────────────────────────────────

def load_pii_rules() -> list[PiiRule]:
    path = RULES_DIR / "pii.toml"
    if not path.exists():
        return []
    with path.open("rb") as f:
        data = tomllib.load(f)
    rules: list[PiiRule] = []
    for entry in data.get("rule", []):
        try:
            rules.append(PiiRule(
                id=entry["id"],
                description=entry.get("description", entry["id"]),
                regex=re.compile(entry["regex"]),
                severity=entry.get("severity", "medium"),
                luhn=entry.get("luhn", False),
            ))
        except (KeyError, re.error) as e:
            audit("rule_load_error", {"rule": entry.get("id", "?"), "error": str(e)})
    return rules


def load_filename_blocklist() -> list[str]:
    path = RULES_DIR / "filenames.txt"
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def load_allowlist() -> Allowlist:
    allow = Allowlist()
    # Plugin default
    default = RULES_DIR / "allowlist.toml"
    # User override
    for src in (default, USER_ALLOWLIST):
        if not src.exists():
            continue
        try:
            with src.open("rb") as f:
                data = tomllib.load(f)
            allow.literal.update(data.get("literal", []))
            allow.rule_ids.update(data.get("rule_ids", []))
            allow.path_globs.extend(data.get("path_globs", []))
        except Exception as e:
            audit("allowlist_load_error", {"src": str(src), "error": str(e)})
    return allow


def path_allowlisted(path: str, allow: Allowlist) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in allow.path_globs)


# ──────────────────────────────────────────────────────────────────────────
# Scanners
# ──────────────────────────────────────────────────────────────────────────

def scan_filename(path: str, blocklist: list[str]) -> list[Finding]:
    name = Path(path).name
    findings: list[Finding] = []
    for pattern in blocklist:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path, pattern):
            findings.append(Finding(
                rule_id="sensitive-filename",
                category="filename",
                description=f"Sensitive file pattern matched: {pattern}",
                line=0,
                preview=f"[FILENAME:{name}]",
                severity="high",
                source=path,
            ))
            break
    return findings


def scan_pii_text(text: str, rules: list[PiiRule], allow: Allowlist,
                  source: str = "") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings
    lines = text.splitlines() or [text]
    for rule in rules:
        if rule.id in allow.rule_ids:
            continue
        for m in rule.regex.finditer(text):
            matched = m.group(0)
            if matched in allow.literal:
                continue
            if rule.luhn and not luhn_valid(matched):
                continue
            # Locate line number
            upto = text[:m.start()]
            line_no = upto.count("\n") + 1
            findings.append(Finding(
                rule_id=rule.id,
                category="pii",
                description=rule.description,
                line=line_no,
                preview=redact_preview(matched, rule.id),
                severity=rule.severity,
                source=source,
            ))
    return findings


def scan_secrets_gitleaks(text: str | None = None, path: str | None = None,
                          source_label: str = "") -> list[Finding]:
    """Run gitleaks in no-git mode. Returns findings.

    Gitleaks exit codes: 0=no leaks, 1=leaks found, other=error.
    On missing gitleaks → fail-closed: return a synthetic error finding.
    """
    gl = find_gitleaks()
    if not gl:
        return [Finding(
            rule_id="leak-guard-error",
            category="secret",
            description="gitleaks not installed — fail-closed. Run: brew install gitleaks",
            line=0,
            preview="[ERROR]",
            severity="critical",
            source=source_label or path or "",
        )]

    try:
        if path is not None:
            p = Path(path)
            if p.is_file():
                # Pipe file content — avoids scanning siblings in the parent dir.
                file_text = p.read_text(errors="replace")
                cmd = [
                    gl, "detect", "--pipe",
                    "--report-format", "json", "--report-path", "-",
                    "--exit-code", "0", "--no-banner",
                ]
                result = subprocess.run(cmd, input=file_text, capture_output=True,
                                        text=True, timeout=30)
                raw_json = result.stdout or "[]"
            elif p.is_dir():
                report_f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
                report_f.close()
                report_path = Path(report_f.name)
                cmd = [
                    gl, "detect", "--no-git", "--source", str(p),
                    "--report-format", "json", "--report-path", str(report_path),
                    "--exit-code", "0", "--no-banner",
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                raw_json = report_path.read_text() if report_path.exists() else "[]"
                try:
                    report_path.unlink(missing_ok=True)
                except Exception:
                    pass
            else:
                return []  # path doesn't exist yet; nothing to scan
        else:
            # In-memory text: pipe via stdin (most reliable across gitleaks versions)
            cmd = [
                gl, "detect", "--pipe",
                "--report-format", "json", "--report-path", "-",
                "--exit-code", "0", "--no-banner",
            ]
            result = subprocess.run(cmd, input=text or "", capture_output=True,
                                    text=True, timeout=30)
            raw_json = result.stdout or "[]"

        findings: list[Finding] = []
        try:
            data = json.loads(raw_json) if raw_json.strip() else []
        except json.JSONDecodeError:
            data = []

        for item in data:
            rule_id = item.get("RuleID", "unknown-secret")
            # Never store the raw secret — use a length+hash preview
            raw = item.get("Secret", "") or item.get("Match", "") or "x"
            findings.append(Finding(
                rule_id=rule_id,
                category="secret",
                description=item.get("Description", rule_id),
                line=int(item.get("StartLine", 0) or 0),
                preview=redact_preview(raw, rule_id),
                severity="critical",
                source=source_label or item.get("File", str(path or "<text>")),
            ))

        if result.returncode not in (0, 1):
            audit("gitleaks_error", {"rc": result.returncode, "stderr": result.stderr[:500]})
        return findings

    except subprocess.TimeoutExpired:
        audit("gitleaks_timeout", {"target": source_label or str(path)})
        return [Finding(
            rule_id="leak-guard-timeout",
            category="secret",
            description="gitleaks scan timed out — fail-closed",
            line=0, preview="[TIMEOUT]", severity="critical",
            source=source_label or str(path or ""),
        )]


def scan_all(text: str | None = None, path: str | None = None,
             source_label: str = "") -> list[Finding]:
    allow = load_allowlist()
    findings: list[Finding] = []
    pii_rules = load_pii_rules()

    # 1. Filename check (path-based only)
    if path:
        if path_allowlisted(path, allow):
            return []
        findings.extend(scan_filename(path, load_filename_blocklist()))

    # 2. Secrets via gitleaks
    findings.extend(scan_secrets_gitleaks(text=text, path=path, source_label=source_label or path or "<text>"))

    # 3. PII via regex
    if text is not None:
        findings.extend(scan_pii_text(text, pii_rules, allow, source=source_label))
    elif path is not None and Path(path).is_file():
        try:
            content = Path(path).read_text(errors="replace")
            findings.extend(scan_pii_text(content, pii_rules, allow, source=path))
        except Exception:
            pass

    return findings


def classify(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Return (secrets, pii_and_filename)."""
    secrets = [f for f in findings if f.category in SECRET_CATEGORIES or f.category == "secret"]
    pii = [f for f in findings if f.category in PII_CATEGORIES or f.category == "filename"]
    return secrets, pii


def format_summary(findings: list[Finding], max_items: int = 10) -> str:
    if not findings:
        return "no findings"
    lines = []
    for f in findings[:max_items]:
        loc = f" line {f.line}" if f.line else ""
        src = f" in {f.source}" if f.source else ""
        lines.append(f"  · [{f.severity}] {f.rule_id} — {f.description}{loc}{src} {f.preview}")
    if len(findings) > max_items:
        lines.append(f"  … and {len(findings) - max_items} more")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────
# Hook handlers
# ──────────────────────────────────────────────────────────────────────────

def emit_pre_tool(decision: str, reason: str, updated_input: dict | None = None) -> None:
    out: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if updated_input is not None:
        out["hookSpecificOutput"]["updatedInput"] = updated_input
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


def emit_post_tool_block(reason: str) -> None:
    out = {"decision": "block", "reason": reason}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


def emit_prompt_block(reason: str) -> None:
    out = {"decision": "block", "reason": reason}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


def hook_user_prompt() -> int:
    event = read_event()
    prompt = event.get("prompt", "") or ""
    findings = scan_all(text=prompt, source_label="<user-prompt>")
    secrets, pii = classify(findings)
    if secrets:
        audit("block_user_prompt_secret", {"count": len(secrets)})
        emit_prompt_block(
            "leak-guard: secrets detected in your prompt. Please remove them before submitting.\n"
            + format_summary(secrets)
        )
        return 0
    if pii:
        audit("block_user_prompt_pii", {"count": len(pii)})
        emit_prompt_block(
            "leak-guard: PII detected in your prompt. Rephrase, redact, or add to allowlist "
            f"(~/.claude/leak-guard/allowlist.toml).\n{format_summary(pii)}"
        )
        return 0
    return 0


def hook_pre_tool() -> int:
    event = read_event()
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}

    # 1. Path-based blocking for file-reading tools
    if tool in PRE_TOOL_BLOCK_BY_PATH:
        fpath = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if fpath:
            allow = load_allowlist()
            if not path_allowlisted(fpath, allow):
                fn_findings = scan_filename(fpath, load_filename_blocklist())
                if fn_findings:
                    audit("deny_pre_tool_filename", {"tool": tool, "path": fpath})
                    emit_pre_tool(
                        "deny",
                        f"leak-guard: sensitive file blocked ({fpath}).\n{format_summary(fn_findings)}"
                    )
                    return 0
        return 0  # silent allow (zero tokens)

    # 2. Input-content scanning for write/exec/outbound tools
    if tool in PRE_TOOL_SCAN_INPUT:
        text = _extract_scannable_text(tool, tool_input)
        if text:
            findings = scan_all(text=text, source_label=f"<{tool}-input>")
            secrets, pii = classify(findings)
            if secrets:
                audit("deny_pre_tool_secret", {"tool": tool, "count": len(secrets)})
                emit_pre_tool(
                    "deny",
                    f"leak-guard: secrets in {tool} input — blocked.\n{format_summary(secrets)}"
                )
                return 0
            if pii:
                audit("ask_pre_tool_pii", {"tool": tool, "count": len(pii)})
                emit_pre_tool(
                    "ask",
                    f"leak-guard: PII detected in {tool} input. Allow, deny, or cancel?\n"
                    f"{format_summary(pii)}\n"
                    "To always allow similar: add to ~/.claude/leak-guard/allowlist.toml"
                )
                return 0
    return 0  # silent allow (zero tokens)


def _extract_scannable_text(tool: str, tool_input: dict) -> str:
    if tool == "Bash":
        return tool_input.get("command", "") or ""
    if tool in ("Write", "Edit"):
        # Write: content; Edit: new_string + old_string
        return "\n".join(str(tool_input.get(k, "") or "")
                         for k in ("content", "new_string", "old_string"))
    if tool == "WebFetch":
        return f"{tool_input.get('url','')}\n{tool_input.get('prompt','')}"
    if tool == "WebSearch":
        return tool_input.get("query", "") or ""
    return ""


def hook_post_tool() -> int:
    event = read_event()
    tool = event.get("tool_name", "")
    if tool not in POST_TOOL_SCAN_OUTPUT:
        return 0
    response = event.get("tool_response", {})
    text = _extract_response_text(tool, response)
    if not text:
        return 0
    source = _extract_response_source(tool, event.get("tool_input", {}) or {})
    findings = scan_all(text=text, source_label=source)
    if not findings:
        return 0
    secrets, pii = classify(findings)
    if secrets:
        audit("block_post_tool_secret", {"tool": tool, "source": source, "count": len(secrets)})
        emit_post_tool_block(
            f"leak-guard BLOCKED {tool} output from {source}: secrets present. "
            f"Content withheld from context.\n{format_summary(secrets)}\n"
            "Action: remove secrets from the source, add the path to allowlist, or scan explicitly with /scan-leaks."
        )
        return 0
    if pii:
        audit("block_post_tool_pii", {"tool": tool, "source": source, "count": len(pii)})
        emit_post_tool_block(
            f"leak-guard BLOCKED {tool} output from {source}: PII present. "
            f"Content withheld.\n{format_summary(pii)}\n"
            "Action: rephrase the query, or add the path/rule to ~/.claude/leak-guard/allowlist.toml."
        )
        return 0
    return 0


def _extract_response_text(tool: str, response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        for key in ("content", "output", "stdout", "text", "result"):
            v = response.get(key)
            if isinstance(v, str) and v:
                return v
        # Grep: { matches: [...] } or similar — fall back to JSON dump
        return json.dumps(response, default=str)
    return str(response)


def _extract_response_source(tool: str, tool_input: dict) -> str:
    if tool == "Read":
        return tool_input.get("file_path", "<read>")
    if tool == "Bash":
        cmd = (tool_input.get("command") or "")[:60]
        return f"<bash:{cmd}>"
    if tool == "Grep":
        return f"<grep:{tool_input.get('pattern','')[:40]}>"
    return f"<{tool}>"


def hook_session_start() -> int:
    event = read_event()
    cwd = event.get("cwd", os.getcwd())
    gl = find_gitleaks()
    ctx_parts = ["leak-guard v0.1.0 active: hooks armed for secrets + PII."]
    if not gl:
        ctx_parts.append("⚠ gitleaks not installed — secret detection will fail-closed. Run: brew install gitleaks")
    # Quick filename scan (no content scan to stay fast)
    try:
        blocklist = load_filename_blocklist()
        hits = []
        for root, dirs, files in os.walk(cwd):
            # Skip heavy / vendored dirs
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv", "dist", "build", ".next"}]
            for f in files:
                fp = os.path.join(root, f)
                if scan_filename(fp, blocklist):
                    hits.append(os.path.relpath(fp, cwd))
                    if len(hits) >= 20:
                        break
            if len(hits) >= 20:
                break
        if hits:
            ctx_parts.append(f"⚠ Sensitive filenames present (excluded from Read): {', '.join(hits[:10])}"
                             + (f" (+{len(hits)-10} more)" if len(hits) > 10 else ""))
    except Exception:
        pass
    out = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "\n".join(ctx_parts),
        }
    }
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    return 0


# ──────────────────────────────────────────────────────────────────────────
# CLI (non-hook) subcommands
# ──────────────────────────────────────────────────────────────────────────

def cmd_scan_path(target: str) -> int:
    p = Path(target).resolve()
    if not p.exists():
        print(f"leak-guard: path not found: {p}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    if p.is_file():
        findings.extend(scan_all(path=str(p), source_label=str(p)))
    else:
        # Directory: single gitleaks run on the whole tree + per-file PII scan
        findings.extend(scan_secrets_gitleaks(path=str(p), source_label=str(p)))
        pii_rules = load_pii_rules()
        allow = load_allowlist()
        blocklist = load_filename_blocklist()
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "target"}]
            for fn in files:
                fp = Path(root) / fn
                rel = str(fp)
                if path_allowlisted(rel, allow):
                    continue
                findings.extend(scan_filename(rel, blocklist))
                try:
                    if fp.stat().st_size > 2_000_000:
                        continue
                    content = fp.read_text(errors="replace")
                except Exception:
                    continue
                findings.extend(scan_pii_text(content, pii_rules, allow, source=rel))

    print(f"leak-guard scan: {p}")
    print(f"findings: {len(findings)}")
    if findings:
        print(format_summary(findings, max_items=50))
        return 1
    print("  ✓ clean")
    return 0


def cmd_scan_text() -> int:
    text = sys.stdin.read()
    findings = scan_all(text=text, source_label="<stdin>")
    if findings:
        print(format_summary(findings, max_items=50), file=sys.stderr)
        return 1
    return 0


def cmd_install_githook() -> int:
    repo = Path.cwd()
    git_dir = repo / ".git"
    if not git_dir.exists():
        print(f"leak-guard: not a git repo: {repo}", file=sys.stderr)
        return 2
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    src = GIT_HOOKS_DIR / "pre-push"
    if not src.exists():
        print(f"leak-guard: pre-push template missing at {src}", file=sys.stderr)
        return 2
    dst = hooks_dir / "pre-push"
    if dst.exists():
        backup = dst.with_suffix(".leak-guard-backup")
        shutil.copy2(dst, backup)
        print(f"leak-guard: existing pre-push backed up to {backup}")
    shutil.copy2(src, dst)
    dst.chmod(0o755)
    print(f"leak-guard: installed pre-push hook at {dst}")
    return 0


def cmd_git_hook_pre_push() -> int:
    """Invoked from .git/hooks/pre-push. Scans HEAD vs upstream diff."""
    # Read refs from stdin per git's pre-push protocol
    refs = sys.stdin.read().strip().splitlines()
    if not refs:
        return 0
    findings: list[Finding] = []
    # Simpler approach: run gitleaks protect on staged + new commits
    gl = find_gitleaks()
    if not gl:
        print("leak-guard pre-push: gitleaks missing — BLOCKED (install with: brew install gitleaks)", file=sys.stderr)
        return 1
    # Scan commits being pushed
    for line in refs:
        parts = line.split()
        if len(parts) < 4:
            continue
        local_sha = parts[1]
        remote_sha = parts[3]
        if local_sha == "0000000000000000000000000000000000000000":
            continue
        if remote_sha == "0000000000000000000000000000000000000000":
            # New branch — scan last 50 commits
            log_range = f"{local_sha}~50..{local_sha}"
        else:
            log_range = f"{remote_sha}..{local_sha}"
        try:
            result = subprocess.run(
                [gl, "detect", "--log-opts", log_range, "--no-banner", "--redact",
                 "--report-format", "json", "--report-path", "/dev/stdout", "--exit-code", "0"],
                capture_output=True, text=True, timeout=60, cwd=os.getcwd(),
            )
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for item in data:
                        findings.append(Finding(
                            rule_id=item.get("RuleID", "secret"),
                            category="secret",
                            description=item.get("Description", ""),
                            line=int(item.get("StartLine", 0) or 0),
                            preview=f"[REDACTED:{item.get('RuleID','secret')}]",
                            severity="critical",
                            source=item.get("File", ""),
                        ))
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            print("leak-guard pre-push: gitleaks timed out — BLOCKED", file=sys.stderr)
            return 1

    if findings:
        print("leak-guard pre-push: SECRETS DETECTED — push blocked.", file=sys.stderr)
        print(format_summary(findings, max_items=50), file=sys.stderr)
        print("", file=sys.stderr)
        print("Remove the secrets, amend or rewrite the offending commits, then push again.", file=sys.stderr)
        print("To bypass (NOT RECOMMENDED): git push --no-verify", file=sys.stderr)
        return 1
    return 0


# ──────────────────────────────────────────────────────────────────────────
# Hook I/O
# ──────────────────────────────────────────────────────────────────────────

def read_event() -> dict:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return {}
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


# ──────────────────────────────────────────────────────────────────────────
# Self-test
# ──────────────────────────────────────────────────────────────────────────

def cmd_selftest() -> int:
    failures = 0
    def check(name: str, ok: bool, detail: str = ""):
        nonlocal failures
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
        if not ok:
            failures += 1

    print("leak-guard selftest")
    # 1. Rule loading
    pii_rules = load_pii_rules()
    check("pii rules load", len(pii_rules) > 0, f"{len(pii_rules)} rules")

    # 2. Email detection
    allow = Allowlist()
    f = scan_pii_text("contact: alice@example.com please", pii_rules, allow)
    check("email detected", any(x.rule_id == "email" for x in f))

    # 3. SSN detection
    f = scan_pii_text("SSN: 123-45-6789", pii_rules, allow)
    check("ssn detected", any(x.rule_id == "us-ssn" for x in f))

    # 4. Luhn filter — bad CC not detected
    f = scan_pii_text("card 1234 5678 9012 3456", pii_rules, allow)
    check("luhn rejects bad CC", not any(x.rule_id == "credit-card" for x in f))

    # 5. Luhn accepts valid CC
    f = scan_pii_text("card 4242 4242 4242 4242", pii_rules, allow)
    check("luhn accepts valid CC", any(x.rule_id == "credit-card" for x in f))

    # 6. Filename blocklist
    f = scan_filename("/tmp/.env", load_filename_blocklist())
    check("filename .env blocked", len(f) > 0)
    f = scan_filename("/tmp/id_rsa", load_filename_blocklist())
    check("filename id_rsa blocked", len(f) > 0)

    # 7. gitleaks available
    check("gitleaks installed", find_gitleaks() is not None,
          find_gitleaks() or "MISSING — brew install gitleaks")

    # 8. gitleaks catches AWS key (use a structurally valid fake, not the canonical
    #    AKIAIOSFODNN7EXAMPLE which gitleaks allowlists internally)
    if find_gitleaks():
        fake = 'AWS_ACCESS_KEY_ID=AKIAY3FDSNDKFKSIDJSW\n'
        f = scan_secrets_gitleaks(text=fake, source_label="<test>")
        check("gitleaks detects AWS key", len(f) > 0, f"found {len(f)}")

    # 9. Classify
    mixed = [Finding("aws", "secret", "", 0, "[R]"), Finding("email", "pii", "", 0, "[R]")]
    s, p = classify(mixed)
    check("classify splits secret/pii", len(s) == 1 and len(p) == 1)

    # 10. Allowlist path glob
    al = Allowlist(path_globs=["*/fixtures/*"])
    check("path allowlist glob", path_allowlisted("/x/fixtures/a.txt", al))

    print(f"\n{'OK' if failures == 0 else 'FAILED'}: {failures} failure(s)")
    return 0 if failures == 0 else 1


# ──────────────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="leak-guard")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("hook-user-prompt")
    sub.add_parser("hook-pre-tool")
    sub.add_parser("hook-post-tool")
    sub.add_parser("hook-session-start")
    sp = sub.add_parser("scan-path"); sp.add_argument("path")
    sub.add_parser("scan-text")
    sub.add_parser("install-githook")
    sub.add_parser("git-hook-pre-push")
    sub.add_parser("selftest")

    args = parser.parse_args(argv)

    try:
        ensure_state_dir()
        if args.cmd == "hook-user-prompt":
            return hook_user_prompt()
        if args.cmd == "hook-pre-tool":
            return hook_pre_tool()
        if args.cmd == "hook-post-tool":
            return hook_post_tool()
        if args.cmd == "hook-session-start":
            return hook_session_start()
        if args.cmd == "scan-path":
            return cmd_scan_path(args.path)
        if args.cmd == "scan-text":
            return cmd_scan_text()
        if args.cmd == "install-githook":
            return cmd_install_githook()
        if args.cmd == "git-hook-pre-push":
            return cmd_git_hook_pre_push()
        if args.cmd == "selftest":
            return cmd_selftest()
    except Exception as e:
        audit("scanner_exception", {"cmd": args.cmd, "error": str(e), "tb": traceback.format_exc()[:2000]})
        # Fail-closed for hook events; pass-through for CLI
        if args.cmd.startswith("hook-"):
            if args.cmd == "hook-pre-tool":
                emit_pre_tool("deny", f"leak-guard internal error (fail-closed): {e}")
            elif args.cmd == "hook-user-prompt":
                emit_prompt_block(f"leak-guard internal error (fail-closed): {e}")
            elif args.cmd == "hook-post-tool":
                emit_post_tool_block(f"leak-guard internal error (fail-closed): {e}")
            else:
                print(f"leak-guard error: {e}", file=sys.stderr)
            return 0
        print(f"leak-guard error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
