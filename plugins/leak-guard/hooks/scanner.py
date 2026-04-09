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
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# Vendored `tomli` (MIT, https://github.com/hukkin/tomli) lives next to this
# file in _vendor/ and serves as the cross-platform fallback for Python < 3.11.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "_vendor"))

try:
    import tomllib          # stdlib ≥ 3.11
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]  # vendored backport
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
CUSTOM_RULES_FILE = STATE_DIR / "custom_rules.toml"

# Severity → policy
SECRET_CATEGORIES = {"secret", "credential", "cloud-key", "private-key"}
PII_CATEGORIES = {"pii"}

# Claude Code tools we scan. Others pass through untouched.
PRE_TOOL_SCAN_INPUT = {"Bash", "Write", "Edit", "WebFetch", "WebSearch"}
PRE_TOOL_BLOCK_BY_PATH = {"Read", "NotebookEdit"}  # block sensitive filenames before reading
POST_TOOL_SCAN_OUTPUT = {"Read", "Bash", "NotebookEdit"}


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
    silent_blocks: bool = False                             # suppress stderr user notifications


# ──────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────

def ensure_state_dir() -> None:
    if STATE_DIR.exists():
        STATE_DIR.chmod(0o700)
    else:
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not AUDIT_LOG.exists():
        AUDIT_LOG.touch()
        AUDIT_LOG.chmod(0o600)


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


def _allowlist_mtime() -> float:
    """Combined mtime of both allowlist files — changes when either file is edited."""
    total = 0.0
    for src in (RULES_DIR / "allowlist.toml", USER_ALLOWLIST):
        try:
            total += src.stat().st_mtime
        except OSError:
            pass
    return total


_allowlist_cache: dict[str, object] = {"mtime": -1.0, "data": None}


def load_allowlist() -> Allowlist:
    mtime = _allowlist_mtime()
    if _allowlist_cache["mtime"] == mtime and _allowlist_cache["data"] is not None:
        return _allowlist_cache["data"]  # type: ignore[return-value]

    allow = Allowlist()
    default = RULES_DIR / "allowlist.toml"
    for src in (default, USER_ALLOWLIST):
        if not src.exists():
            continue
        try:
            with src.open("rb") as f:
                data = tomllib.load(f)
            allow.literal.update(data.get("literal", []))
            allow.rule_ids.update(data.get("rule_ids", []))
            allow.path_globs.extend(data.get("path_globs", []))
            if src == USER_ALLOWLIST:
                allow.silent_blocks = bool(data.get("silent_blocks", False))
        except Exception as e:
            audit("allowlist_load_error", {"src": str(src), "error": str(e)})

    _allowlist_cache["mtime"] = mtime
    _allowlist_cache["data"] = allow
    return allow


def path_allowlisted(path: str, allow: Allowlist) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in allow.path_globs)


# ──────────────────────────────────────────────────────────────────────────
# Custom rules (user-defined patterns / keywords / prefixes)
# ──────────────────────────────────────────────────────────────────────────

_custom_rules_cache: dict = {"mtime": -1.0, "data": None}


def _custom_rules_mtime() -> float:
    try:
        return CUSTOM_RULES_FILE.stat().st_mtime
    except OSError:
        return 0.0


def load_custom_rules() -> dict:
    mtime = _custom_rules_mtime()
    if _custom_rules_cache["mtime"] == mtime and _custom_rules_cache["data"] is not None:
        return _custom_rules_cache["data"]
    data: dict = {"pattern": [], "context_keyword": [], "fuzzy_prefix": []}
    if CUSTOM_RULES_FILE.exists():
        try:
            with CUSTOM_RULES_FILE.open("rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            audit("custom_rules_load_error", {"error": str(e)})
    _custom_rules_cache["mtime"] = mtime
    _custom_rules_cache["data"] = data
    return data


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
    text = _normalize_text(text)
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
            # Suppress dummy/placeholder RHS for assignment-style rules
            # (e.g. `password=helloworld`, `api_key="changeme"`).
            if "=" in matched or ":" in matched:
                rhs = re.split(r"[:=]", matched, maxsplit=1)[-1]
                if _is_dummy_value(rhs):
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


def _shannon_entropy(s: str) -> float:
    """Bits-per-character Shannon entropy."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


# Charset patterns for high-entropy token candidates.
# base64url: A-Za-z0-9+/=_ and - (covers bearer tokens, JWT segments, API keys)
# hex: 0-9a-f (covers commit hashes, UUIDs stripped of dashes, raw keys)
_B64_RE = re.compile(r'[A-Za-z0-9+/=_~-]{20,}')
_HEX_RE = re.compile(r'\b[0-9a-fA-F]{32,}\b')

# Entropy thresholds (bits/char). Tuned to catch real tokens while avoiding
# English prose (entropy ~3.5) and short random words.
_B64_ENTROPY_MIN = 4.5   # base64 random data: ~5.8 bits/char
_HEX_ENTROPY_MIN = 3.5   # hex random data: ~3.9 bits/char; lowercase words: ~3.2

# Skip strings that look like common non-secret base64 (e.g. long URLs, UUIDs).
_URL_RE = re.compile(r'https?://', re.I)

# Context keywords adjacent to the candidate that strongly suggest a secret.
# We use these to *lower* the entropy threshold when present.
# Frozenset lookup is faster than a compiled regex for short keyword lists.
# All entries are lowercase; callers must lower() the window before checking.
_SECRET_CONTEXT_KEYWORDS: frozenset[str] = frozenset({
    # Full words
    "secret", "token", "password", "passwd", "pswd",
    "credential", "cred", "bearer", "auth",
    "private_key", "privkey", "access_key", "enc_key", "api_key", "apikey",
    # Common abbreviations
    "pass", "pwd", "pk", "sk", "pat", "jwt", "oauth", "psk",
})


# ──────────────────────────────────────────────────────────────────────────────
# Known dummy / placeholder values — suppresses FPs on obvious non-secrets like
# `password=helloworld` or `api_key=changeme`. Strings are stored normalized
# (lowercased, surrounding quotes stripped). Keep this list conservative:
# every entry must be something that would NEVER be a real credential in
# production code.
# ──────────────────────────────────────────────────────────────────────────────
_KNOWN_DUMMY_VALUES: frozenset[str] = frozenset({
    # Canonical weak passwords / placeholders
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "123456", "12345678", "qwerty", "qwerty123", "letmein", "welcome",
    "admin", "admin123", "root", "toor", "default", "changeme", "change_me",
    "hunter2", "iloveyou", "dragon", "monkey", "master", "superman",
    # Generic placeholders
    "helloworld", "hello_world", "foo", "foobar", "bar", "baz", "qux",
    "test", "test123", "testing", "tester", "example", "sample", "demo",
    "placeholder", "redacted", "xxxxxx", "xxxxxxxx", "yyyyyy", "zzzzzz",
    "todo", "tbd", "none", "null", "undefined", "empty", "blank",
    # Explicit "not real" markers
    "fake", "dummy", "invalid", "mock", "stub", "fixture",
    "your_password_here", "your_token_here", "your_key_here",
    "your_secret_here", "your_api_key_here",
    "insert_password_here", "insert_token_here", "insert_key_here",
})

# Structural placeholder patterns — things like `<your-key>`, `{{API_KEY}}`,
# `$SECRET`, `${TOKEN}`. Matches wrappers that are unambiguously templating.
_PLACEHOLDER_SHAPE_RE = re.compile(
    r"""^(
        <[^<>]{1,80}>              # <your-key>
      | \{\{[^{}]{1,80}\}\}        # {{API_KEY}}
      | \$\{[^${}]{1,80}\}         # ${TOKEN}
      | \$[A-Z_][A-Z0-9_]{0,40}    # $SECRET_TOKEN
      | %[A-Z_][A-Z0-9_]{0,40}%    # %TOKEN%
    )$""",
    re.VERBOSE,
)


def _normalize_dummy_candidate(val: str) -> str:
    """Lowercase and strip surrounding quotes/whitespace for dummy-set lookup."""
    return val.strip().strip("'\"`").strip().lower()


def _is_dummy_value(val: str) -> bool:
    """Return True if *val* is an obvious placeholder / non-secret.

    Two checks:
    1. Exact match (normalized) against _KNOWN_DUMMY_VALUES.
    2. Structural placeholder shapes like <...>, {{...}}, ${...}, $VAR.
    """
    norm = _normalize_dummy_candidate(val)
    if not norm:
        return True
    if norm in _KNOWN_DUMMY_VALUES:
        return True
    # Runs of a single character (xxxxxxxx, 00000000, ********)
    if len(norm) >= 4 and len(set(norm)) == 1:
        return True
    if _PLACEHOLDER_SHAPE_RE.match(val.strip()):
        return True
    return False


# Characters that are purely visual/directional and should be stripped
# before any scanning — zero-width spaces, bidi controls, BOM.
_STRIP_UNICODE_RE = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f'
    r'\u202a\u202b\u202c\u202d\u202e'
    r'\u2066\u2067\u2068\u2069\ufeff]'
)


def _normalize_text(text: str) -> str:
    """NFKC-normalize and strip bidi/zero-width control characters."""
    import unicodedata
    text = unicodedata.normalize('NFKC', text)
    text = _STRIP_UNICODE_RE.sub('', text)
    return text


def _has_secret_context(window: str) -> bool:
    """Return True if any secret-context keyword appears in *window* (case-insensitive)."""
    lower = window.lower()
    if any(kw in lower for kw in _SECRET_CONTEXT_KEYWORDS):
        return True
    custom = load_custom_rules()
    return any(entry.get("word", "") in lower for entry in custom.get("context_keyword", []))


def scan_entropy(text: str, allow: Allowlist, source: str = "") -> list[Finding]:
    """Detect standalone high-entropy strings that look like tokens or keys."""
    if not text:
        return []
    text = _normalize_text(text)
    findings: list[Finding] = []
    seen: set[str] = set()

    def _check(m: re.Match, charset: str, threshold: float) -> None:
        candidate = m.group(0)
        if candidate in seen or candidate in allow.literal:
            return
        if _is_dummy_value(candidate):
            return
        # Skip plain URLs
        start = max(0, m.start() - 8)
        prefix = text[start:m.start()]
        if _URL_RE.search(prefix):
            return
        ent = _shannon_entropy(candidate)
        # Lower threshold when a secret-like keyword appears within 60 chars
        ctx_window = text[max(0, m.start() - 60):m.end() + 60]
        effective_threshold = threshold - 0.7 if _has_secret_context(ctx_window) else threshold
        if ent < effective_threshold:
            return
        seen.add(candidate)
        upto = text[:m.start()]
        line_no = upto.count("\n") + 1
        findings.append(Finding(
            rule_id=f"high-entropy-{charset}",
            category="pii",
            description=f"High-entropy {charset} string (entropy={ent:.2f} bits/char) — possible token/key",
            line=line_no,
            preview=redact_preview(candidate, f"entropy-{charset}"),
            severity="high",
            source=source,
        ))

    for m in _B64_RE.finditer(text):
        _check(m, "base64", _B64_ENTROPY_MIN)
    for m in _HEX_RE.finditer(text):
        _check(m, "hex", _HEX_ENTROPY_MIN)

    return findings


# Matches PREFIX:value where PREFIX is 2-12 uppercase alphanum chars and value
# is 10+ mixed alphanumeric chars.  Catches custom credential schemes like
# "CSKC:ScdsJCCKLSLKDKLCNLKCEINK2233as" that gitleaks has no rule for.
_FUZZY_CRED_RE = re.compile(r'\b([A-Z][A-Z0-9]{1,11}):([A-Za-z0-9+/=_~-]{10,})')


def scan_fuzzy_credentials(text: str, allow: Allowlist, source: str = "") -> list[Finding]:
    """Detect PREFIX:value credential patterns not covered by gitleaks rules."""
    if not text:
        return []
    text = _normalize_text(text)
    findings: list[Finding] = []
    for m in _FUZZY_CRED_RE.finditer(text):
        prefix, value = m.group(1), m.group(2)
        if value in allow.literal:
            continue
        if _is_dummy_value(value):
            continue
        # Require character-class diversity: plain uppercase words (e.g. "NOTE:")
        # and version strings (e.g. "V2:something") are excluded.
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        diversity = sum([has_upper, has_lower, has_digit])
        if diversity < 2:
            continue
        # Skip URLs (already excluded by _URL_RE in entropy scan, replicate here)
        start = max(0, m.start() - 8)
        if _URL_RE.search(text[start:m.start()]):
            continue
        upto = text[:m.start()]
        line_no = upto.count("\n") + 1
        findings.append(Finding(
            rule_id="fuzzy-prefixed-credential",
            category="secret",
            description=f"Possible custom credential with prefix '{prefix}:'",
            line=line_no,
            preview=redact_preview(value, "fuzzy-cred"),
            severity="high",
            source=source,
        ))
    # Custom fuzzy prefix rules from ~/.claude/leak-guard/custom_rules.toml
    custom = load_custom_rules()
    for entry in custom.get("fuzzy_prefix", []):
        prefix = entry.get("prefix", "")
        if not prefix:
            continue
        pat = re.compile(rf'\b{re.escape(prefix)}:([A-Za-z0-9+/=_~-]{{10,}})')
        for m in pat.finditer(text):
            value = m.group(1)
            if value in allow.literal:
                continue
            upto = text[:m.start()]
            findings.append(Finding(
                rule_id=f"custom-prefix-{prefix.lower()}",
                category="secret",
                description=f"Custom credential prefix '{prefix}:'",
                line=upto.count("\n") + 1,
                preview=redact_preview(value, f"custom-{prefix}"),
                severity="high",
                source=source,
            ))
    return findings


# ──────────────────────────────────────────────────────────────────────────
# Fast pure-Python secret patterns (used for real-time prompt/tool hooks).
# Pre-compiled at import time — no subprocess, no disk I/O on the hot path.
# Rule coverage targets the highest-value secret types; gitleaks handles the
# long tail for batch file scans where latency doesn't matter.
# ──────────────────────────────────────────────────────────────────────────

_FAST_RULES: list[tuple[str, re.Pattern, str]] = [
    # (rule_id, pattern, severity)

    # Cloud providers
    ("aws-access-key-id",
     re.compile(r'\bAKIA[0-9A-Z]{16}\b'), "critical"),
    ("aws-secret-access-key",
     re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']?([A-Za-z0-9/+]{40})["\']?'), "critical"),

    # Source-control tokens
    ("github-pat",
     re.compile(r'\bghp_[A-Za-z0-9]{36}\b'), "critical"),
    ("github-oauth",
     re.compile(r'\bgho_[A-Za-z0-9]{36}\b'), "critical"),
    ("github-app-token",
     re.compile(r'\bghs_[A-Za-z0-9]{36}\b'), "critical"),
    ("github-user-token",
     re.compile(r'\bghu_[A-Za-z0-9]{36}\b'), "critical"),
    ("github-fine-grained-pat",
     re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}\b'), "critical"),

    # AI / API services
    ("anthropic-api-key",
     re.compile(r'\bsk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{93,}\b'), "critical"),
    ("openai-api-key",
     re.compile(r'\bsk-proj-[A-Za-z0-9_\-]{50,}\b|\bsk-[A-Za-z0-9]{48}\b'), "critical"),

    # Payment / comms
    ("stripe-secret-key",
     re.compile(r'\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b'), "critical"),
    ("sendgrid-api-key",
     re.compile(r'\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b'), "critical"),
    ("twilio-api-key",
     re.compile(r'\bSK[0-9a-fA-F]{32}\b'), "high"),
    ("slack-token",
     re.compile(r'\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b'), "critical"),

    # Package registries
    ("npm-token",
     re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'), "critical"),
    ("pypi-token",
     re.compile(r'\bpypi-[A-Za-z0-9\-_]{50,}\b'), "critical"),

    # Generic high-signal patterns
    ("google-api-key",
     re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), "critical"),
    ("private-key-header",
     re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "critical"),
    ("jwt-token",
     re.compile(r'\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b'), "high"),
    ("bearer-header",
     re.compile(r'(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*'), "high"),
    ("curl-auth-header",
     re.compile(r"""(?i)-H\s+['"]?Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}"""), "high"),
]


def scan_secrets_fast(text: str, source: str = "") -> list[Finding]:
    """Pure-Python secret scan — zero subprocesses, runs in microseconds.

    Used for real-time hooks (UserPromptSubmit, PreToolUse, PostToolUse).
    """
    if not text:
        return []
    text = _normalize_text(text)
    findings: list[Finding] = []
    for rule_id, pattern, severity in _FAST_RULES:
        for m in pattern.finditer(text):
            matched = m.group(0)
            upto = text[:m.start()]
            findings.append(Finding(
                rule_id=rule_id,
                category="secret",
                description=f"Possible {rule_id.replace('-', ' ')}",
                line=upto.count("\n") + 1,
                preview=redact_preview(matched, rule_id),
                severity=severity,
                source=source,
            ))
    # Custom pattern rules from ~/.claude/leak-guard/custom_rules.toml
    custom = load_custom_rules()
    for rule in custom.get("pattern", []):
        try:
            pat = re.compile(rule["regex"])
        except re.error:
            continue
        for m in pat.finditer(text):
            matched = m.group(0)
            upto = text[:m.start()]
            findings.append(Finding(
                rule_id=rule.get("rule_id", "custom-pattern"),
                category="secret",
                description=rule.get("description", f"Custom rule: {rule.get('rule_id', '')}"),
                line=upto.count("\n") + 1,
                preview=redact_preview(matched, rule.get("rule_id", "custom")),
                severity=rule.get("severity", "high"),
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

    # 2. Secret detection — fast pure-Python path for text, gitleaks for files.
    #    Real-time hooks always supply text; batch file scans supply path.
    #    This keeps the hot path (per-prompt) subprocess-free.
    if text is not None:
        findings.extend(scan_secrets_fast(text, source=source_label))
    if path is not None:
        findings.extend(scan_secrets_gitleaks(path=path, source_label=source_label or path))

    # 3. PII via regex + fuzzy credential patterns
    if text is not None:
        findings.extend(scan_pii_text(text, pii_rules, allow, source=source_label))
        findings.extend(scan_entropy(text, allow, source=source_label))
        findings.extend(scan_fuzzy_credentials(text, allow, source=source_label))
    elif path is not None and Path(path).is_file():
        try:
            content = Path(path).read_text(errors="replace")
            findings.extend(scan_pii_text(content, pii_rules, allow, source=path))
            findings.extend(scan_entropy(content, allow, source=path))
            findings.extend(scan_fuzzy_credentials(content, allow, source=path))
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

def emit_pre_tool(decision: str, reason: str, updated_input: dict | None = None, *, silent: bool = False) -> None:
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
    if not silent and decision in ("deny", "ask"):
        print(f"\n[leak-guard] {reason}", file=sys.stderr)


def emit_post_tool_block(reason: str, *, silent: bool = False) -> None:
    out = {"decision": "block", "reason": reason}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    if not silent:
        print(f"\n[leak-guard] {reason}", file=sys.stderr)


def emit_prompt_block(reason: str, *, silent: bool = False) -> None:
    out = {"decision": "block", "reason": reason}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    if not silent:
        print(f"\n[leak-guard] {reason}", file=sys.stderr)


# Prefix the user can prepend to bypass heuristic (non-gitleaks) findings for one submission.
_ALLOW_ONCE_PREFIX = "[allow-once]"

# Rule IDs produced by heuristics rather than gitleaks — eligible for the ask flow.
_HEURISTIC_RULE_IDS = {"high-entropy-base64", "high-entropy-hex",
                        "assigned-password", "assigned-token",
                        "assigned-api-key", "assigned-secret"}


def _ask_message(findings: list[Finding]) -> str:
    summary = format_summary(findings)
    return (
        "leak-guard: suspicious pattern detected — possible credential or token.\n"
        f"{summary}\n\n"
        "Choose an action and resubmit:\n"
        "  1. Redact  — remove or replace the value in your message (e.g. <REDACTED>)\n"
        "  2. Remove  — delete the sensitive part entirely before sending\n"
        f"  3. Allow once — prepend '{_ALLOW_ONCE_PREFIX}' to your message to send as-is this one time\n"
        "  4. Allow always — add the value to ~/.claude/leak-guard/allowlist.toml"
    )


def hook_user_prompt() -> int:
    event = read_event()
    prompt = event.get("prompt", "") or ""
    allow_once = prompt.lstrip().startswith(_ALLOW_ONCE_PREFIX)

    allow = load_allowlist()
    silent = allow.silent_blocks
    findings = scan_all(text=prompt, source_label="<user-prompt>")
    secrets, pii = classify(findings)

    # Partition heuristic vs. high-confidence findings.
    definitive_secrets = [f for f in secrets if f.rule_id not in _HEURISTIC_RULE_IDS]
    heuristic_findings = [f for f in secrets + pii if f.rule_id in _HEURISTIC_RULE_IDS]
    definitive_pii = [f for f in pii if f.rule_id not in _HEURISTIC_RULE_IDS]

    if definitive_secrets:
        # [allow-once] does NOT bypass definitive secret findings — block regardless.
        audit("block_user_prompt_secret", {"count": len(definitive_secrets)})
        emit_prompt_block(
            "leak-guard: secrets detected in your prompt. Please remove them before submitting.\n"
            + format_summary(definitive_secrets),
            silent=silent,
        )
        return 0

    # [allow-once] prefix: skip heuristic findings only (no definitive secrets above).
    if allow_once:
        audit("allow_once_bypass", {})
        return 0  # let the prompt through unchanged

    if heuristic_findings:
        audit("ask_user_prompt_heuristic", {"count": len(heuristic_findings)})
        emit_prompt_block(_ask_message(heuristic_findings), silent=silent)
        return 0

    if definitive_pii:
        audit("block_user_prompt_pii", {"count": len(definitive_pii)})
        emit_prompt_block(
            "leak-guard: PII detected in your prompt. Rephrase, redact, or add to allowlist "
            f"(~/.claude/leak-guard/allowlist.toml).\n{format_summary(definitive_pii)}",
            silent=silent,
        )
        return 0

    return 0


def hook_pre_tool() -> int:
    event = read_event()
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    allow = load_allowlist()
    silent = allow.silent_blocks

    # 1. Path-based blocking for file-reading tools
    if tool in PRE_TOOL_BLOCK_BY_PATH:
        fpath = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if fpath:
            if not path_allowlisted(fpath, allow):
                fn_findings = scan_filename(fpath, load_filename_blocklist())
                if fn_findings:
                    audit("deny_pre_tool_filename", {"tool": tool, "path": fpath})
                    emit_pre_tool(
                        "deny",
                        f"leak-guard: sensitive file blocked ({fpath}).\n{format_summary(fn_findings)}",
                        silent=silent,
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
                    f"leak-guard: secrets in {tool} input — blocked.\n{format_summary(secrets)}",
                    silent=silent,
                )
                return 0
            if pii:
                audit("ask_pre_tool_pii", {"tool": tool, "count": len(pii)})
                emit_pre_tool(
                    "ask",
                    f"leak-guard: PII detected in {tool} input. Allow, deny, or cancel?\n"
                    f"{format_summary(pii)}\n"
                    "To always allow similar: add to ~/.claude/leak-guard/allowlist.toml",
                    silent=silent,
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
    tool_input = event.get("tool_input", {}) or {}
    source = _extract_response_source(tool, tool_input)
    allow = load_allowlist()
    silent = allow.silent_blocks
    # Honour path_globs for Read outputs — if the file path is allowlisted,
    # skip scanning entirely (same logic as PreToolUse path check).
    if tool == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path and path_allowlisted(file_path, allow):
            return 0
    findings = scan_all(text=text, source_label=source)
    if not findings:
        return 0
    secrets, pii = classify(findings)
    if secrets:
        audit("block_post_tool_secret", {"tool": tool, "source": source, "count": len(secrets)})
        emit_post_tool_block(
            f"leak-guard BLOCKED {tool} output from {source}: secrets present. "
            f"Content withheld from context.\n{format_summary(secrets)}\n"
            "Action: remove secrets from the source, add the path to allowlist, or scan explicitly with /scan-leaks.",
            silent=silent,
        )
        return 0
    if pii:
        audit("block_post_tool_pii", {"tool": tool, "source": source, "count": len(pii)})
        emit_post_tool_block(
            f"leak-guard BLOCKED {tool} output from {source}: PII present. "
            f"Content withheld.\n{format_summary(pii)}\n"
            "Action: rephrase the query, or add the path/rule to ~/.claude/leak-guard/allowlist.toml.",
            silent=silent,
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
    text = sys.stdin.read(_STDIN_MAX_BYTES)
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


_SHA_RE = re.compile(r'^[0-9a-f]{40}$')


def cmd_git_hook_pre_push() -> int:
    """Invoked from .git/hooks/pre-push. Scans HEAD vs upstream diff."""
    # Read refs from stdin per git's pre-push protocol
    refs = sys.stdin.read(_STDIN_MAX_BYTES).strip().splitlines()
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
        local_sha = parts[1] if len(parts) > 1 else ""
        remote_sha = parts[3] if len(parts) > 3 else ""
        if not _SHA_RE.match(local_sha) or not _SHA_RE.match(remote_sha):
            print("[leak-guard] invalid SHA in pre-push stdin, blocking push", file=sys.stderr)
            return 1
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

_STDIN_MAX_BYTES = 4 * 1024 * 1024  # 4 MB


def read_event() -> dict:
    try:
        raw = sys.stdin.read(_STDIN_MAX_BYTES)
        if not raw.strip():
            return {}
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed hook event JSON: {exc}") from exc


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
# Flag command — teach leak-guard from user feedback.
# Appends to either the user allowlist (fp) or custom_rules.toml (fn).
# ──────────────────────────────────────────────────────────────────────────

def _toml_escape_literal(s: str) -> str:
    """Quote a string for TOML. Prefer single-quoted literal strings so
    regex backslashes survive without escaping. Fall back to basic string
    only when the value contains a single quote."""
    if "'" not in s and "\n" not in s:
        return "'" + s + "'"
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return '"' + escaped + '"'


def _append_to_file(path: Path, block: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existed = path.exists()
    with path.open("a", encoding="utf-8") as f:
        if not existed:
            f.write(f"# leak-guard user-learned entries — managed by `scanner.py flag`\n")
        f.write(block)


def cmd_flag(args) -> int:
    """Append a user feedback entry to the appropriate learned-state file."""
    ensure_state_dir()
    now = time.strftime("%Y-%m-%d")
    reason = args.reason or f"user-flagged {now}"

    if args.kind == "fp":
        # False positive → suppress via allowlist.
        if not (args.literal or args.suppress_rule):
            print("flag fp: provide --literal <value> or --suppress-rule <rule_id>",
                  file=sys.stderr)
            return 2
        block = f"\n# {reason}\n"
        if args.literal:
            # Append as TOML array fragment — if `literal` already exists in the
            # user allowlist, the parser will merge multiple top-level keys only
            # when rewritten, so we use a sectioned approach: write a new
            # [[learned_fp]] table array that load_allowlist will also read.
            # Simpler: rewrite the literal = [...] block by reading + appending.
            return _append_literal(args.literal, reason)
        if args.suppress_rule:
            return _append_suppress_rule(args.suppress_rule, reason)

    if args.kind == "fn":
        # False negative → add a new detection rule.
        if args.context_keyword:
            return _append_custom_section(
                "context_keyword",
                {"word": args.context_keyword.lower()},
                reason,
            )
        if args.fuzzy_prefix:
            return _append_custom_section(
                "fuzzy_prefix",
                {"prefix": args.fuzzy_prefix},
                reason,
            )
        if not (args.rule_id and args.pattern):
            print("flag fn: provide --rule-id AND --pattern "
                  "(or --context-keyword / --fuzzy-prefix for lightweight additions)",
                  file=sys.stderr)
            return 2
        # Validate regex before writing.
        try:
            re.compile(args.pattern)
        except re.error as e:
            print(f"flag fn: invalid regex: {e}", file=sys.stderr)
            return 2
        entry = {
            "rule_id": args.rule_id,
            "regex": args.pattern,
            "description": args.description or f"user-added {now}",
            "severity": args.severity,
        }
        return _append_custom_section("pattern", entry, reason)

    return 2


def _append_literal(literal: str, reason: str) -> int:
    """Append a single literal to the user allowlist's `literal` array.
    Uses a simple file rewrite approach to preserve existing entries."""
    path = USER_ALLOWLIST
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_literals: list[str] = []
    other_lines: list[str] = []
    if path.exists():
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
            existing_literals = list(data.get("literal", []))
            # Preserve non-literal keys by re-reading raw text and stripping
            # the `literal = [...]` block.
            raw = path.read_text(encoding="utf-8")
            other_lines = _strip_toml_array(raw, "literal").splitlines()
        except Exception as e:
            print(f"flag fp: could not parse {path}: {e}", file=sys.stderr)
            return 2
    if literal in existing_literals:
        print(f"[flag] literal already present — no change: {literal[:40]}")
        return 0
    existing_literals.append(literal)
    # Rewrite: literal array first, then preserved content.
    out_lines = ["literal = ["]
    for lit in existing_literals:
        out_lines.append(f"    {_toml_escape_literal(lit)},")
    out_lines.append("]")
    out_lines.append("")
    if other_lines:
        out_lines.append(f"# user-flagged fp {time.strftime('%Y-%m-%d')} — {reason}")
        out_lines.extend(other_lines)
    path.write_text("\n".join(out_lines).rstrip() + "\n", encoding="utf-8")
    print(f"[flag] added literal to allowlist: {literal[:60]}")
    return 0


def _append_suppress_rule(rule_id: str, reason: str) -> int:
    """Append to the user allowlist `rule_ids` array to globally suppress a rule."""
    path = USER_ALLOWLIST
    path.parent.mkdir(parents=True, exist_ok=True)
    block = (
        f"\n# user-flagged fp {time.strftime('%Y-%m-%d')} — {reason}\n"
        f"rule_ids = [{_toml_escape_literal(rule_id)}]\n"
    )
    # Quick path: if rule_ids already exists, append by rewrite.
    if path.exists():
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
            existing = set(data.get("rule_ids", []))
            if rule_id in existing:
                print(f"[flag] rule {rule_id} already suppressed — no change")
                return 0
            existing.add(rule_id)
            raw = path.read_text(encoding="utf-8")
            stripped = _strip_toml_array(raw, "rule_ids")
            new_arr_lines = ["rule_ids = ["]
            for rid in sorted(existing):
                new_arr_lines.append(f"    {_toml_escape_literal(rid)},")
            new_arr_lines.append("]")
            path.write_text(
                stripped.rstrip() + "\n\n"
                + f"# user-flagged fp {time.strftime('%Y-%m-%d')} — {reason}\n"
                + "\n".join(new_arr_lines) + "\n",
                encoding="utf-8",
            )
            print(f"[flag] suppressed rule globally: {rule_id}")
            return 0
        except Exception as e:
            print(f"flag fp: could not parse {path}: {e}", file=sys.stderr)
            return 2
    _append_to_file(path, block)
    print(f"[flag] suppressed rule globally: {rule_id}")
    return 0


def _append_custom_section(section: str, entry: dict, reason: str) -> int:
    """Append a [[section]] table to CUSTOM_RULES_FILE."""
    path = CUSTOM_RULES_FILE
    lines = [f"\n# user-flagged fn {time.strftime('%Y-%m-%d')} — {reason}",
             f"[[{section}]]"]
    for k, v in entry.items():
        lines.append(f"{k} = {_toml_escape_literal(str(v))}")
    lines.append("")
    _append_to_file(path, "\n".join(lines))
    print(f"[flag] added {section}: {entry.get('rule_id') or entry.get('prefix') or entry.get('word')}")
    return 0


def _strip_toml_array(raw: str, key: str) -> str:
    """Remove a top-level `<key> = [ ... ]` block (single-line or multi-line)
    so the caller can rewrite it. Preserves everything else verbatim."""
    import re as _re
    pat = _re.compile(
        rf"^{_re.escape(key)}\s*=\s*\[[^\]]*\]\s*$",
        _re.MULTILINE | _re.DOTALL,
    )
    return pat.sub("", raw)


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

    # `flag` — user feedback loop: append allowlist / custom-rule entries so
    # leak-guard learns from FP/FN/uncertain verdicts (see `tests/adversarial_suite.py`).
    fp = sub.add_parser("flag",
        help="Teach leak-guard from false-positive / false-negative feedback")
    fp.add_argument("kind", choices=["fp", "fn"],
        help="fp=suppress (allowlist), fn=add detection rule")
    fp.add_argument("--literal",
        help="[fp] Exact string to suppress globally")
    fp.add_argument("--suppress-rule",
        help="[fp] Rule ID to suppress globally (e.g. 'email')")
    fp.add_argument("--rule-id",
        help="[fn] New rule identifier, e.g. 'ssn-dot-variant'")
    fp.add_argument("--pattern",
        help="[fn] Regex pattern for detection")
    fp.add_argument("--description", default="",
        help="[fn] Human description (auto-dated if omitted)")
    fp.add_argument("--severity", choices=["low","medium","high","critical"], default="high",
        help="[fn] Severity level")
    fp.add_argument("--context-keyword",
        help="[fn] Add a context keyword (lowers entropy threshold near it)")
    fp.add_argument("--fuzzy-prefix",
        help="[fn] Add a custom PREFIX: credential format")
    fp.add_argument("--reason", default="",
        help="Note explaining why this entry was added")

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
        if args.cmd == "flag":
            return cmd_flag(args)
    except Exception as e:
        audit("scanner_exception", {"cmd": args.cmd, "error": str(e), "tb": traceback.format_exc()[:2000]})
        # Fail-closed for hook events; pass-through for CLI
        if args.cmd.startswith("hook-"):
            if args.cmd == "hook-pre-tool":
                emit_pre_tool("deny", "leak-guard internal error (fail-closed) — check audit log")
            elif args.cmd == "hook-user-prompt":
                emit_prompt_block("leak-guard internal error (fail-closed) — check audit log")
            elif args.cmd == "hook-post-tool":
                emit_post_tool_block("leak-guard internal error (fail-closed) — check audit log")
            else:
                print(f"leak-guard error: {e}", file=sys.stderr)
            return 0
        print(f"leak-guard error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
