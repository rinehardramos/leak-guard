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
TRAINING_LOG = STATE_DIR / "training_log.jsonl"
USER_ALLOWLIST = STATE_DIR / "allowlist.toml"
CUSTOM_RULES_FILE = STATE_DIR / "custom_rules.toml"

# Verifier state files (Commit C — opt-in LLM cross-check)
VERIFIER_CONFIG = STATE_DIR / "verifier.toml"
PENDING_VERIFICATIONS = STATE_DIR / "pending_verifications.jsonl"
VERIFIER_FEEDBACK = STATE_DIR / "verifier_feedback.jsonl"

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

    raw_match: str = field(default="", repr=False)  # internal only — never logged/displayed

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
    bash_globs: list[str] = field(default_factory=list)    # bash commands where PostToolUse output is suppressed
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


def _author_mode() -> bool:
    """True only on the author's machine — gated by LEAK_GUARD_AUTHOR=1 env var.
    Set in ~/.zshrc: export LEAK_GUARD_AUTHOR=1
    Other users never have this set, so training capture is a no-op for them.
    """
    return os.environ.get("LEAK_GUARD_AUTHOR") == "1"


def audit(event: str, payload: dict[str, Any]) -> None:
    """Append one JSON line to audit log. Never raises."""
    try:
        ensure_state_dir()
        entry = {"ts": time.time(), "event": event, **payload}
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def _write_training_entry(findings: list, session_id: str = "") -> None:
    """Author-only: append one JSONL line per finding. No raw values stored."""
    if not _author_mode():
        return
    try:
        ensure_state_dir()
        ts = time.time()
        lines = []
        for f in findings:
            entry = {
                "ts": ts,
                "session_id": session_id,
                "verdict": "pending",
                "analysis": None,
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "hash": sha256(f.raw_match) if f.raw_match else "",
                "preview": f.preview,
                "source": f.source,
            }
            lines.append(json.dumps(entry, default=str))
        with TRAINING_LOG.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
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
            allow.bash_globs.extend(data.get("bash_globs", []))
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
                raw_match=matched,
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


# Structural template wrappers — unambiguously NOT secrets.
# These are syntactic markers used in documentation and config templates.
# We do NOT maintain a word-list of "known weak passwords" — those suppressions
# are fragile, hard to keep correct, and create silent blind spots.  If something
# looks like a credential assignment, the user should decide via the action picker.
_PLACEHOLDER_SHAPE_RE = re.compile(
    r"""^(
        <[^<>]{1,80}>              # <your-key>  (angle-bracket template)
      | \{\{[^{}]{1,80}\}\}        # {{API_KEY}} (Jinja/Mustache template)
      | \$\{[^${}]{1,80}\}         # ${TOKEN}    (shell variable expansion)
      | \$[A-Z_][A-Z0-9_]{0,40}    # $SECRET_TOKEN (env var reference)
      | %[A-Z_][A-Z0-9_]{0,40}%    # %TOKEN%     (Windows-style env var)
    )$""",
    re.VERBOSE,
)


def _is_dummy_value(val: str) -> bool:
    """Return True only for values that are *structurally* non-secrets.

    Deliberately minimal — the scanner's job is to notice and notify.
    Anything ambiguous goes to the user via the action picker.

    Suppressed:
    - Empty / whitespace-only strings.
    - Runs of a single repeated character (xxxxxxxx, 00000000, ********).
    - Template syntax wrappers: <...>, {{...}}, ${...}, $VAR, %VAR%.
    - 40-char all-lowercase-hex strings (git commit SHAs).
    """
    stripped = val.strip().strip("'\"`").strip()
    if not stripped:
        return True
    # Runs of a single character — unambiguously not a real credential.
    if len(stripped) >= 4 and len(set(stripped.lower())) == 1:
        return True
    # Template syntax — syntactic markers, never actual secrets.
    if _PLACEHOLDER_SHAPE_RE.match(val.strip()):
        return True
    # 40-char all-lowercase-hex → git SHA, not a secret.
    if len(stripped) == 40 and all(c in "0123456789abcdef" for c in stripped.lower()):
        return True
    return False


# Characters that are purely visual/directional and should be stripped
# before any scanning — zero-width spaces, bidi controls, BOM.
_STRIP_UNICODE_RE = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f'
    r'\u202a\u202b\u202c\u202d\u202e'
    r'\u2066\u2067\u2068\u2069\ufeff]'
)

# leak-guard's own redaction preview tags — strip before re-scanning output.
_REDACTED_TAG_RE = re.compile(r'\[REDACTED:[^\]]{1,120}\]')

# Claude Code runtime XML blocks injected into prompts — never contain user secrets.
# Covers: <task-notification>, <command-output>, <local-command-stdout>, etc.
_RUNTIME_XML_RE = re.compile(
    r'<(task-notification|command-output|local-command-stdout|system-reminder|antml:[^>]+)'
    r'[\s\S]*?</\1>',
    re.DOTALL,
)


def _normalize_text(text: str) -> str:
    """NFKC-normalize, strip bidi/zero-width controls, redaction tags, and runtime XML blocks."""
    import unicodedata
    text = unicodedata.normalize('NFKC', text)
    text = _STRIP_UNICODE_RE.sub('', text)
    text = _REDACTED_TAG_RE.sub('', text)
    text = _RUNTIME_XML_RE.sub('', text)
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
            raw_match=candidate,
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
        # Skip leak-guard's own redaction preview prefixes (e.g. REDACTED:...)
        if prefix.upper() in {'REDACTED'}:
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
        full_match = m.group(0)
        findings.append(Finding(
            rule_id="fuzzy-prefixed-credential",
            category="secret",
            description=f"Possible custom credential with prefix '{prefix}:'",
            line=line_no,
            preview=redact_preview(value, "fuzzy-cred"),
            severity="high",
            source=source,
            raw_match=full_match,
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
                raw_match=m.group(0),
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
                raw_match=matched,
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
                raw_match=matched,
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
                raw_match=raw,
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
# Verifier (Commit C) — opt-in LLM cross-check via emitted prompts.
# Never makes API calls. Never sends real user content anywhere.
# ──────────────────────────────────────────────────────────────────────────

import random as _random_mod


def verifier_enabled() -> bool:
    """Return True if the user has opted into the verifier."""
    if not VERIFIER_CONFIG.exists():
        return False
    try:
        with VERIFIER_CONFIG.open("rb") as f:
            data = tomllib.load(f)
        return bool(data.get("verifier_enabled", False))
    except Exception:
        return False


# PII-category rule ids for which synthetic cross-check adds no value.
_VERIFIER_SKIP_CATEGORIES = {"pii"}
_VERIFIER_SKIP_RULE_PREFIXES = ("us-ssn", "credit-card", "us-phone", "email", "ssn",
                                 "phone", "credit")


def _verifier_skip_rule(rule_id: str, category: str) -> bool:
    """Return True for PII rules where a synthetic cross-check adds no value."""
    if category in _VERIFIER_SKIP_CATEGORIES:
        return True
    rid = rule_id.lower()
    return any(rid.startswith(p) for p in _VERIFIER_SKIP_RULE_PREFIXES)


# ── Deterministic synthetic string generators ─────────────────────────────

def _rand_alphanum(n: int, seed: int) -> str:
    """n uppercase letters + digits, reproducible from seed."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    rng = _random_mod.Random(seed)
    return "".join(rng.choice(chars) for _ in range(n))


def _rand_lower(n: int, seed: int) -> str:
    """n lowercase letters, reproducible from seed."""
    chars = "abcdefghijklmnopqrstuvwxyz"
    rng = _random_mod.Random(seed)
    return "".join(rng.choice(chars) for _ in range(n))


def _rand_digits(n: int, seed: int) -> str:
    """n digit characters, reproducible from seed."""
    rng = _random_mod.Random(seed)
    return "".join(rng.choice("0123456789") for _ in range(n))


def _rand_b64(n: int, seed: int) -> str:
    """n base64 characters [A-Za-z0-9+/], reproducible from seed."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    rng = _random_mod.Random(seed)
    return "".join(rng.choice(chars) for _ in range(n))


def _rand_mixed(n: int, seed: int) -> str:
    """n mixed-case letters + digits, reproducible from seed."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    rng = _random_mod.Random(seed)
    return "".join(rng.choice(chars) for _ in range(n))


def _generate_synthetic(rule_id: str, seed: int) -> tuple[str, str, str] | None:
    """Return (synthetic, decoy1, decoy2) deterministic strings for rule_id.

    Returns None for PII rules where cross-check adds no value.
    The synthetic looks like the rule would match it; decoys are obviously benign.
    All strings are freshly generated from rule_id + seed — zero info about the
    original blocked string.
    """
    rid = rule_id.lower()

    # PII rules — skip
    if any(rid.startswith(p) for p in _VERIFIER_SKIP_RULE_PREFIXES):
        return None

    if "aws" in rid:
        synthetic = "AKIA" + _rand_alphanum(16, seed)
        decoy1 = _rand_lower(20, seed + 1)
        decoy2 = _rand_lower(20, seed + 2)

    elif "github-pat" in rid or rid == "ghp" or "ghp" in rid:
        synthetic = "ghp_" + _rand_alphanum(36, seed)
        decoy1 = _rand_lower(20, seed + 1)
        decoy2 = _rand_lower(20, seed + 2)

    elif "stripe" in rid or "sk_live" in rid:
        synthetic = "sk_live_" + _rand_alphanum(24, seed)
        decoy1 = _rand_lower(20, seed + 1)
        decoy2 = _rand_lower(20, seed + 2)

    elif "slack" in rid or "xoxb" in rid:
        part1 = _rand_digits(12, seed)
        part2 = _rand_digits(13, seed + 1)
        part3 = _rand_lower(12, seed + 2)
        synthetic = f"xoxb-{part1}-{part2}-{part3}"
        decoy1 = _rand_lower(20, seed + 3)
        decoy2 = _rand_lower(20, seed + 4)

    elif "jwt" in rid or "eyj" in rid:
        synthetic = "eyJhbGciOiJIUzI1NiJ9." + _rand_b64(32, seed) + "." + _rand_b64(32, seed + 1)
        decoy1 = _rand_lower(20, seed + 2)
        decoy2 = _rand_lower(20, seed + 3)

    elif "fuzzy" in rid:
        synthetic = "ORG:" + _rand_mixed(20, seed)
        decoy1 = _rand_lower(20, seed + 1)
        decoy2 = _rand_lower(20, seed + 2)

    elif "entropy" in rid or "high-entropy" in rid:
        synthetic = _rand_b64(32, seed)
        decoy1 = _rand_lower(20, seed + 1)
        decoy2 = _rand_lower(20, seed + 2)

    else:
        # Default: base64-shaped synthetic + lower-case decoys
        synthetic = _rand_b64(28, seed)
        decoy1 = _rand_b64(28, seed + 1)
        decoy2 = _rand_b64(28, seed + 2)

    return synthetic, decoy1, decoy2


def _verifier_id() -> str:
    """Generate a unique correlation ID: lg-<timestamp>-<4hex>."""
    ts = int(time.time())
    suffix = _rand_alphanum(4, ts ^ id(object())).lower()
    return f"lg-{ts}-{suffix}"


def _maybe_emit_verifier_notice(rule_id: str, category: str) -> str:
    """If verifier is enabled and rule is not PII-skip, log pending verification
    and return a one-line notice string. Returns empty string otherwise."""
    try:
        if not verifier_enabled():
            return ""
        if _verifier_skip_rule(rule_id, category):
            return ""
        vid = _verifier_id()
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = {
            "id": vid,
            "ts": ts,
            "rule_id": rule_id,
            "category": category,
            "shape": rule_id,
            "verdict": None,
        }
        ensure_state_dir()
        with PENDING_VERIFICATIONS.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return f"  \u21b3 [verifier] Cross-check available \u2014 run: scanner.py verify-emit {vid}"
    except Exception:
        return ""


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


def emit_allow_modified(updated_prompt: str) -> None:
    """Re-inject the original (or redacted) prompt as additionalContext.

    UserPromptSubmit does not support updatedUserPrompt — only additionalContext.
    We inject the prompt text so Claude sees it and responds to it.
    """
    out = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": updated_prompt}}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


def _open_tty():
    """Open /dev/tty for interactive I/O. Returns file or None if non-interactive."""
    try:
        return open("/dev/tty", "r+", buffering=1)
    except OSError:
        return None


def _action_picker(findings: list, prompt: str, silent: bool) -> tuple:
    """
    Show interactive action menu when findings are detected.
    Returns (exit_code, updated_prompt_or_none).
    - (0, None)    -> allow as-is
    - (0, text)    -> allow with modified prompt (redacted)
    - (2, None)    -> block/discard
    """
    if silent:
        return (2, None)

    tty = _open_tty()
    if tty is None:
        return (2, None)

    try:
        # Build display
        lines = ["\n\U0001f6a8 leak-guard: credential detected in your prompt.\n"]
        for f in findings:
            lines.append(f"  Rule: {f.rule_id} ({f.severity})")
            lines.append(f"  Preview: {f.preview}\n")
        lines.append("  What would you like to do?")
        lines.append("  [A] Allow once — send prompt as-is")
        lines.append("  [R] Redact — strip flagged token(s), then send")
        lines.append("  [D] Delete — discard prompt entirely   (default)")
        lines.append("  [F] Flag as false positive — allowlist + send")
        lines.append("  > ")
        tty.write("\n".join(lines))
        tty.flush()

        try:
            ch = tty.read(1)
            # consume rest of line
            if ch != "\n":
                tty.readline()
        except KeyboardInterrupt:
            return (2, None)

        choice = ch.strip().lower() if ch else ""

        if choice == "a":
            return (0, None)
        elif choice == "r":
            redacted = prompt
            for f in findings:
                if f.raw_match:
                    redacted = redacted.replace(f.raw_match, "[REDACTED]")
            return (0, redacted)
        elif choice == "f":
            for f in findings:
                if f.raw_match:
                    try:
                        subprocess.run(
                            [sys.argv[0], "flag", "fp",
                             "--literal", f.raw_match,
                             "--reason", "user marked FP in action picker"],
                            timeout=10,
                        )
                    except Exception:
                        pass
            return (0, None)
        else:
            # "d", Enter, or anything else → block
            return (2, None)
    finally:
        try:
            tty.close()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────
# Prompt-injected action picker (Turn 1: block + write pending; Turn 2: handle choice)
# ──────────────────────────────────────────────────────────────────────────

# Pending action file — stores the original prompt + redact targets temporarily
# so the user can reply with A/R/D/F in the next turn.
# Security note: raw_match values are stored here temporarily (mode 0o600),
# same security posture as ssh-agent temp files. Auto-deleted after use or TTL.
PENDING_ACTION = STATE_DIR / "pending_action.json"

_PENDING_TTL = 300  # 5 minutes


def _write_pending_action(prompt: str, findings: list) -> None:
    """Write pending_action.json with mode 0o600. findings is a list of Finding objects."""
    try:
        ensure_state_dir()
        data = {
            "prompt": prompt,
            "redact_targets": [f.raw_match for f in findings if f.raw_match],
            "findings_summary": [
                {"rule_id": f.rule_id, "severity": f.severity, "preview": f.preview}
                for f in findings
            ],
            "expires_at": time.time() + _PENDING_TTL,
        }
        # Write with restricted permissions
        fd = os.open(str(PENDING_ACTION), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except Exception:
        pass  # fail open: if we can't write, fall through to normal scan next turn


def _read_pending_action() -> dict | None:
    """Read and return pending action, or None if missing/expired."""
    try:
        if not PENDING_ACTION.exists():
            return None
        data = json.loads(PENDING_ACTION.read_text(encoding="utf-8"))
        if time.time() > data.get("expires_at", 0):
            try:
                PENDING_ACTION.unlink(missing_ok=True)
            except Exception:
                pass
            return None
        return data
    except Exception:
        return None


def _is_choice_reply(prompt: str) -> str | None:
    """Return normalised choice ('A','R','D','F') if prompt is a reply to the action picker.

    Returns None if no pending_action.json exists — avoids intercepting
    genuine one-letter prompts when there's nothing pending.
    """
    # Check pending file first to avoid intercepting genuine one-letter prompts
    try:
        if not PENDING_ACTION.exists():
            return None
    except Exception:
        return None

    stripped = prompt.strip().lower()
    if stripped in {"a", "r", "d", "f"}:
        return stripped.upper()
    if stripped.startswith("allow"):
        return "A"
    if stripped.startswith("redact"):
        return "R"
    if stripped.startswith("discard") or stripped.startswith("delete"):
        return "D"
    if stripped.startswith("flag"):
        return "F"
    return None


def _handle_choice(choice: str, pending: dict) -> int:
    """Execute the user's choice from the action picker menu.

    Always deletes PENDING_ACTION first, then acts on the choice.
    """
    try:
        PENDING_ACTION.unlink(missing_ok=True)
    except Exception:
        pass

    original_prompt = pending.get("prompt", "")
    redact_targets = pending.get("redact_targets", [])

    if choice == "A":
        emit_allow_modified(original_prompt)
        return 0

    elif choice == "R":
        redacted = original_prompt
        for target in redact_targets:
            if target:
                redacted = redacted.replace(target, "[REDACTED]")
        emit_allow_modified(redacted)
        return 0

    elif choice == "F":
        for target in redact_targets:
            if target:
                try:
                    subprocess.run(
                        [sys.executable, __file__, "flag", "fp",
                         "--literal", target,
                         "--reason", "user marked FP via action picker"],
                        capture_output=True,
                        timeout=10,
                    )
                except Exception:
                    pass
        emit_allow_modified(original_prompt)
        return 0

    else:  # D or anything else
        emit_prompt_block("Discarded by user choice.")
        return 2


def _build_menu_text(findings: list) -> str:
    """Build the action picker menu text shown to the user via Claude's chat UI."""
    lines = ["\U0001f6a8 leak-guard intercepted your prompt — suspicious content detected.\n"]
    for f in findings:
        lines.append(f"  \u00b7 {f.rule_id} ({f.severity}) \u2014 {f.preview}")
    lines.append("\n  Your original message was withheld. Reply with your choice:")
    lines.append("    A \u2014 Allow once (send original prompt as-is)")
    lines.append("    R \u2014 Redact (strip flagged content, send cleaned prompt)")
    lines.append("    D \u2014 Discard (cancel, default after 5 min)")
    lines.append("    F \u2014 Flag as false positive (allowlist + send)")
    lines.append("\n  Choice [A/R/D/F]:")
    return "\n".join(lines)


def emit_menu_prompt(menu_text: str) -> None:
    """Inject the action picker menu as additionalContext so Claude sees and responds to it.

    UserPromptSubmit hookSpecificOutput only supports `additionalContext` (not
    `updatedUserPrompt` which is PreToolUse-only).  Exit 0 + additionalContext
    injects the text as a meta message Claude reads — Claude then asks the user
    for A/R/D/F.  The original secret-bearing prompt is withheld by exit 2 on
    the block branches; this is called only from the Turn 2 allow path.
    """
    out = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": menu_text}}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


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
    session_id = event.get("session_id", "")

    # ── Turn 2: check if this is a reply to the action picker menu ────────────
    choice = _is_choice_reply(prompt)
    if choice is not None:
        pending = _read_pending_action()
        if pending is not None:
            return _handle_choice(choice, pending)
        # No valid pending action — fall through to normal scan

    allow_once = prompt.lstrip().startswith(_ALLOW_ONCE_PREFIX)

    allow = load_allowlist()
    silent = allow.silent_blocks
    findings = scan_all(text=prompt, source_label="<user-prompt>")
    secrets, pii = classify(findings)

    # Partition heuristic vs. high-confidence findings.
    definitive_secrets = [f for f in secrets if f.rule_id not in _HEURISTIC_RULE_IDS]
    heuristic_findings = [f for f in secrets + pii if f.rule_id in _HEURISTIC_RULE_IDS]
    definitive_pii = [f for f in pii if f.rule_id not in _HEURISTIC_RULE_IDS]

    if not findings:
        return 0

    # [allow-once] prefix bypasses all findings.
    if allow_once:
        audit("allow_once_bypass", {})
        return 0

    # Redact detected values from the prompt text.
    redacted_prompt = prompt
    for f in findings:
        if f.raw_match:
            redacted_prompt = redacted_prompt.replace(f.raw_match, "[REDACTED]")

    audit("redact_user_prompt", {"count": len(findings)})
    _write_training_entry(findings, session_id=session_id)
    summary = format_summary(findings)

    context = (
        "SYSTEM NOTE (leak-guard): The user's message contained potential secrets or PII "
        "that have been flagged. The sensitive values are shown as [REDACTED] below.\n\n"
        f"Findings:\n{summary}\n\n"
        f"Redacted message:\n{redacted_prompt}\n\n"
        "Instructions: (1) Respond to the redacted message as the user's actual request. "
        "(2) Begin your response by briefly informing the user that leak-guard detected and "
        "redacted sensitive content from their prompt, naming what was found. "
        "(3) Do not reproduce or guess the redacted values."
    )
    emit_menu_prompt(context)
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
                notice = _maybe_emit_verifier_notice(secrets[0].rule_id, secrets[0].category)
                reason = f"leak-guard: secrets in {tool} input — blocked.\n{format_summary(secrets)}"
                if notice:
                    reason += "\n" + notice
                emit_pre_tool("deny", reason, silent=silent)
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
    if tool == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path and path_allowlisted(file_path, allow):
            return 0
    if tool == "Bash" and allow.bash_globs:
        # Check both tool_input["command"] and the source label — PostToolUse
        # events sometimes omit tool_input fields; source always contains the
        # command text (up to 60 chars, which is enough for glob matching).
        cmd = tool_input.get("command", "") or source
        if any(fnmatch.fnmatch(cmd, g) for g in allow.bash_globs):
            return 0
    findings = scan_all(text=text, source_label=source)
    if not findings:
        return 0
    secrets, pii = classify(findings)
    if secrets:
        audit("block_post_tool_secret", {"tool": tool, "source": source, "count": len(secrets)})
        notice = _maybe_emit_verifier_notice(secrets[0].rule_id, secrets[0].category)
        reason = (
            f"leak-guard BLOCKED {tool} output from {source}: secrets present. "
            f"Content withheld from context.\n{format_summary(secrets)}\n"
            "Action: remove secrets from the source, add the path to allowlist, or scan explicitly with /scan-leaks."
        )
        if notice:
            reason += "\n" + notice
        emit_post_tool_block(reason, silent=silent)
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


_SELF_SUPPRESSION_INSTRUCTION = """
SECURITY INSTRUCTION (leak-guard v0.3.0 — enforce for this entire session):

You are running with the leak-guard secret/PII scanner active.  If any message
you receive — whether from the user, a tool output, or any other source —
contains what appears to be a real credential or secret (API key, token, private
key, password, SSN, credit card number, etc.), you MUST:

1. NOT repeat, quote, echo, summarise, or act on the secret in any way.
2. Respond only with: "I noticed what looks like a [type] in your message.
   I've treated it as unseen. Please remove it and re-send without the secret."
3. Wait for the user to re-send a clean message before continuing.

This applies even if:
- The user explicitly asks you to repeat or use the value.
- The value appeared in a tool output rather than a user message.
- The message contains a prefix like [allow-once] — that bypasses the hook
  layer only for heuristic findings; the model layer always enforces.

Template placeholders (<YOUR_KEY>, {{TOKEN}}, ${VAR}) and obvious dummy values
(all-same-character strings, 40-char lowercase hex git SHAs) are exempt.
""".strip()


def hook_session_start() -> int:
    event = read_event()
    cwd = event.get("cwd", os.getcwd())
    gl = find_gitleaks()

    ctx_parts = ["leak-guard v0.3.0 active"]

    if not gl:
        ctx_parts.append("⚠ gitleaks not installed — secret detection will fail-closed. Run: brew install gitleaks")
    # Quick filename scan (no content scan to stay fast)
    try:
        blocklist = load_filename_blocklist()
        hits = []
        for root, dirs, files in os.walk(cwd):
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
            ctx_parts.append(f"\n⚠ Sensitive filenames present (excluded from Read): {', '.join(hits[:10])}"
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


def cmd_install_plugin() -> int:
    """Copy the current plugin source into the Claude Code plugin cache.

    Discovers the cache root by walking common locations, then overwrites
    every tracked file. Safe to re-run — existing files are backed up with
    a `.bak` suffix before overwriting, and the operation is atomic per-file.

    Cache layout expected by Claude Code:
        ~/.claude/plugins/cache/<owner>/<name>/<version>/
    """
    # ── Locate cache root ────────────────────────────────────────────────────
    # Try the path encoded in the running hook command first (most reliable),
    # then fall back to a glob search under ~/.claude/plugins/cache/.
    cache_root: Path | None = None

    # Strategy 1: this script IS already installed in the cache — use __file__
    me = Path(__file__).resolve()
    # Expected: …/cache/<owner>/<plugin>/<version>/hooks/scanner.py
    if me.parts[-3:] == ("hooks", "scanner.py") or True:
        candidate = me.parent.parent  # strip hooks/scanner.py → version dir
        if (candidate / "hooks" / "scanner.py").exists():
            # Verify it looks like a cache entry (has a version-like name)
            if candidate.name[0].isdigit():
                cache_root = candidate

    # Strategy 2: glob search
    if cache_root is None:
        base = Path.home() / ".claude" / "plugins" / "cache"
        hits = sorted(base.glob("*/leak-guard/*/hooks/scanner.py"))
        if hits:
            cache_root = hits[-1].parent.parent  # latest version dir

    if cache_root is None:
        print(
            "leak-guard install: could not find plugin cache directory.\n"
            "Expected: ~/.claude/plugins/cache/<owner>/leak-guard/<version>/\n"
            "Is leak-guard installed via the Claude Code marketplace?",
            file=sys.stderr,
        )
        return 2

    # ── Source root (this file lives at <src>/hooks/scanner.py) ─────────────
    src_root = me.parent.parent  # plugins/leak-guard/

    # ── Files to sync ────────────────────────────────────────────────────────
    # Walk src_root and mirror every file into cache_root, skipping
    # __pycache__, *.pyc, and .git artefacts.
    SKIP_DIRS  = {"__pycache__", ".git", ".claude-plugin"}
    SKIP_EXTS  = {".pyc"}

    copied = 0
    skipped = 0
    errors: list[str] = []

    for src_file in src_root.rglob("*"):
        if src_file.is_dir():
            continue
        # Skip unwanted dirs/extensions
        rel = src_file.relative_to(src_root)
        if any(part in SKIP_DIRS for part in rel.parts):
            skipped += 1
            continue
        if src_file.suffix in SKIP_EXTS:
            skipped += 1
            continue

        dst_file = cache_root / rel
        dst_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            if dst_file.exists():
                shutil.copy2(dst_file, dst_file.with_suffix(dst_file.suffix + ".bak"))
            shutil.copy2(src_file, dst_file)
            # Preserve executable bit for hooks and shell scripts
            if src_file.stat().st_mode & 0o111:
                dst_file.chmod(dst_file.stat().st_mode | 0o755)
            copied += 1
        except OSError as exc:
            errors.append(f"  {rel}: {exc}")

    # ── Report ───────────────────────────────────────────────────────────────
    print(f"leak-guard: installed {copied} file(s) → {cache_root}")
    if skipped:
        print(f"  (skipped {skipped} cache/build file(s))")
    if errors:
        print("Errors:", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        return 2

    # Quick smoke-test: run selftest from the newly installed copy
    installed_scanner = cache_root / "hooks" / "scanner.py"
    result = subprocess.run(
        [sys.executable, str(installed_scanner), "selftest"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(
            f"leak-guard install: selftest FAILED on installed copy:\n{result.stdout}",
            file=sys.stderr,
        )
        return 2

    # Count PASS lines for a terse summary
    passes = result.stdout.count("[PASS]")
    print(f"  selftest: {passes} checks OK ✓")
    print("  Restart Claude Code (or reload the session) for changes to take effect.")
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

    def warn(name: str, ok: bool, detail: str = ""):
        """Like check() but a failure is a warning only — does not increment failures."""
        status = "PASS" if ok else "WARN"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))

    print("leak-guard selftest — fresh-install + functional checks")

    # 0. Fresh-install validation
    import sys as _sys, os as _os

    # Python version >= 3.9
    _ver = _sys.version_info
    check("python >= 3.9", _ver >= (3, 9), f"found {_ver.major}.{_ver.minor}")

    # State dir is creatable (or already exists) with correct mode
    _state_dir = STATE_DIR
    try:
        _state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        _mode = oct(_state_dir.stat().st_mode)[-3:]
        check("state dir exists", True, str(_state_dir))
        if _os.name != "nt":
            check("state dir mode 700", _mode == "700", f"mode={_mode}")
    except Exception as _exc:
        check("state dir creatable", False, str(_exc))

    # Rules dir exists (relative to scanner.py)
    _rules_dir = Path(__file__).parent.parent / "rules"
    check("rules dir present", _rules_dir.is_dir(), str(_rules_dir))

    # allowlist.toml: default loads cleanly even when absent
    try:
        _al = load_allowlist()
        check("allowlist loads when absent", True, "default allowlist ok")
    except Exception as _exc:
        check("allowlist loads when absent", False, str(_exc))

    # Hook JSON I/O round-trip
    import json as _json
    import subprocess as _sp
    _fake_event = {"hook_event_name": "UserPromptSubmit", "prompt": "hello world", "session_id": "selftest"}
    try:
        _r = _sp.run([_sys.executable, __file__, "hook-user-prompt"],
            input=_json.dumps(_fake_event), capture_output=True, text=True, timeout=10)
        check("hook JSON round-trip (clean prompt)", _r.returncode == 0, f"rc={_r.returncode}")
    except Exception as _exc:
        check("hook JSON round-trip (clean prompt)", False, str(_exc))

    # Hook correctly redacts a known fake credential
    # String is built at runtime to avoid triggering the scanner on source literals.
    _fake_cred_prompt = "my key " + "CSKC:" + "ScdsJCCKLSLKDKLCNLKCEINK2233as"
    _fake_cred_event = {"hook_event_name": "UserPromptSubmit", "prompt": _fake_cred_prompt, "session_id": "selftest"}
    try:
        _r2 = _sp.run([_sys.executable, __file__, "hook-user-prompt"],
            input=_json.dumps(_fake_cred_event), capture_output=True, text=True, timeout=10)
        _out = _json.loads(_r2.stdout) if _r2.stdout.strip() else {}
        _ctx = _out.get("hookSpecificOutput", {}).get("additionalContext", "")
        check("hook redacts credential", _r2.returncode == 0 and "leak-guard" in _ctx and "[REDACTED]" in _ctx,
              f"rc={_r2.returncode} ctx_len={len(_ctx)}")
    except Exception as _exc:
        check("hook redacts credential", False, str(_exc))

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

    # 7. gitleaks available (optional — WARN not FAIL when absent)
    warn("gitleaks installed", find_gitleaks() is not None,
         find_gitleaks() or "not found — install for deep secret scanning (brew install gitleaks)")

    # 8. gitleaks catches a structurally valid fake key — only runs when present
    if find_gitleaks():
        fake = "AWS_ACCESS_KEY_ID=" + "AKIAY3FDS" + "NDKFKSIDJSW\n"
        f = scan_secrets_gitleaks(text=fake, source_label="<test>")
        check("gitleaks detects AWS key", len(f) > 0, f"found {len(f)}")

    # 9. Classify
    mixed = [Finding("aws", "secret", "", 0, "[R]"), Finding("email", "pii", "", 0, "[R]")]
    s, p = classify(mixed)
    check("classify splits secret/pii", len(s) == 1 and len(p) == 1)

    # 10. Allowlist path glob
    al = Allowlist(path_globs=["*/fixtures/*"])
    check("path allowlist glob", path_allowlisted("/x/fixtures/a.txt", al))

    # 11. (proxy removed)

    # Training mode (author-only)
    if _author_mode():
        try:
            _write_training_entry(
                [Finding("selftest-rule", "secret", "<selftest>", 0,
                         "[REDACTED:selftest:8ch:hash=00000000]",
                         raw_match="selftest-dummy")],
                session_id="selftest",
            )
            check("training log writable [author]", TRAINING_LOG.exists(), str(TRAINING_LOG))
        except Exception as exc:
            check("training log writable [author]", False, str(exc))
    else:
        check("training mode", True, "disabled (not author machine — expected for other users)")

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


_VALID_VERDICTS = {"fp", "fn", "unclear", "confirm"}

_RULES_DIR = Path(os.environ.get(
    "LEAK_GUARD_RULES_DIR",
    Path(__file__).parent.parent / "rules",
))

_PROMOTE_CONFIDENCE_THRESHOLD = 0.75


def cmd_train(args) -> int:
    """Author-only training pipeline commands."""
    if not _author_mode() and args.train_cmd not in ("list",):
        print("train: requires LEAK_GUARD_AUTHOR=1 (author-only feature)", file=sys.stderr)
        return 2
    dispatch = {
        "verdict":          lambda: _train_verdict(args.hash_prefix, args.verdict),
        "list":             lambda: _train_list(getattr(args, "filter", "pending"),
                                                getattr(args, "project", "")),
        "analyze":          lambda: _train_analyze(),
        "ingest-analysis":  lambda: _train_ingest_analysis(
                                args.text if getattr(args, "text", None) else sys.stdin.read()),
        "promote":          lambda: _train_promote(getattr(args, "dry_run", False)),
    }
    fn = dispatch.get(args.train_cmd)
    if fn is None:
        print(f"train: unknown subcommand '{args.train_cmd}'", file=sys.stderr)
        return 2
    return fn()


def _train_verdict(hash_prefix: str, verdict: str) -> int:
    if verdict not in _VALID_VERDICTS:
        print(f"train verdict: must be one of {sorted(_VALID_VERDICTS)}", file=sys.stderr)
        return 2
    if not TRAINING_LOG.exists():
        print("train verdict: no training_log.jsonl found — run the scanner first", file=sys.stderr)
        return 1
    entries, updated = [], 0
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            entries.append(line)
            continue
        if e.get("hash", "").startswith(hash_prefix) and e.get("verdict") == "pending":
            e["verdict"] = verdict
            e["verdict_ts"] = time.time()
            updated += 1
        entries.append(json.dumps(e, default=str))
    TRAINING_LOG.write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(f"train verdict: updated {updated} entry/entries to '{verdict}'")
    audit("train_verdict", {"hash_prefix": hash_prefix, "verdict": verdict, "updated": updated})
    return 0 if updated > 0 else 1


def _train_list(filter_verdict: str = "pending", project: str = "") -> int:
    if not TRAINING_LOG.exists():
        print("train list: no training_log.jsonl found")
        return 0
    entries = []
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    shown = [e for e in entries
             if (filter_verdict == "all" or e.get("verdict") == filter_verdict)
             and (not project or project in e.get("source", ""))]
    if not shown:
        print(f"train list: no entries with verdict='{filter_verdict}'" +
              (f" project='{project}'" if project else ""))
        return 0
    print(f"{'#':<4} {'verdict':<10} {'analysis':<12} {'rule_id':<35} {'hash':<18} preview")
    print("-" * 100)
    for i, e in enumerate(shown):
        ana = (e.get("analysis") or {}).get("category", "-") if e.get("analysis") else "-"
        print(f"{i+1:<4} {e.get('verdict','?'):<10} {ana:<12} {e.get('rule_id','?'):<35} "
              f"{e.get('hash','?')[:16]:<18} {e.get('preview','')}")
    print(f"\n{len(shown)} entry/entries.")
    return 0


_ANALYSIS_RE = re.compile(
    r"ANALYSIS:(?P<hash>[a-f0-9]+):category=(?P<category>secret|pii|benign)"
    r":confidence=(?P<conf>[0-9.]+):reason=(?P<reason>.+)"
)


def _train_analyze() -> int:
    """Emit additionalContext asking Claude to categorize pending/unclear/fn findings."""
    if not TRAINING_LOG.exists():
        print("train analyze: no training_log.jsonl found", file=sys.stderr)
        return 1
    candidates = []
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("verdict") in ("pending", "unclear", "fn") and e.get("analysis") is None:
            candidates.append(e)
    if not candidates:
        print("train analyze: no unanalyzed entries found")
        return 0
    lines = [
        "SYSTEM NOTE (leak-guard training): Analyze each finding below.",
        "For each, respond on ONE line exactly:",
        "  ANALYSIS:<hash>:category=<secret|pii|benign>:confidence=<0.00-1.00>:reason=<one sentence>",
        "",
        "Rules:",
        "- secret: any credential, token, API key, password, private key",
        "- pii: personally identifiable info (email, SSN, phone) but not a credential",
        "- benign: internal ID, UUID, hash, random string with no credential semantics",
        "- confidence: 0.0=certainly benign, 1.0=certainly a real credential/PII leak",
        "- Be conservative: weight toward real leak if ambiguous",
        "",
        "Findings to analyze:",
    ]
    for e in candidates[:20]:
        lines.append(f"  hash={e['hash']} rule={e['rule_id']} preview={e['preview']} "
                     f"user_verdict={e['verdict']}")
    lines += [
        "",
        "After responding with ANALYSIS lines, run: scanner.py train ingest-analysis",
    ]
    ctx = "\n".join(lines)
    out = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": ctx}}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    audit("train_analyze", {"count": len(candidates)})
    return 0


def _train_ingest_analysis(text: str) -> int:
    """Parse ANALYSIS lines from Claude's response and update training_log.jsonl."""
    if not TRAINING_LOG.exists():
        print("train ingest-analysis: no training_log.jsonl found", file=sys.stderr)
        return 1
    parsed = {}
    for line in text.splitlines():
        m = _ANALYSIS_RE.search(line.strip())
        if m:
            h = m.group("hash")
            parsed[h] = {
                "category": m.group("category"),
                "confidence": float(m.group("conf")),
                "reason": m.group("reason").strip(),
                "analyzed_ts": time.time(),
            }
    if not parsed:
        print("train ingest-analysis: no valid ANALYSIS lines found in input", file=sys.stderr)
        return 1
    entries, updated = [], 0
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            entries.append(line)
            continue
        h = e.get("hash", "")
        match = next((v for k, v in parsed.items() if h.startswith(k) or k.startswith(h)), None)
        if match:
            e["analysis"] = match
            updated += 1
        entries.append(json.dumps(e, default=str))
    TRAINING_LOG.write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(f"train ingest-analysis: updated {updated} entry/entries with LLM analysis")
    audit("train_ingest_analysis", {"parsed": len(parsed), "updated": updated})
    return 0


def _train_promote(dry_run: bool = False) -> int:
    """Promote high-confidence findings into repo rules.

    FN/unclear/confirm with confidence >= threshold → pii.toml candidate block.
    FP with benign analysis → suppress_rules in allowlist.toml.
    """
    if not TRAINING_LOG.exists():
        print("train promote: no training_log.jsonl found", file=sys.stderr)
        return 1
    fn_candidates, fp_candidates = [], []
    entries_raw = []
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            entries_raw.append(line)
            continue
        analysis = e.get("analysis") or {}
        conf = float(analysis.get("confidence", 0.0))
        cat = analysis.get("category", "")
        verdict = e.get("verdict", "pending")
        already_promoted = e.get("promoted", False)
        if already_promoted or conf < _PROMOTE_CONFIDENCE_THRESHOLD:
            entries_raw.append(json.dumps(e, default=str))
            continue
        if verdict == "fp" and cat == "benign":
            fp_candidates.append(e)
            e["promoted"] = True
        elif verdict in ("fn", "unclear", "confirm") and cat in ("secret", "pii"):
            fn_candidates.append(e)
            e["promoted"] = True
        entries_raw.append(json.dumps(e, default=str))

    if not fn_candidates and not fp_candidates:
        print(f"train promote: no high-confidence candidates "
              f"(threshold={_PROMOTE_CONFIDENCE_THRESHOLD})")
        return 0

    if fn_candidates:
        pii_toml = _RULES_DIR / "pii.toml"
        block_lines = [f"\n# --- training-promoted candidates ({time.strftime('%Y-%m-%d')}) ---"]
        for e in fn_candidates:
            ana = e.get("analysis", {})
            block_lines += [
                f"# rule_id: {e['rule_id']}  confidence: {ana.get('confidence')}",
                f"# reason: {ana.get('reason', '')}",
                f"# preview: {e['preview']}",
                f"# TODO: add regex pattern below",
                f"# [[pattern]]",
                f"# rule_id = \"{e['rule_id']}\"",
                f"# regex = \"FILL_IN_PATTERN\"",
                f"# description = \"{ana.get('reason', '')}\"",
                f"# severity = \"{e['severity']}\"",
                "",
            ]
            print(f"  [FN→pii.toml] {e['rule_id']} (confidence={ana.get('confidence')})")
        if not dry_run:
            with pii_toml.open("a", encoding="utf-8") as f:
                f.write("\n".join(block_lines))

    if fp_candidates:
        allowlist_toml = _RULES_DIR / "allowlist.toml"
        fp_lines = [f"\n# training-promoted FP suppressions ({time.strftime('%Y-%m-%d')})"]
        fp_lines.append("[suppress_rules]")
        for e in fp_candidates:
            ana = e.get("analysis", {})
            fp_lines += [
                f"# confidence={ana.get('confidence')} reason={ana.get('reason', '')}",
                f"{e['rule_id']} = true",
                "",
            ]
            print(f"  [FP→allowlist.toml] {e['rule_id']} (confidence={ana.get('confidence')})")
        if not dry_run:
            with allowlist_toml.open("a", encoding="utf-8") as f:
                f.write("\n".join(fp_lines))

    if not dry_run:
        TRAINING_LOG.write_text("\n".join(entries_raw) + "\n", encoding="utf-8")
        print(f"\ntrain promote: {len(fn_candidates)} FN + {len(fp_candidates)} FP promoted.")
        print("Review rule files, fill in TODO patterns, then commit and push.")
        audit("train_promote", {"fn": len(fn_candidates), "fp": len(fp_candidates)})
    else:
        print(f"\ntrain promote --dry-run: would promote "
              f"{len(fn_candidates)} FN + {len(fp_candidates)} FP.")
    return 0


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
# Verifier CLI commands
# ──────────────────────────────────────────────────────────────────────────

def cmd_verifier(args) -> int:
    """verifier <enable|disable|status> — manage the opt-in LLM cross-check."""
    ensure_state_dir()
    action = args.action

    if action == "enable":
        VERIFIER_CONFIG.write_text('verifier_enabled = true\n', encoding="utf-8")
        print(
            "Verifier enabled. When a block occurs, you'll see a one-line prompt suggestion.\n"
            "Running it pastes a synthetic cross-check into your session — no real content is ever sent."
        )
        return 0

    if action == "disable":
        VERIFIER_CONFIG.write_text('verifier_enabled = false\n', encoding="utf-8")
        print("Verifier disabled.")
        return 0

    if action == "status":
        enabled = verifier_enabled()
        print(f"Verifier is {'enabled' if enabled else 'disabled'}.")
        pending = 0
        if PENDING_VERIFICATIONS.exists():
            try:
                pending = sum(1 for line in PENDING_VERIFICATIONS.read_text().splitlines()
                              if line.strip())
            except Exception:
                pass
        print(f"Pending verifications: {pending}")
        return 0

    print(f"verifier: unknown action '{action}'. Use enable, disable, or status.", file=sys.stderr)
    return 2


def cmd_verify_emit(args) -> int:
    """verify-emit <id> — print a synthetic cross-check prompt to stdout."""
    vid = args.id

    # Look up the pending verification entry
    entry = None
    if PENDING_VERIFICATIONS.exists():
        try:
            for line in PENDING_VERIFICATIONS.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("id") == vid:
                        entry = obj
                        break
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass

    if entry is None:
        print(
            f"verify-emit: ID '{vid}' not found in pending verifications.\n"
            "Check ~/.claude/leak-guard/pending_verifications.jsonl for available IDs.",
            file=sys.stderr,
        )
        return 2

    rule_id = entry.get("rule_id", "unknown")
    category = entry.get("category", "secret")

    # PII rules don't benefit from cross-check
    if _verifier_skip_rule(rule_id, category):
        print(
            f"# leak-guard cross-check: rule '{rule_id}' is pattern-based PII.\n"
            "# PII rules do not benefit from model cross-check — no synthetic needed."
        )
        return 0

    # Generate deterministic seed from the ID string
    seed = hash(vid) & 0x7FFFFFFF

    result = _generate_synthetic(rule_id, seed)
    if result is None:
        print(
            f"# leak-guard cross-check: rule '{rule_id}' is a PII rule.\n"
            "# PII rules do not benefit from model cross-check."
        )
        return 0

    synthetic, decoy1, decoy2 = result

    print("# leak-guard cross-check (no real content — synthetics generated from rule shape only)")
    print(f"# Correlation ID: {vid}  |  Rule: {rule_id}")
    print()
    print(f"[leak-guard cross-check {vid}]")
    print("I need to classify these strings. Reply with exactly one word per line: SECRET or BENIGN.")
    print("Do not explain. Strings:")
    print(f"1. {synthetic}")
    print(f"2. {decoy1}")
    print(f"3. {decoy2}")
    print(f"When done, run: scanner.py verify-ingest {vid} <your-answer-for-string-1>")
    return 0


def cmd_verify_ingest(args) -> int:
    """verify-ingest <id> <verdict> — record model's verdict for a pending verification."""
    vid = args.id
    verdict = args.verdict.upper()
    ingested_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Find and update the entry in pending_verifications.jsonl
    entry = None
    if PENDING_VERIFICATIONS.exists():
        lines = []
        try:
            raw_lines = PENDING_VERIFICATIONS.read_text(encoding="utf-8").splitlines()
            for line in raw_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("id") == vid:
                        obj["verdict"] = verdict
                        entry = obj
                    lines.append(json.dumps(obj))
                except json.JSONDecodeError:
                    lines.append(line)
            PENDING_VERIFICATIONS.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception as e:
            print(f"verify-ingest: could not update pending_verifications.jsonl: {e}", file=sys.stderr)
            return 2

    if entry is None:
        print(f"verify-ingest: ID '{vid}' not found.", file=sys.stderr)
        return 2

    # Append to verifier_feedback.jsonl
    ensure_state_dir()
    feedback = {
        "id": vid,
        "ts": entry.get("ts", ""),
        "rule_id": entry.get("rule_id", ""),
        "verdict": verdict,
        "shape": entry.get("shape", entry.get("rule_id", "")),
        "ingested_at": ingested_at,
    }
    try:
        with VERIFIER_FEEDBACK.open("a", encoding="utf-8") as f:
            f.write(json.dumps(feedback) + "\n")
    except Exception as e:
        print(f"verify-ingest: could not write feedback: {e}", file=sys.stderr)
        return 2

    print(f"Verdict recorded. Use `scanner.py --review` after the next pentest to act on it.")
    return 0


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
    sub.add_parser("install", help="Sync plugin source into the Claude Code plugin cache")
    sub.add_parser("git-hook-pre-push")
    sub.add_parser("selftest")

    # `train` — author-only training pipeline
    tp = sub.add_parser("train", help="[author] Training pipeline: verdict/list/analyze/promote")
    train_sub = tp.add_subparsers(dest="train_cmd", required=True)

    tv = train_sub.add_parser("verdict", help="Label a finding by hash prefix")
    tv.add_argument("hash_prefix")
    tv.add_argument("verdict", choices=sorted(_VALID_VERDICTS))

    tl = train_sub.add_parser("list", help="List training log entries")
    tl.add_argument("--filter", choices=["pending", "fp", "fn", "unclear", "confirm", "all"],
                    default="pending")
    tl.add_argument("--project", default="", help="Filter by source project name substring")

    train_sub.add_parser("analyze", help="Emit LLM prompt to categorize unanalyzed findings")

    ia = train_sub.add_parser("ingest-analysis", help="Record Claude's ANALYSIS responses")
    ia.add_argument("--text", default=None, help="ANALYSIS text (reads stdin if omitted)")

    tpr = train_sub.add_parser("promote", help="Promote high-confidence findings into repo rules")
    tpr.add_argument("--dry-run", action="store_true")

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

    # verifier <enable|disable|status>
    vp = sub.add_parser("verifier", help="Manage the opt-in LLM cross-check verifier")
    vp.add_argument("action", choices=["enable", "disable", "status"])

    # verify-emit <id>
    ve = sub.add_parser("verify-emit", help="Emit a synthetic cross-check prompt for a pending verification")
    ve.add_argument("id")

    # verify-ingest <id> <verdict>
    vi = sub.add_parser("verify-ingest", help="Record the model's verdict for a verification")
    vi.add_argument("id")
    vi.add_argument("verdict", choices=["SECRET", "BENIGN", "UNCERTAIN"])

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
        if args.cmd == "install":
            return cmd_install_plugin()
        if args.cmd == "git-hook-pre-push":
            return cmd_git_hook_pre_push()
        if args.cmd == "selftest":
            return cmd_selftest()
        if args.cmd == "train":
            return cmd_train(args)
        if args.cmd == "flag":
            return cmd_flag(args)
        if args.cmd == "verifier":
            return cmd_verifier(args)
        if args.cmd == "verify-emit":
            return cmd_verify_emit(args)
        if args.cmd == "verify-ingest":
            return cmd_verify_ingest(args)
    except Exception as e:
        audit("scanner_exception", {"cmd": args.cmd, "error": str(e), "tb": traceback.format_exc()[:2000]})
        # Fail-closed for hook events; pass-through for CLI
        if args.cmd.startswith("hook-"):
            if args.cmd == "hook-pre-tool":
                emit_pre_tool("deny", "leak-guard internal error (fail-closed) — check audit log")
                return 2
            elif args.cmd == "hook-user-prompt":
                emit_prompt_block("leak-guard internal error (fail-closed) — check audit log")
                return 2
            elif args.cmd == "hook-post-tool":
                emit_post_tool_block("leak-guard internal error (fail-closed) — check audit log")
                return 0  # PostToolUse block is advisory (return 0, block via stdout)
            else:
                print(f"leak-guard error: {e}", file=sys.stderr)
                return 0
        print(f"leak-guard error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
