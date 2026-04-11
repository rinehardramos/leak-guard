"""
leak-guard proxy core — redaction engine (Task 1).

Functions used by the HTTP proxy to scan, redact, and manage pending state.
HTTP server, threading, and daemon code are in separate tasks.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import scanner as _sc

from scanner import (
    scan_all,
    _scan_ner_candidates,
    load_allowlist,
    _confidence,
    _redaction_tag,
    _append_literal,
    Allowlist,
    Finding,
)

# ──────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────

LISTEN_PORT = int(os.environ.get("LEAK_GUARD_PROXY_PORT", "18019"))
UPSTREAM_HOST = "api.anthropic.com"
UPSTREAM_PORT = 443
STATE_DIR = _sc.STATE_DIR
PENDING_FILE = STATE_DIR / "pending.json"
PID_FILE = STATE_DIR / "proxy.pid"
_PENDING_TTL = 300           # 5 minutes
_INACTIVITY_TIMEOUT = 4 * 3600  # 4 hours


# ──────────────────────────────────────────────────────────────────────────
# Payload helpers
# ──────────────────────────────────────────────────────────────────────────

def get_last_user_text(payload: dict[str, Any]) -> str | None:
    """Return the last user text block that is not a <system-reminder>.

    Claude Code wraps user messages in content block arrays and prepends
    <system-reminder> injections. Walk messages in reverse, find the last
    message with role "user", then walk its content blocks in reverse and
    return the first text block whose content does not start with
    "<system-reminder>".
    """
    messages = payload.get("messages", [])
    for msg in reversed(messages):
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        # Content can be a plain string or a list of content blocks
        if isinstance(content, str):
            if not content.startswith("<system-reminder>"):
                return content
            return None
        if isinstance(content, list):
            for block in reversed(content):
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "text":
                    continue
                text = block.get("text", "")
                if not text.startswith("<system-reminder>"):
                    return text
    return None


def is_allow_response(text: str) -> str | None:
    """Classify a user reply as "allow", "redact", or None.

    Returns:
        "allow"  — text is one of: a, allow, yes, y (case-insensitive)
        "redact" — text is one of: r, redact, no, n  (case-insensitive)
        None     — empty, >50 chars, or unrecognised
    """
    stripped = text.strip()
    if not stripped:
        return None
    if len(stripped) > 50:
        return None
    lowered = stripped.lower()
    if lowered in {"a", "allow", "yes", "y"}:
        return "allow"
    if lowered in {"r", "redact", "no", "n"}:
        return "redact"
    return None


# ──────────────────────────────────────────────────────────────────────────
# Core redaction
# ──────────────────────────────────────────────────────────────────────────

def scan_and_redact_payload(
    payload: dict[str, Any],
    allowlist: Allowlist,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Scan all user message text blocks and redact findings in place.

    Skips:
    - Non-user messages (role != "user")
    - Text blocks starting with "<system-reminder>"

    For each finding whose raw_match is not in allowlist.literal, replaces
    the raw value with _redaction_tag(finding) in the text block.

    Returns:
        (modified_payload, findings_list)

    Each entry in findings_list is a dict with keys:
        type, raw, tag, rule_id, confidence
    """
    import copy
    payload = copy.deepcopy(payload)
    all_findings: list[dict[str, Any]] = []

    messages = payload.get("messages", [])
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            text = content
            if text.startswith("<system-reminder>"):
                continue
            text, block_findings = _redact_text(text, allowlist)
            msg["content"] = text
            all_findings.extend(block_findings)
        elif isinstance(content, list):
            for i, block in enumerate(content):
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "text":
                    continue
                text = block.get("text", "")
                if text.startswith("<system-reminder>"):
                    continue
                text, block_findings = _redact_text(text, allowlist)
                block["text"] = text
                content[i] = block
                all_findings.extend(block_findings)

    return payload, all_findings


def _redact_text(
    text: str,
    allowlist: Allowlist,
) -> tuple[str, list[dict[str, Any]]]:
    """Scan a single text block and apply redactions. Returns (redacted_text, findings)."""
    raw_findings: list[Finding] = scan_all(text=text, source_label="<proxy>")
    raw_findings += _scan_ner_candidates(text, source="<proxy>")

    findings_out: list[dict[str, Any]] = []
    for f in raw_findings:
        raw = f.raw_match
        if not raw:
            continue
        if raw in allowlist.literal:
            continue
        tag = _redaction_tag(f)
        text = text.replace(raw, tag)
        findings_out.append({
            "type": f.category,
            "raw": raw,
            "tag": tag,
            "rule_id": f.rule_id,
            "confidence": _confidence(f),
        })
    return text, findings_out


# ──────────────────────────────────────────────────────────────────────────
# System note injection
# ──────────────────────────────────────────────────────────────────────────

_REDACTION_NOTE_TEMPLATE = (
    "[leak-guard] The following were redacted from your message: {tags}. "
    "Reply 'a' to allow (add to allowlist) or 'r' to keep redacted."
)

_ALLOW_CONFIRMATION_TEMPLATE = (
    "[leak-guard] Allowlisted: {masked}. The original values will pass through in future messages."
)

_REDACT_CONFIRMATION = (
    "[leak-guard] Continuing with redacted values. The originals were not sent."
)


def _append_system_note(payload: dict[str, Any], note: str) -> dict[str, Any]:
    """Append *note* to the payload's system field. Handles str, list, and missing."""
    system = payload.get("system")
    if system is None:
        payload["system"] = note
    elif isinstance(system, str):
        payload["system"] = system + "\n\n" + note
    elif isinstance(system, list):
        payload["system"] = system + [{"type": "text", "text": note}]
    else:
        payload["system"] = str(system) + "\n\n" + note
    return payload


def inject_system_note_with_question(
    payload: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Append a redaction notice to the system field.

    NEVER includes raw values — only the redaction tags.
    """
    tags = ", ".join(sorted({f["tag"] for f in findings}))
    note = _REDACTION_NOTE_TEMPLATE.format(tags=tags)
    return _append_system_note(payload, note)


def inject_allow_confirmation(
    payload: dict[str, Any],
    masked_values: list[str],
) -> dict[str, Any]:
    """Append a confirmation note that the allowlist was updated."""
    masked = ", ".join(masked_values)
    note = _ALLOW_CONFIRMATION_TEMPLATE.format(masked=masked)
    return _append_system_note(payload, note)


def inject_redact_confirmation(payload: dict[str, Any]) -> dict[str, Any]:
    """Append a confirmation note that redaction will continue."""
    return _append_system_note(payload, _REDACT_CONFIRMATION)


# ──────────────────────────────────────────────────────────────────────────
# Pending state (findings waiting for user allow/redact decision)
# ──────────────────────────────────────────────────────────────────────────

def write_pending(findings: list[dict[str, Any]]) -> None:
    """Write findings to PENDING_FILE with a timestamp. Mode 0o600."""
    _sc.ensure_state_dir()
    record = {
        "ts": time.time(),
        "findings": findings,
    }
    data = json.dumps(record)
    PENDING_FILE.write_text(data, encoding="utf-8")
    PENDING_FILE.chmod(0o600)


def read_and_clear_pending() -> list[dict[str, Any]] | None:
    """Read pending.json, delete it, and return findings.

    Returns None if the file is missing or older than _PENDING_TTL seconds.
    """
    if not PENDING_FILE.exists():
        return None
    try:
        data = json.loads(PENDING_FILE.read_text(encoding="utf-8"))
        PENDING_FILE.unlink()
    except (OSError, json.JSONDecodeError):
        return None

    ts = data.get("ts", 0.0)
    if time.time() - ts > _PENDING_TTL:
        return None
    return data.get("findings")
