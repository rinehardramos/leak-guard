#!/usr/bin/env python3
"""
leak-guard local proxy — intercepts Anthropic API calls to scan prompts
before they reach the model.

Start:  python3 proxy.py [--port 8787]
Health: GET http://localhost:8787/_leak_guard/health
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import signal
import ssl
import sys
import threading
import urllib.request
from pathlib import Path
from uuid import uuid4

# ──────────────────────────────────────────────────────────────────────────
# Paths — resolve relative to this file so it can be run from any cwd.
# ──────────────────────────────────────────────────────────────────────────

_PROXY_DIR = Path(__file__).resolve().parent          # plugins/leak-guard/
_HOOKS_DIR = _PROXY_DIR / "hooks"
_STATE_DIR = Path(os.environ.get("LEAK_GUARD_STATE_DIR",
                                  Path.home() / ".claude" / "leak-guard"))

_DEFAULT_PORT = int(os.environ.get("LEAK_GUARD_PROXY_PORT", "8787"))

# ──────────────────────────────────────────────────────────────────────────
# Scanner import (lazy, so proxy.py can be imported without the hooks dir
# on sys.path by default)
# ──────────────────────────────────────────────────────────────────────────

_sc = None  # lazy singleton


def _load_scanner():
    global _sc
    if _sc is not None:
        return _sc
    sys.path.insert(0, str(_HOOKS_DIR))
    import scanner as sc
    _sc = sc
    return _sc


# ──────────────────────────────────────────────────────────────────────────
# Synthetic streaming response
# ──────────────────────────────────────────────────────────────────────────

def _new_request_id() -> str:
    return "msg_lg_" + uuid4().hex[:16]


def synthetic_stream(menu_text: str, model: str, request_id: str) -> bytes:
    """Build a complete SSE response body for the action picker menu."""
    events = [
        {"type": "message_start", "message": {
            "id": request_id, "type": "message", "role": "assistant",
            "content": [], "model": model, "stop_reason": None,
            "usage": {"input_tokens": 10, "output_tokens": 0},
        }},
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "text", "text": ""}},
    ]
    for chunk in [menu_text]:
        events.append({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "text_delta", "text": chunk}})
    events.extend([
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta",
         "delta": {"stop_reason": "end_turn", "stop_sequence": None},
         "usage": {"output_tokens": len(menu_text.split())}},
        {"type": "message_stop"},
    ])
    lines = []
    for ev in events:
        lines.append(f"data: {json.dumps(ev)}\n\n")
    return "".join(lines).encode()


def synthetic_json(menu_text: str, model: str, request_id: str) -> bytes:
    """Build a regular JSON response for non-streaming requests."""
    resp = {
        "id": request_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": menu_text}],
        "model": model,
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 10, "output_tokens": len(menu_text.split())},
    }
    return json.dumps(resp).encode()


# ──────────────────────────────────────────────────────────────────────────
# Forwarding
# ──────────────────────────────────────────────────────────────────────────

_UPSTREAM = "https://api.anthropic.com"


def _forward(method: str, path: str, headers: dict, body: bytes | None):
    url = _UPSTREAM + path
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        if k.lower() not in ("host", "content-length"):
            req.add_header(k, v)
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, context=ctx, timeout=120)


# ──────────────────────────────────────────────────────────────────────────
# Extract user text from messages payload
# ──────────────────────────────────────────────────────────────────────────

def _extract_last_user_text(messages: list) -> str:
    """Return text of the last user message, or empty string."""
    for msg in reversed(messages):
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            return "\n".join(parts)
        return str(content)
    return ""


# ──────────────────────────────────────────────────────────────────────────
# Request handler
# ──────────────────────────────────────────────────────────────────────────

class ProxyHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):  # noqa: A002
        # Suppress default per-request logging — we don't log bodies.
        pass

    # ── Health endpoint ────────────────────────────────────────────────────

    def _handle_health(self):
        body = json.dumps({"status": "ok", "pid": os.getpid()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── Main dispatcher ────────────────────────────────────────────────────

    def do_GET(self):
        if self.path == "/_leak_guard/health":
            self._handle_health()
        else:
            self._proxy_transparent("GET", None)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b""

        if self.path == "/v1/messages":
            self._handle_messages(raw_body)
        else:
            self._proxy_transparent("POST", raw_body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b""
        self._proxy_transparent("PUT", raw_body)

    def do_DELETE(self):
        self._proxy_transparent("DELETE", None)

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b""
        self._proxy_transparent("PATCH", raw_body)

    # ── /v1/messages interception ──────────────────────────────────────────

    def _handle_messages(self, raw_body: bytes):
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            # Malformed — forward as-is
            self._proxy_transparent("POST", raw_body)
            return

        messages = body.get("messages", [])
        model = body.get("model", "claude-3-5-sonnet-20241022")
        is_streaming = body.get("stream", False)
        user_text = _extract_last_user_text(messages)

        sc = _load_scanner()

        # ── Turn 2: choice reply? ──────────────────────────────────────────
        choice = sc._is_choice_reply(user_text) if user_text else None
        if choice is not None:
            pending = sc._read_pending_action()
            if pending is not None:
                # Build a modified body with the resolved prompt
                resolved = self._resolve_choice(choice, pending, sc)
                if resolved is None:
                    # Discard — return a synthetic "discarded" message
                    menu_text = "Your prompt was discarded."
                    rid = _new_request_id()
                    self._send_synthetic(menu_text, model, rid, is_streaming)
                    return
                # Replace last user message content with resolved text
                modified_messages = list(messages)
                for i in range(len(modified_messages) - 1, -1, -1):
                    if modified_messages[i].get("role") == "user":
                        modified_messages[i] = dict(modified_messages[i])
                        modified_messages[i]["content"] = resolved
                        break
                modified_body = dict(body)
                modified_body["messages"] = modified_messages
                self._proxy_transparent("POST", json.dumps(modified_body).encode(),
                                        content_type=self.headers.get("Content-Type",
                                                                       "application/json"))
                return

        # ── Turn 1: scan for secrets/PII ──────────────────────────────────
        findings = sc.scan_all(text=user_text, source_label="<proxy>") if user_text else []
        if findings:
            sc._write_pending_action(user_text, findings)
            menu_text = sc._build_menu_text(findings)
            rid = _new_request_id()
            self._send_synthetic(menu_text, model, rid, is_streaming)
            return

        # ── Clean: transparent forward ─────────────────────────────────────
        self._proxy_transparent("POST", raw_body)

    def _resolve_choice(self, choice: str, pending: dict, sc) -> str | None:
        """Return resolved prompt text, or None to discard. Also cleans pending file."""
        try:
            sc.PENDING_ACTION.unlink(missing_ok=True)
        except Exception:
            pass

        original = pending.get("prompt", "")
        redact_targets = pending.get("redact_targets", [])

        if choice == "A":
            return original
        if choice == "R":
            redacted = original
            for target in redact_targets:
                if target:
                    redacted = redacted.replace(target, "[REDACTED]")
            return redacted
        if choice == "F":
            # Flag as false positive, then allow
            for target in redact_targets:
                if target:
                    try:
                        import subprocess
                        subprocess.run(
                            [sys.executable, str(_HOOKS_DIR / "scanner.py"),
                             "flag", "fp", "--literal", target,
                             "--reason", "user marked FP via proxy action picker"],
                            capture_output=True, timeout=10,
                        )
                    except Exception:
                        pass
            return original
        # D or anything else
        return None

    def _send_synthetic(self, menu_text: str, model: str, rid: str, streaming: bool):
        if streaming:
            body = synthetic_stream(menu_text, model, rid)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = synthetic_json(menu_text, model, rid)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # ── Transparent proxy ──────────────────────────────────────────────────

    def _proxy_transparent(self, method: str, body: bytes | None, content_type: str | None = None):
        headers = dict(self.headers)
        if content_type is not None:
            headers["Content-Type"] = content_type
        try:
            resp = _forward(method, self.path, headers, body)
        except urllib.error.HTTPError as exc:
            # Forward the upstream error response as-is
            self.send_response(exc.code)
            for k, v in exc.headers.items():
                if k.lower() in ("transfer-encoding",):
                    continue
                self.send_header(k, v)
            self.end_headers()
            err_body = exc.read()
            self.wfile.write(err_body)
            return
        except Exception as exc:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": f"leak-guard proxy: upstream error: {exc}"}).encode()
            )
            return

        self.send_response(resp.status)
        for k, v in resp.headers.items():
            if k.lower() in ("transfer-encoding",):
                continue
            self.send_header(k, v)
        self.end_headers()

        # Stream response back in 4 KB chunks
        chunk_size = 4096
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            try:
                self.wfile.write(chunk)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                break


# ──────────────────────────────────────────────────────────────────────────
# Server lifecycle
# ──────────────────────────────────────────────────────────────────────────

import urllib.error  # noqa: E402 — placed after handler for clarity


def _write_pid(port: int) -> Path:
    _STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    pid_file = _STATE_DIR / "proxy.pid"
    fd = os.open(str(pid_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(str(os.getpid()))
    return pid_file


def _remove_pid(pid_file: Path) -> None:
    try:
        pid_file.unlink(missing_ok=True)
    except Exception:
        pass


def run_proxy(port: int) -> None:
    server = http.server.HTTPServer(("127.0.0.1", port), ProxyHandler)
    server.allow_reuse_address = True

    pid_file = _write_pid(port)

    def _shutdown(signum, frame):
        _remove_pid(pid_file)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(f"leak-guard proxy listening on http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    finally:
        _remove_pid(pid_file)


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="proxy.py",
        description="leak-guard local proxy — intercepts Anthropic API calls.",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=_DEFAULT_PORT,
        help=f"Port to listen on (default: {_DEFAULT_PORT}, env: LEAK_GUARD_PROXY_PORT)",
    )
    args = parser.parse_args(argv)
    run_proxy(args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
