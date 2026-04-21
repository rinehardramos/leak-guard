#!/usr/bin/env python3
"""TUI compatibility test — verifies leak-guard proxy handles opencode + gemini-cli traffic.

Architecture:
  1. Mock backend (records requests, returns stub responses)
  2. leak-guard proxy (configured to forward to mock backend, TLS off)
  3. Test client (sends requests in Anthropic + Gemini formats)

Checks both correct proxying AND leak-guard-specific secret redaction.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import sys
import threading
import time

# ── Mock backend ──────────────────────────────────────────────────────────

_received: list[dict] = []  # thread-safe enough for sequential tests
_received_lock = threading.Lock()


class MockBackendHandler(http.server.BaseHTTPRequestHandler):
    """Records request bodies and returns stub API responses."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body)
        except Exception:
            payload = None

        with _received_lock:
            _received.append({
                "path": self.path,
                "body": body.decode("utf-8", errors="replace"),
                "payload": payload,
                "headers": dict(self.headers),
            })

        # Return a stub response appropriate to the API format
        if "/v1/messages" in self.path:
            resp = {
                "id": "msg_stub",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "stub response"}],
                "model": "stub",
                "stop_reason": "end_turn",
            }
        elif "/v1beta/models/" in self.path or "/v1/models/" in self.path:
            resp = {
                "candidates": [{"content": {"parts": [{"text": "stub response"}]}}],
            }
        else:
            resp = {"status": "ok"}

        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.do_POST()

    def log_message(self, fmt, *args):
        pass


def _free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── Test helpers ──────────────────────────────────────────────────────────

def _clear():
    with _received_lock:
        _received.clear()


def _last_payload() -> dict | None:
    with _received_lock:
        return _received[-1]["payload"] if _received else None


def _last_body() -> str:
    with _received_lock:
        return _received[-1]["body"] if _received else ""


def _send(proxy_port: int, method: str, path: str,
          payload: dict | None = None) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    body = json.dumps(payload).encode() if payload else None
    headers = {"Content-Type": "application/json"}
    if body:
        headers["Content-Length"] = str(len(body))
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    resp.read()  # consume body
    conn.close()
    return resp


# ── Credential builders (halves assembled at runtime) ─────────────────────

def _aws():
    return "AKIA" + "Y3FDSNDK" + "FKSIDJSW"

def _ssn():
    return "078" + "-" + "05" + "-" + "1120"

def _db():
    # Assemble from fragments to avoid static pattern detection
    scheme = "postgres" + "://"
    creds = "admin" + ":" + "s3cr3t" + "P@ss"
    host = "@db" + ".internal" + ":5432" + "/prod"
    return scheme + creds + host

def _ghp():
    return "ghp_" + "A1b2C3d4" + "E5f6G7h8" + "I9j0K1l2" + "M3n4O5p6"


# ── Anthropic-format payload builders (opencode) ─────────────────────────

def _anthropic_payload(user_text: str, stream: bool = False) -> dict:
    return {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "stream": stream,
        "messages": [{"role": "user", "content": user_text}],
    }


def _anthropic_blocks_payload(blocks: list[dict]) -> dict:
    return {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": blocks}],
    }


# ── Gemini-format payload builders (gemini-cli) ──────────────────────────

def _gemini_payload(user_text: str) -> dict:
    return {
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 1024},
    }


def _gemini_multi_turn(*texts: str) -> dict:
    contents = []
    for i, text in enumerate(texts):
        role = "user" if i % 2 == 0 else "model"
        contents.append({"role": role, "parts": [{"text": text}]})
    return {"contents": contents}


def _gemini_with_system(user_text: str, system_text: str) -> dict:
    return {
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "systemInstruction": {"parts": [{"text": system_text}]},
        "generationConfig": {"temperature": 0.7},
    }


# ── Test vectors ──────────────────────────────────────────────────────────

class R:
    """Result tracker."""
    def __init__(self, name: str, cat: str):
        self.name = name
        self.cat = cat
        self.ok = False
        self.detail = ""
        self.sev = ""

    def p(self, detail: str = "") -> "R":
        self.ok = True
        self.detail = detail
        return self

    def f(self, detail: str, sev: str = "HIGH") -> "R":
        self.ok = False
        self.detail = detail
        self.sev = sev
        return self


def run_tests(proxy_port: int) -> list[R]:
    results: list[R] = []

    # ── opencode (Anthropic format) ──────────────────────────────────

    # 1. Clean payload forwarded correctly
    r = R("opencode-clean-forward", "opencode")
    _clear()
    _send(proxy_port, "POST", "/v1/messages",
          _anthropic_payload("Hello, world"))
    p = _last_payload()
    if p and p.get("messages", [{}])[0].get("content") == "Hello, world":
        r.p("clean text forwarded intact")
    else:
        r.f("clean text modified or lost")
    results.append(r)

    # 2. AWS key in user message redacted at backend
    r = R("opencode-aws-redacted", "opencode")
    key = _aws()
    _clear()
    _send(proxy_port, "POST", "/v1/messages",
          _anthropic_payload("key is " + key))
    body = _last_body()
    if key not in body:
        r.p("AWS key redacted before reaching backend")
    else:
        r.f("AWS key leaked to backend", "CRITICAL")
    results.append(r)

    # 3. SSN in content blocks redacted
    r = R("opencode-ssn-blocks-redacted", "opencode")
    ssn = _ssn()
    _clear()
    _send(proxy_port, "POST", "/v1/messages",
          _anthropic_blocks_payload([
              {"type": "text", "text": "SSN: " + ssn}
          ]))
    body = _last_body()
    if ssn not in body:
        r.p("SSN redacted in content blocks")
    else:
        r.f("SSN leaked in content blocks", "CRITICAL")
    results.append(r)

    # 4. Streaming flag preserved
    r = R("opencode-stream-flag", "opencode")
    _clear()
    _send(proxy_port, "POST", "/v1/messages",
          _anthropic_payload("test", stream=True))
    p = _last_payload()
    if p and p.get("stream") is True:
        r.p("stream=true preserved")
    else:
        r.f("stream flag lost or modified")
    results.append(r)

    # 5. DB connection string redacted
    r = R("opencode-db-conn-redacted", "opencode")
    db = _db()
    _clear()
    _send(proxy_port, "POST", "/v1/messages",
          _anthropic_payload("connect to " + db))
    body = _last_body()
    if db not in body:
        r.p("DB connection string redacted")
    else:
        r.f("DB connection string leaked", "CRITICAL")
    results.append(r)

    # ── gemini-cli (Gemini format) ───────────────────────────────────

    # 6. Clean Gemini payload forwarded correctly
    r = R("gemini-clean-forward", "gemini")
    _clear()
    _send(proxy_port, "POST",
          "/v1beta/models/gemini-2.5-pro:generateContent",
          _gemini_payload("Hello from Gemini"))
    p = _last_payload()
    text = (p or {}).get("contents", [{}])[0].get(
        "parts", [{}])[0].get("text", "")
    if text == "Hello from Gemini":
        r.p("clean Gemini text forwarded intact")
    else:
        r.f("clean Gemini text modified or lost")
    results.append(r)

    # 7. AWS key in Gemini parts redacted
    r = R("gemini-aws-redacted", "gemini")
    key = _aws()
    _clear()
    _send(proxy_port, "POST",
          "/v1beta/models/gemini-2.5-pro:generateContent",
          _gemini_payload("my AWS key: " + key))
    body = _last_body()
    if key not in body:
        r.p("AWS key redacted in Gemini payload")
    else:
        r.f("AWS key leaked in Gemini payload", "CRITICAL")
    results.append(r)

    # 8. SSN in Gemini payload redacted
    r = R("gemini-ssn-redacted", "gemini")
    ssn = _ssn()
    _clear()
    _send(proxy_port, "POST",
          "/v1beta/models/gemini-2.5-pro:generateContent",
          _gemini_payload("SSN is " + ssn))
    body = _last_body()
    if ssn not in body:
        r.p("SSN redacted in Gemini payload")
    else:
        r.f("SSN leaked in Gemini payload", "CRITICAL")
    results.append(r)

    # 9. DB connection in Gemini redacted
    r = R("gemini-db-conn-redacted", "gemini")
    db = _db()
    _clear()
    _send(proxy_port, "POST",
          "/v1beta/models/gemini-2.5-pro:generateContent",
          _gemini_payload("use " + db))
    body = _last_body()
    if db not in body:
        r.p("DB conn redacted in Gemini payload")
    else:
        r.f("DB conn leaked in Gemini payload", "CRITICAL")
    results.append(r)

    # 10. Multi-turn Gemini: user turns scanned, model turns untouched
    r = R("gemini-multi-turn", "gemini")
    key = _aws()
    _clear()
    _send(proxy_port, "POST",
          "/v1beta/models/gemini-2.5-pro:generateContent",
          _gemini_multi_turn("store " + key, "OK stored", "now use it"))
    body = _last_body()
    p = _last_payload()
    if key not in body and p and \
       p["contents"][1]["parts"][0]["text"] == "OK stored":
        r.p("user turn redacted, model turn preserved")
    elif key in body:
        r.f("AWS key survived multi-turn scan", "CRITICAL")
    else:
        r.f("model turn was modified")
    results.append(r)

    # 11. System instruction scanned
    r = R("gemini-system-instruction", "gemini")
    ghp = _ghp()
    _clear()
    _send(proxy_port, "POST",
          "/v1beta/models/gemini-2.5-pro:generateContent",
          _gemini_with_system("hello", "use token " + ghp))
    body = _last_body()
    if ghp not in body:
        r.p("system instruction secret redacted")
    else:
        r.f("system instruction secret leaked", "CRITICAL")
    results.append(r)

    # 12. /v1/models/ path also detected as Gemini
    r = R("gemini-v1-models-path", "gemini")
    key = _aws()
    _clear()
    _send(proxy_port, "POST",
          "/v1/models/gemini-2.5-pro:generateContent",
          _gemini_payload("key=" + key))
    body = _last_body()
    if key not in body:
        r.p("/v1/models/ path scanned correctly")
    else:
        r.f("/v1/models/ path not scanned", "HIGH")
    results.append(r)

    # ── Cross-cutting ────────────────────────────────────────────────

    # 13. Health endpoint returns JSON
    r = R("health-endpoint", "infra")
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
    conn.request("GET", "/lg-status")
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()
    if resp.status == 200 and "status" in data:
        r.p("status=" + str(data["status"]))
    else:
        r.f("health returned " + str(resp.status))
    results.append(r)

    # 14. Non-API path forwarded transparently
    r = R("non-api-forward", "infra")
    _clear()
    _send(proxy_port, "POST", "/some/other/path", {"foo": "bar"})
    body = _last_body()
    if "bar" in body:
        r.p("non-API path forwarded transparently")
    else:
        r.f("non-API path not forwarded")
    results.append(r)

    return results


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    # Add plugin source to path
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.join(here, "..", "..")
    hooks_dir = os.path.join(root, "plugins", "leak-guard", "hooks")
    sys.path.insert(0, hooks_dir)

    import proxy as px

    # Start mock backend
    mock_port = _free_port()
    mock_server = http.server.HTTPServer(
        ("127.0.0.1", mock_port), MockBackendHandler)
    mock_thread = threading.Thread(
        target=mock_server.serve_forever, daemon=True)
    mock_thread.start()

    # Configure proxy to forward to mock backend (no TLS)
    px.UPSTREAM_HOST = "127.0.0.1"
    px.UPSTREAM_PORT = mock_port
    px.UPSTREAM_TLS = False
    px.GEMINI_UPSTREAM_HOST = "127.0.0.1"
    px.GEMINI_UPSTREAM_PORT = mock_port
    px.GEMINI_UPSTREAM_TLS = False

    # Start proxy
    proxy_port = _free_port()
    proxy_server = px.ThreadedHTTPServer(
        ("127.0.0.1", proxy_port), px.ProxyHandler)
    proxy_thread = threading.Thread(
        target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    time.sleep(0.3)

    print("=" * 60)
    print("  leak-guard TUI Compatibility Test")
    print("  proxy=%d  mock_backend=%d" % (proxy_port, mock_port))
    print("=" * 60)
    print()

    results = run_tests(proxy_port)

    # Report
    failures = 0
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        sev = " [%s]" % r.sev if r.sev else ""
        print("  %s  %-10s %-35s %s%s" % (
            status, r.cat, r.name, r.detail, sev))
        if not r.ok:
            failures += 1

    print()
    print("=" * 60)
    if failures:
        print("  %d FAILED out of %d" % (failures, len(results)))
    else:
        print("  All %d tests passed" % len(results))
    print("=" * 60)

    # Cleanup
    proxy_server.shutdown()
    mock_server.shutdown()

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
