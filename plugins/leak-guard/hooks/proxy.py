"""
leak-guard proxy — redaction engine + HTTP proxy server.

Task 1 functions: scan, redact, pending state management.
Task 2 additions: ThreadedHTTPServer, ProxyHandler, _forward logic.
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import signal
import ssl
import sys
import threading
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

import re as _re

# Matches <system-reminder>...</system-reminder> blocks (user-controlled in
# user-role messages — must NOT be trusted to skip scanning).
_SYS_REMINDER_RE = _re.compile(
    r'<system-reminder>[\s\S]*?</system-reminder>', _re.DOTALL,
)


def _strip_system_reminders(text: str) -> str:
    """Remove <system-reminder> blocks from text, return the remainder."""
    return _SYS_REMINDER_RE.sub('', text).strip()


# ──────────────────────────────────────────────────────────────────────────
# Payload helpers
# ──────────────────────────────────────────────────────────────────────────

def get_last_user_text(payload: dict[str, Any]) -> str | None:
    """Return the last user text from the final user message.

    Claude Code wraps user messages in content block arrays and prepends
    <system-reminder> injections. Walk messages in reverse, find the last
    message with role "user", then walk its content blocks in reverse.
    System-reminder tags are stripped — they are user-controlled in user
    role messages and must not be trusted.
    """
    messages = payload.get("messages", [])
    for msg in reversed(messages):
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            cleaned = _strip_system_reminders(content)
            return cleaned if cleaned else None
        if isinstance(content, list):
            for block in reversed(content):
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "text":
                    continue
                text = block.get("text", "")
                cleaned = _strip_system_reminders(text)
                if cleaned:
                    return cleaned
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

    System-reminder tags are stripped before scanning — they are
    user-controlled in user role messages and must not be trusted
    to suppress scanning.

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
            # Strip system-reminder tags; scan the remainder
            scannable = _strip_system_reminders(text) if text.startswith("<system-reminder>") else text
            if not scannable:
                continue
            scannable, block_findings = _redact_text(scannable, allowlist)
            # If the original had system-reminder tags, re-inject them
            if text.startswith("<system-reminder>") and block_findings:
                # Replace findings in the ORIGINAL text (which still has tags)
                for bf in block_findings:
                    text = text.replace(bf["raw"], bf["tag"])
                msg["content"] = text
            else:
                msg["content"] = scannable
            all_findings.extend(block_findings)
        elif isinstance(content, list):
            for i, block in enumerate(content):
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "text":
                    continue
                text = block.get("text", "")
                scannable = _strip_system_reminders(text) if text.startswith("<system-reminder>") else text
                if not scannable:
                    continue
                scannable, block_findings = _redact_text(scannable, allowlist)
                if text.startswith("<system-reminder>") and block_findings:
                    for bf in block_findings:
                        text = text.replace(bf["raw"], bf["tag"])
                    block["text"] = text
                else:
                    block["text"] = scannable
                content[i] = block
                all_findings.extend(block_findings)

    return payload, all_findings


_BASE64_RE = _re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')


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

    # Base64 decode-and-scan: catch encoded secrets that bypass regex patterns.
    import base64 as _b64
    for match in _BASE64_RE.finditer(text):
        blob = match.group()
        if blob.startswith("[REDACTED"):
            continue
        try:
            decoded = _b64.b64decode(blob, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if not decoded or len(decoded) < 8:
            continue
        inner_findings = scan_all(text=decoded, source_label="<proxy-b64>")
        if inner_findings:
            tag = "[REDACTED:encoded-credential]"
            text = text.replace(blob, tag)
            findings_out.append({
                "type": "secret",
                "raw": blob,
                "tag": tag,
                "rule_id": "base64-encoded-secret",
                "confidence": 0.85,
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


# ──────────────────────────────────────────────────────────────────────────
# Runtime counters
# ──────────────────────────────────────────────────────────────────────────

_requests_redacted = 0
_last_activity = time.time()


# ──────────────────────────────────────────────────────────────────────────
# HTTP server
# ──────────────────────────────────────────────────────────────────────────

class ThreadedHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def process_request(self, request, client_address):
        t = threading.Thread(target=self._handle, args=(request, client_address))
        t.daemon = True
        t.start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            pass
        finally:
            self.shutdown_request(request)


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ── routing ──────────────────────────────────────────────────────────

    def do_GET(self):
        if self.path == "/lg-status":
            self._health()
        else:
            self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    # ── health endpoint ───────────────────────────────────────────────────

    def _health(self):
        global _requests_redacted
        snapshot = {}
        if hasattr(self.__class__, "resource_monitor") and self.__class__.resource_monitor is not None:
            snapshot = self.__class__.resource_monitor.snapshot()
        data = {
            "status": "ok" if not snapshot.get("warnings") else "warning",
            "allowlist_size": len(_sc.load_allowlist().literal),
            "requests_redacted": _requests_redacted,
        }
        data.update(snapshot)
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── proxy core ────────────────────────────────────────────────────────

    def _forward(self, method: str):
        global _requests_redacted, _last_activity
        _last_activity = time.time()

        # Read request body
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length else b""

        is_messages = "/v1/messages" in self.path and "count_tokens" not in self.path
        is_count_tokens = "count_tokens" in self.path

        body = raw_body
        payload = None

        # Parse JSON payload for messages/count_tokens endpoints
        if (is_messages or is_count_tokens) and raw_body:
            try:
                payload = json.loads(raw_body)
            except (json.JSONDecodeError, ValueError):
                payload = None

        if payload is not None:
            allowlist = load_allowlist()

            if is_messages:
                handled_pending = False
                user_text = get_last_user_text(payload)
                pending = read_and_clear_pending()

                if pending is not None and user_text is not None:
                    choice = is_allow_response(user_text)
                    if choice == "allow":
                        masked_values = []
                        for f in pending:
                            _append_literal(f["raw"], "user allowed via proxy")
                            masked_values.append(f["tag"])
                        payload = inject_allow_confirmation(payload, masked_values)
                        _requests_redacted += 1
                        handled_pending = True
                    elif choice == "redact":
                        payload = inject_redact_confirmation(payload)
                        handled_pending = True
                    # If choice is None, fall through to normal scan below

                if not handled_pending:
                    # If pending existed but choice was None, re-write pending
                    # so the question remains active, then do normal scan
                    payload, findings = scan_and_redact_payload(payload, allowlist)
                    if findings:
                        payload = inject_system_note_with_question(payload, findings)
                        write_pending(findings)
                        _requests_redacted += 1

            elif is_count_tokens:
                # Silent redact — no pending state, no system note
                payload, _ = scan_and_redact_payload(payload, allowlist)

            body = json.dumps(payload).encode()

        # Build upstream request headers (strip hop-by-hop + force no compression)
        skip_headers = {"host", "transfer-encoding", "content-length", "accept-encoding"}
        upstream_headers: dict[str, str] = {}
        for key, val in self.headers.items():
            if key.lower() not in skip_headers:
                upstream_headers[key] = val
        upstream_headers["Host"] = UPSTREAM_HOST
        upstream_headers["Content-Length"] = str(len(body))
        upstream_headers["Accept-Encoding"] = "identity"

        # Determine streaming
        is_stream = False
        if payload is not None and isinstance(payload, dict):
            is_stream = bool(payload.get("stream", False))

        # Forward to upstream via HTTPS
        try:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(UPSTREAM_HOST, UPSTREAM_PORT, context=ctx)
            conn.request(method, self.path, body=body, headers=upstream_headers)
            resp = conn.getresponse()
        except Exception:
            self._send_502()
            return

        # Send response status and headers
        self.send_response(resp.status)
        skip_resp = {"transfer-encoding", "content-length"}
        for key, val in resp.getheaders():
            if key.lower() not in skip_resp:
                self.send_header(key, val)

        if is_stream:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for line in iter(resp.readline, b""):
                    self.wfile.write(f"{len(line):x}\r\n".encode())
                    self.wfile.write(line)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except Exception:
                pass
        else:
            resp_body = resp.read()
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

        conn.close()

    def _send_502(self):
        body = b'{"error": "bad_gateway"}'
        self.send_response(502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Suppress default BaseHTTPRequestHandler logging
        pass


# ──────────────────────────────────────────────────────────────────────────
# PID management
# ──────────────────────────────────────────────────────────────────────────

def _write_pid(pid: int) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(pid))


def _read_pid():
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def _cleanup_pid(expected_pid: int | None = None) -> None:
    """Remove PID file, but only if it belongs to us.

    If *expected_pid* is given, the file is only deleted when its contents
    match.  This prevents a crashing child from wiping the PID written by
    an earlier, healthy instance.
    """
    try:
        if expected_pid is not None:
            current = _read_pid()
            if current != expected_pid:
                return  # not ours — leave it alone
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def _port_in_use(port: int) -> bool:
    """Check if a TCP port is already bound on localhost."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def is_proxy_running() -> bool:
    pid = _read_pid()
    if pid is not None:
        try:
            os.kill(pid, 0)  # signal 0 = check existence
            return True
        except ProcessLookupError:
            _cleanup_pid()
        except PermissionError:
            return True  # exists but can't signal

    # Fallback: PID file missing/stale but port is held by a previous instance
    if _port_in_use(LISTEN_PORT):
        return True

    return False


# ──────────────────────────────────────────────────────────────────────────
# Inactivity watchdog
# ──────────────────────────────────────────────────────────────────────────

def _inactivity_watchdog(server) -> None:
    while True:
        time.sleep(60)
        if time.time() - _last_activity > _INACTIVITY_TIMEOUT:
            print("[proxy] shutting down after inactivity", file=sys.stderr, flush=True)
            _cleanup_pid()
            server.shutdown()
            break


# ──────────────────────────────────────────────────────────────────────────
# Startup lock
# ──────────────────────────────────────────────────────────────────────────

def _acquire_startup_lock() -> "int | None":
    """Try to acquire an exclusive startup lock via a lockfile.

    Returns the fd on success, None if another process holds it.
    Uses fcntl.flock which is automatically released on process exit / crash.
    """
    import fcntl
    lock_path = STATE_DIR / "proxy.lock"
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except (OSError, IOError):
        return None


def _should_daemonize(daemon_flag: bool) -> bool:
    """Under a supervisor, never self-daemonize — supervisor owns the lifecycle."""
    if os.environ.get("LEAK_GUARD_PROXY_SUPERVISED") == "1":
        return False
    return daemon_flag


# ──────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────

def _cmd_service(action: str) -> None:
    """Handle 'service install|uninstall|status|restart' subcommands."""
    from supervisor import get_adapter
    adapter = get_adapter()
    proxy_path = Path(__file__).resolve()

    if action == "install":
        print("[leak-guard] Installing supervisor service...", flush=True)
        adapter.install(proxy_path)
        print("[leak-guard] Service installed and started.", flush=True)
        print(f"  The proxy will auto-start on login and restart on crash.")
        print(f"  Verify: curl -s http://127.0.0.1:{LISTEN_PORT}/lg-status")
    elif action == "uninstall":
        adapter.uninstall()
        print("[leak-guard] Service removed.", flush=True)
    elif action == "status":
        info = adapter.status()
        print(f"[leak-guard] Supervisor: loaded={info['loaded']} "
              f"running={info['running']} pid={info.get('pid')} "
              f"last_exit={info.get('last_exit')}", flush=True)
    elif action == "restart":
        if adapter.is_installed():
            adapter.restart()
            print("[leak-guard] Restart requested via supervisor.", flush=True)
        else:
            print("[leak-guard] No supervisor installed. Use 'service install' first.",
                  file=sys.stderr, flush=True)
            sys.exit(1)
    else:
        print(f"[leak-guard] Unknown service action: {action}", file=sys.stderr)
        sys.exit(1)


def main():
    import argparse
    parser = argparse.ArgumentParser(prog="leak-guard-proxy")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--port", type=int, default=LISTEN_PORT)
    sub = parser.add_subparsers(dest="command")
    svc = sub.add_parser("service", help="Manage OS-level supervisor (launchd/systemd)")
    svc.add_argument("action", choices=["install", "uninstall", "status", "restart"])
    args = parser.parse_args()

    if args.command == "service":
        _cmd_service(args.action)
        return

    port = args.port

    # Dedup guard — silently exit if an instance is already running.
    if is_proxy_running():
        sys.exit(0)

    if _should_daemonize(args.daemon):
        pid = os.fork()
        if pid > 0:
            print(f"[proxy] started in background (PID {pid})", flush=True)
            sys.exit(0)
        os.setsid()
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        log_file = STATE_DIR / "proxy.log"
        log_fd = os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.dup2(log_fd, 2)

    # Acquire exclusive startup lock — serialises concurrent launches so only
    # one child proceeds past this point.
    lock_fd = _acquire_startup_lock()
    if lock_fd is None:
        sys.exit(0)  # another instance is starting or running

    # Re-check after acquiring lock — another instance may have bound the port
    # while we were racing.
    if _port_in_use(port):
        os.close(lock_fd)
        sys.exit(0)

    # Write PID immediately so concurrent launches see us before server is ready.
    my_pid = os.getpid()
    _write_pid(my_pid)

    # Register atexit cleanup with ownership guard
    import atexit
    atexit.register(_cleanup_pid, expected_pid=my_pid)

    # Wire resource monitor — recycles process on leak/drift thresholds.
    from monitor import ResourceMonitor
    resource_monitor = ResourceMonitor()
    ProxyHandler.resource_monitor = resource_monitor

    def _on_recycle(breach):
        print(
            f"[monitor] recycling: reason={breach.reason} "
            f"value={breach.value} threshold={breach.threshold}",
            file=sys.stderr, flush=True,
        )
        os._exit(75)

    resource_monitor.start(on_recycle=_on_recycle, interval_s=60.0)

    server = ThreadedHTTPServer(("127.0.0.1", port), ProxyHandler)
    print(f"[proxy] listening on http://127.0.0.1:{port}", file=sys.stderr, flush=True)

    wd = threading.Thread(target=_inactivity_watchdog, args=(server,), daemon=True)
    wd.start()

    def _shutdown(signum, frame):
        _cleanup_pid(expected_pid=my_pid)
        # Call shutdown from a thread — calling it directly in a signal
        # handler can deadlock if serve_forever() holds an internal lock.
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _cleanup_pid(expected_pid=my_pid)
        server.shutdown()


if __name__ == "__main__":
    main()
