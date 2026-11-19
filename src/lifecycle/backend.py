#!/usr/bin/env python3
"""
Lifecycle Validation Sidecar Backend.

Instrumented HTTP/1.1 server that runs on the host and provides
separately observable lifecycle phases for each request:

  Phase 1 — context_cancelled:  connection drop detected (select EOF/RST)
  Phase 2 — op_terminated:      work loop exited (operation actually stopped)
  Phase 3 — resource_released:  handler returned, all local cleanup done

Additionally tracks:
  outstanding_cleanups — ops currently live (incremented on work start,
                         decremented when resource_released fires); returns
                         to 0 as cleanup completes after an attack stops.

Routes:
  GET  /stream?duration_s=N — streams chunked response: sends "STARTED\\n"
                               immediately when processing begins, then blocks
                               for N seconds and sends "DONE\\n". Clients
                               use the "STARTED" chunk as an event-driven
                               trigger to send RESET_STREAM at the right time.
  GET  /work?duration_s=N   — blocking request (non-streaming); kept for
                               backward compat.
  GET  /metrics             — JSON snapshot of all counters
  POST /reset               — resets all counters to zero

Usage:
  python -m lifecycle.backend --port 18080
  python src/lifecycle/backend.py --port 18080
"""

import argparse
import json
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse


# ── global counters ───────────────────────────────────────────────────────────

_lock = threading.Lock()

# Running totals (cumulative, never decremented)
_active = 0
_completed = 0
_cancelled = 0
_cleanup_pending = 0       # alias for _cancelled; kept for caller compat
_context_cancelled = 0     # Phase 1: connection drop detected
_op_terminated = 0         # Phase 2: work loop exited
_resource_released = 0     # Phase 3: handler returned

# Current live-ops gauge (decrements as cleanup completes)
_outstanding_cleanups = 0


def _reset() -> None:
    global (_active, _completed, _cancelled, _cleanup_pending,
            _context_cancelled, _op_terminated, _resource_released,
            _outstanding_cleanups)
    with _lock:
        (_active, _completed, _cancelled, _cleanup_pending,
         _context_cancelled, _op_terminated, _resource_released,
         _outstanding_cleanups) = (0,) * 8


def _snapshot() -> dict:
    with _lock:
        return {
            "active": _active,
            "completed": _completed,
            "cancelled": _cancelled,
            "cleanup_pending": _cleanup_pending,
            "context_cancelled": _context_cancelled,
            "op_terminated": _op_terminated,
            "resource_released": _resource_released,
            "outstanding_cleanups": _outstanding_cleanups,
        }


# ── connection drop detection ─────────────────────────────────────────────────

def _poll_connection_alive(conn, interval_s: float = 0.05) -> bool:
    """Return False if the connection has been closed by the peer."""
    try:
        rlist, _, _ = select.select([conn], [], [], interval_s)
        if rlist:
            data = conn.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            return bool(data)      # empty bytes = EOF
    except OSError:
        return False
    return True


# ── request handler ───────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        try:
            duration_s = float(params.get("duration_s", ["1.0"])[0])
        except (ValueError, IndexError):
            duration_s = 1.0

        if parsed.path == "/stream":
            self._handle_stream(duration_s)
        elif parsed.path == "/work":
            self._handle_work(duration_s)
        elif parsed.path == "/metrics":
            self._reply(200, json.dumps(_snapshot()).encode(), "application/json")
        else:
            self._reply(404, b"Not Found")

    def do_POST(self):
        if urlparse(self.path).path == "/reset":
            _reset()
            self._reply(200, b"OK")
        else:
            self._reply(404, b"Not Found")

    # ── /stream — event-driven, chunked response ──────────────────────────────

    def _handle_stream(self, duration_s: float) -> None:
        """
        Chunked streaming endpoint:
          1. Increments outstanding_cleanups (op is now live).
          2. Sends HTTP 200 + "STARTED\\n" chunk immediately.
             The H3 client uses this as the event-driven cancel trigger.
          3. Polls for connection drop while simulating work.
          4. On cancel: fires context_cancelled, op_terminated, resource_released.
          5. On completion: sends "DONE\\n" final chunk.
        """
        global (_active, _completed, _cancelled, _cleanup_pending,
                _context_cancelled, _op_terminated, _resource_released,
                _outstanding_cleanups)

        with _lock:
            _active += 1
            _outstanding_cleanups += 1  # op is now live

        # Send headers + first chunk ("STARTED") — this is the event-driven trigger.
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self._write_chunk(b"STARTED\n")
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Connection dropped before we could send start signal —
            # Scenario B (early cancel before dispatch) ends up here.
            with _lock:
                _active -= 1
                _cancelled += 1
                _cleanup_pending += 1
                _context_cancelled += 1
                _op_terminated += 1
                _resource_released += 1
                _outstanding_cleanups -= 1
            return

        # Simulate backend work, polling for cancellation.
        start = time.monotonic()
        cancelled = False
        while time.monotonic() - start < duration_s:
            if not _poll_connection_alive(self.connection):
                cancelled = True
                with _lock:
                    _context_cancelled += 1   # Phase 1
                break

        with _lock:
            _op_terminated += 1               # Phase 2
            _active -= 1

        if cancelled:
            # Try to send a cancel chunk so the client knows we got the signal.
            try:
                self._write_chunk(b"CANCELLED\n")
                self._write_chunk(b"")        # trailing chunk
            except Exception:
                pass
            with _lock:
                _cancelled += 1
                _cleanup_pending += 1
                _resource_released += 1       # Phase 3
                _outstanding_cleanups -= 1    # op no longer live
            return

        # Normal completion — send final chunk.
        try:
            self._write_chunk(b"DONE\n")
            self._write_chunk(b"")            # trailing chunk
            with _lock:
                _completed += 1
                _resource_released += 1       # Phase 3
                _outstanding_cleanups -= 1
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Connection dropped after we finished work but before sending DONE —
            # proxy cancelled after the backend was already done.
            with _lock:
                _cancelled += 1
                _cleanup_pending += 1
                _context_cancelled += 1
                _resource_released += 1       # Phase 3
                _outstanding_cleanups -= 1

    # ── /work — legacy blocking endpoint ─────────────────────────────────────

    def _handle_work(self, duration_s: float) -> None:
        global (_active, _completed, _cancelled, _cleanup_pending,
                _context_cancelled, _op_terminated, _resource_released,
                _outstanding_cleanups)

        with _lock:
            _active += 1
            _outstanding_cleanups += 1

        start = time.monotonic()
        cancelled = False
        while time.monotonic() - start < duration_s:
            if not _poll_connection_alive(self.connection):
                cancelled = True
                with _lock:
                    _context_cancelled += 1
                break

        with _lock:
            _op_terminated += 1
            _active -= 1

        if cancelled:
            with _lock:
                _cancelled += 1
                _cleanup_pending += 1
                _resource_released += 1
                _outstanding_cleanups -= 1
            return

        try:
            body = b"OK\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            with _lock:
                _completed += 1
                _resource_released += 1
                _outstanding_cleanups -= 1
        except (BrokenPipeError, ConnectionResetError, OSError):
            with _lock:
                _cancelled += 1
                _cleanup_pending += 1
                _context_cancelled += 1
                _resource_released += 1
                _outstanding_cleanups -= 1

    # ── helpers ───────────────────────────────────────────────────────────────

    def _write_chunk(self, data: bytes) -> None:
        """Write one HTTP/1.1 chunked transfer encoding chunk."""
        if data:
            frame = f"{len(data):x}\r\n".encode() + data + b"\r\n"
        else:
            frame = b"0\r\n\r\n"   # trailing chunk
        self.wfile.write(frame)
        self.wfile.flush()

    def _reply(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass


# ── threaded server ───────────────────────────────────────────────────────────

class _ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def serve(port: int = 18080) -> None:
    server = _ThreadedServer(("0.0.0.0", port), _Handler)
    print(f"[lifecycle:backend] listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="HypoGenie lifecycle sidecar backend")
    p.add_argument("--port", type=int, default=18080)
    args = p.parse_args()
    serve(args.port)
