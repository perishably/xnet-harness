"""Authenticated loopback dashboard; supplied callbacks own worker lifecycle.

No process/model launch or command interpretation occurs in this adapter.
Every control verifies the supplied signed scope and appends private audit
evidence. Stop callbacks must close dispatch admission before returning.
"""
from __future__ import annotations

import collections
import hmac
import json
import math
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from xnet.ledger import Ledger
from xnet.oroboros_public_export import _safe_path
from xnet.protocol import canonical, digest, make_event
from xnet.scope import ScopeAuthority, ScopeError
from xnet.workflow import ToolRegistry

ASSETS = Path(__file__).resolve().parent / "assets"
STATES = {"idle", "running", "draining", "pending", "stopped", "failed",
          "budget_exhausted", "curriculum_exhausted"}
REQUIRED = {"state", "active", "accepting", "completed_tasks", "pending_tasks"}
COUNTS = {"completed_tasks", "pending_tasks", "remaining_tasks", "max_tasks",
          "completed_epochs", "max_epochs", "coach_calls", "worker_calls",
          "input_tokens", "output_tokens", "worker_pid", "gateway_pid",
          "updated_at", "submitted_tasks", "failed_tasks", "tasks_per_day",
          "home_completed", "home_total", "home_first_correct", "home_final_correct"}
TEXT = {"detail", "task_id", "run_id", "model", "profile", "last_receipt",
        "deadline_utc", "updated_at_utc", "runtime_dir"}
FLAGS = {"active", "accepting", "gateway_owned", "model_running"}
OPTIONAL = COUNTS | TEXT | FLAGS | {"wall_seconds", "worker_exit_code"}

class DojoError(ValueError):
    pass

class DojoRateError(DojoError):
    pass

class DojoTools(ToolRegistry):
    METHODS = {"dojo_start": False, "dojo_stop": False,
               "dojo_status": False, "dojo_serve": False}

def _snapshot(value: dict) -> dict:
    if type(value) is not dict or not REQUIRED <= set(value) or set(value) - (REQUIRED | OPTIONAL):
        raise DojoError("caller status fields do not match the Dojo contract")
    if type(value["state"]) is not str or value["state"] not in STATES:
        raise DojoError("unknown caller status")
    for name in FLAGS & set(value):
        if type(value[name]) is not bool:
            raise DojoError("status flags must be booleans")
    for name in COUNTS & set(value):
        if type(value[name]) is not int or not 0 <= value[name] <= 2**63 - 1:
            raise DojoError("status counts must be bounded nonnegative integers")
    for name in TEXT & set(value):
        if (type(value[name]) is not str or len(value[name]) > 2048
                or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value[name])):
            raise DojoError("status text must be bounded plain text")
    if "wall_seconds" in value and (type(value["wall_seconds"]) not in (int, float)
            or not math.isfinite(value["wall_seconds"]) or not 0 <= value["wall_seconds"] <= 1e12):
        raise DojoError("wall_seconds must be bounded elapsed time")
    if "worker_exit_code" in value and (value["worker_exit_code"] is not None
            and (type(value["worker_exit_code"]) is not int or not -(2**31) <= value["worker_exit_code"] < 2**32)):
        raise DojoError("worker exit code must be an integer or null")
    if value["state"] in {"idle", "stopped", "budget_exhausted", "curriculum_exhausted"} and (value["active"] or value["accepting"]):
        raise DojoError("terminal status cannot claim an active or accepting worker")
    if value["state"] == "draining" and (not value["active"] or value["accepting"]):
        raise DojoError("draining must retain active work with dispatch closed")
    if len(canonical(value)) > 16384:
        raise DojoError("status exceeds byte bound")
    return json.loads(canonical(value))

class DojoController:
    def __init__(self, *, start: Callable[[], dict], stop: Callable[[], dict],
                 status: Callable[[], dict], authority: ScopeAuthority,
                 scope_id: str, audit_dir: Path):
        if any(not callable(callback) for callback in (start, stop, status)):
            raise DojoError("three explicit caller-owned callbacks required")
        self.audit_dir = _safe_path(Path(audit_dir))
        self.tools = DojoTools(authority)
        self.scope_id = scope_id
        self.target = "path:" + str(self.audit_dir)
        self.tools.gate(scope_id, "dojo_status", self.target)
        self.ledger = Ledger(self.audit_dir)
        self.ledger.verify_chain()
        self.callbacks = {"start": start, "stop": stop, "status": status}
        self._lock = threading.Lock()
        self._requests = collections.deque()

    def admit_server(self) -> None:
        self.tools.gate(self.scope_id, "dojo_serve", self.target)

    def call(self, action: str) -> dict:
        if action not in self.callbacks:
            raise DojoError("fixed start, stop or status action required")
        with self._lock:
            manifest = self.tools.gate(self.scope_id, "dojo_" + action, self.target)
            now = time.monotonic()
            while self._requests and self._requests[0] <= now - 60:
                self._requests.popleft()
            if len(self._requests) >= manifest["requests_per_minute"]:
                raise DojoRateError("scope rate limit reached")
            self._requests.append(now)
            admitted = self.ledger.append(make_event("dojo-control", self.scope_id, "dojo.control.admitted",
                {"action": action}, source="dojo-dashboard"))
            try:
                snapshot = _snapshot(self.callbacks[action]())
                if action == "stop" and snapshot["accepting"]:
                    raise DojoError("stop callback must prevent the next dispatch before returning")
            except Exception as error:
                self.ledger.append(make_event("dojo-control", self.scope_id, "dojo.control.failed",
                    {"action": action, "error_type": type(error).__name__,
                     "admission_receipt": admitted["receipt_hash"]}, source="dojo-dashboard"))
                raise
            receipt = self.ledger.append(make_event("dojo-control", self.scope_id, "dojo.control.completed",
                {"action": action, "state": snapshot["state"], "snapshot_sha256": digest(snapshot),
                 "admission_receipt": admitted["receipt_hash"]}, source="dojo-dashboard"))
            return {"schema": "xnet.dojo-control.v1", "ok": True, "status": snapshot,
                    "audit_receipt_sha256": receipt["receipt_hash"]}

def make_server(controller: DojoController, *, port: int = 0,
                token: str | None = None) -> ThreadingHTTPServer:
    if type(port) is not int or not 0 <= port <= 65535:
        raise DojoError("bounded local port required")
    if token is None:
        token = secrets.token_hex(32)
    if type(token) is not str or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise DojoError("private 32-byte hexadecimal token required")
    controller.admit_server()
    assets = {}
    for route, filename, mime in (("/", "index.html", "text/html; charset=utf-8"),
                                   ("/app.js", "app.js", "text/javascript; charset=utf-8"),
                                   ("/style.css", "style.css", "text/css; charset=utf-8")):
        path = _safe_path(ASSETS / filename, ASSETS)
        with path.open("rb") as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise DojoError("fixed dashboard asset byte bound exceeded")
        assets[route] = (raw, mime)

    class Handler(BaseHTTPRequestHandler):
        server_version = "XNETDojo/1"

        def setup(self):
            super().setup()
            self.connection.settimeout(5)
            self._body_consumed = False

        def log_message(self, *args):
            pass  # Never log Authorization, private fragments or request bodies.

        def _send(self, code, body, mime="application/json"):
            # Closing a Windows socket with a small unread POST can reset the
            # denial response. Discard at most 4 KiB of a declared rejected
            # body without parsing any framing/content. The connection then
            # closes; contents never reach a callback or an audit payload.
            if code >= 400 and self.command == "POST" and not self._body_consumed:
                length = self._header("Content-Length")
                if (type(length) is str and re.fullmatch(r"[0-9]{1,4}", length)
                        and 0 <= int(length) <= 4096):
                    try:
                        self._body_consumed = True
                        self.rfile.read(int(length))
                    except OSError:
                        pass
            raw = canonical(body) if type(body) is dict else body
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def _header(self, name):
            values = self.headers.get_all(name, [])
            return values[0] if len(values) == 1 else None

        def _peer(self, *, origin_required=False):
            expected_host = "127.0.0.1:" + str(self.server.server_port)
            origin = self._header("Origin")
            return (self.client_address[0] == "127.0.0.1"
                    and self._header("Host") == expected_host
                    and len(self.headers.get_all("Origin", [])) <= 1
                    and len(self.headers.get_all("Sec-Fetch-Site", [])) <= 1
                    and (origin == "http://" + expected_host if origin_required else origin in (None, "http://" + expected_host))
                    and self._header("Sec-Fetch-Site") in (None, "same-origin", "none"))

        def do_GET(self):
            if not self._peer():
                self._send(403, {"ok": False, "error": "peer_rejected"})
            elif self.path in assets:
                self._send(200, *assets[self.path])
            else:
                self._send(404, {"ok": False, "error": "unavailable"})

        def do_POST(self):
            if not self._peer(origin_required=True):
                self._send(403, {"ok": False, "error": "origin_rejected"})
                return
            auth = self._header("Authorization")
            if type(auth) is not str or not hmac.compare_digest(auth.encode("utf-8"), ("Bearer " + token).encode("ascii")):
                self._send(401, {"ok": False, "error": "unauthorized"})
                return
            actions = {"/api/start": "start", "/api/stop": "stop", "/api/status": "status"}
            if self.path not in actions:
                self._send(404, {"ok": False, "error": "unavailable"})
                return
            length = self._header("Content-Length")
            if (self.headers.get_all("Transfer-Encoding") or type(length) is not str
                    or not re.fullmatch(r"[0-9]{1,3}", length) or not 1 <= int(length) <= 256
                    or self._header("Content-Type") != "application/json"):
                self._send(400, {"ok": False, "error": "bounded_json_required"})
                return
            try:
                self._body_consumed = True
                raw = self.rfile.read(int(length))
                if len(raw) != int(length) or json.loads(raw) != {}:
                    raise DojoError("only an empty fixed-action object is accepted")
                result = controller.call(actions[self.path])
                self._send(200, result)
            except ScopeError:
                self._send(403, {"ok": False, "error": "scope_rejected"})
            except DojoRateError:
                self._send(429, {"ok": False, "error": "scope_rate_limit"})
            except (ValueError, UnicodeError):
                self._send(400, {"ok": False, "error": "control_rejected"})
            except Exception:
                self._send(500, {"ok": False, "error": "callback_failed"})

        def do_OPTIONS(self):
            self._send(405, {"ok": False, "error": "unavailable"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.token = token
    server.control = controller
    server.dashboard_url = "http://127.0.0.1:" + str(server.server_port) + "/#token=" + token
    return server
