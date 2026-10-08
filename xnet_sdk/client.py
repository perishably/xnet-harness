"""Bounded, hash-pinned Python binding to the Rust process runtime."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import uuid

API = "xnet.fabric.v1"
MAX_FRAME = 262144
OPS = frozenset({"health", "sets", "seal", "fetch", "verify", "pack_context", "context_depth", "rank_routes", "storage_admission", "shutdown",
                 "context_append", "context_history", "context_bind", "context_occupancy", "context_prepare", "context_acknowledge", "context_state"})

class XnetError(RuntimeError):
    pass

class XnetStartupError(XnetError):
    """A validated startup rejection, distinct from a broken wire protocol."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise XnetError("duplicate response field")
        out[key] = value
    return out

def _bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")

def _regular(path: Path):
    for parent in (path, *path.parents):
        if parent.exists():
            stat = parent.lstat()
            if parent.is_symlink() or getattr(stat, "st_file_attributes", 0) & 0x400:
                raise XnetError("linked binary or root")

class Client:
    """Owns exactly one foreground Rust runtime; close never stops a sibling app.

    Runtime roots must be operator-selected designated XNET directories. The
    expected binary digest is supplied by a reviewed build receipt, not a model.
    """
    def __init__(self, binary: Path, root: Path, *, sha256: str, timeout: float = 10):
        binary, root = Path(binary).absolute(), Path(root).absolute()
        if not 0 < timeout <= 60 or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise XnetError("invalid pin or timeout")
        _regular(binary)
        _regular(root)
        if not binary.is_file():
            raise XnetError("binary missing")
        with binary.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != sha256:
            raise XnetError("binary pin mismatch")
        self.binary, self.root, self.binary_sha256 = binary, root, sha256
        self.timeout = timeout
        self._lock = threading.Lock()
        self._queue = queue.Queue(maxsize=2)
        self._closed = False
        self._startup = True
        self._process = subprocess.Popen([str(binary), "daemon", "--root", str(root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        try:
            self.call("health")
            self._startup = False
        except BaseException:
            self._terminate()
            raise

    def _read(self):
        try:
            while not self._closed:
                data = self._process.stdout.readline(MAX_FRAME + 1)
                if not data:
                    self._queue.put(XnetError("runtime exited"), timeout=1)
                    break
                if len(data) > MAX_FRAME or not data.endswith(b"\n"):
                    self._queue.put(XnetError("invalid response frame"), timeout=1)
                    break
                self._queue.put(data, timeout=1)
        except (OSError, ValueError, queue.Full):
            pass

    def call(self, op: str, **fields):
        with self._lock:
            if self._closed or op not in OPS:
                raise XnetError("closed client or unsupported operation")
            identity = uuid.uuid4().hex
            request = _bytes({"api": API, "id": identity, "request": {"op": op, **fields}}) + b"\n"
            if len(request) > MAX_FRAME:
                raise XnetError("request too large")
            try:
                write_error = None
                try:
                    self._process.stdin.write(request)
                    self._process.stdin.flush()
                except OSError as error:
                    if not self._startup:
                        raise
                    # A refused startup may emit its rejection and exit before
                    # health reaches stdin. Read that one validated rejection;
                    # never resend or reopen the caller's root.
                    write_error = error
                response = self._queue.get(timeout=self.timeout)
                if isinstance(response, Exception):
                    raise response
                value = json.loads(response, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(XnetError("nonfinite response")))
                if type(value) is not dict:
                    raise XnetError("response object required")
                expected = {"api", "id", "ok", "result", "result_sha256", "error"}
                startup_error = self._startup and value.get("id") == "startup" and value.get("ok") is False
                if set(value) != expected or value["api"] != API or not (value["id"] == identity or startup_error) or type(value["ok"]) is not bool or value["ok"] != (value["error"] is None):
                    raise XnetError("response binding failed")
                if hashlib.sha256(_bytes(value["result"])).hexdigest() != value["result_sha256"]:
                    raise XnetError("response hash mismatch")
                if write_error is not None and not startup_error:
                    raise XnetError("startup transport failed without a validated rejection") from write_error
                if startup_error:
                    if value["result"] is not None or type(value["error"]) is not str:
                        raise XnetError("invalid startup rejection")
                    raise XnetStartupError(value["error"])
            except XnetStartupError:
                self._terminate()
                raise
            except (OSError, queue.Empty, json.JSONDecodeError, UnicodeError, TypeError, XnetError) as error:
                self._terminate()
                raise XnetError("runtime protocol failed") from error
            if not value["ok"]:
                raise XnetError(str(value["error"]))
            return value["result"]

    def _terminate(self):
        self._closed = True
        try:
            if self._process.poll() is None:
                self._process.kill()
        except OSError:
            pass  # The owned child may exit between poll and kill.
        try:
            self._process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            # One bounded retry reaps a racing child; cleanup cannot replace
            # the validated startup/protocol error that triggered it.
            try:
                self._process.kill()
            except OSError:
                pass
            try:
                self._process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for pipe in (self._process.stdin, self._process.stdout, self._process.stderr):
            if pipe:
                try:
                    pipe.close()
                except (OSError, ValueError):
                    # BufferedWriter.close() can flush into an already closed
                    # pipe. Continue closing the other handles and join reader.
                    pass
        self._reader.join(timeout=2)

    def close(self):
        if not self._closed:
            try:
                self.call("shutdown")
                self._process.wait(timeout=self.timeout)
            finally:
                self._terminate()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def seal(self, text: str): return self.call("seal", text=text)
    def fetch(self, digest: str): return self.call("fetch", digest=digest)
    def pack_context(self, records: list[dict], *, max_bytes: int = 8192):
        return self.call("pack_context", records=records, max_bytes=max_bytes)
