"""Fixed tool registry and bounded Ouroboros observe-to-learn workflow."""
from __future__ import annotations

import collections
import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .ledger import Ledger
from .memory import MemoryStore
from .nullclaw import NullClaw
from .protocol import canonical, digest, make_event
from .scope import ScopeAuthority, ScopeError


class WorkflowError(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ToolRegistry:
    """Models may request these names, but only signed scope admits execution."""
    METHODS = {"inventory": False, "file_metadata": False, "http_head": True}

    def __init__(self, scopes: ScopeAuthority):
        self.scopes = scopes
        self._lock = threading.Lock()
        self._requests: dict[str, collections.deque[float]] = {}
        self._semaphores: dict[str, threading.BoundedSemaphore] = {}

    def gate(self, scope_id: str, method: str, target: str) -> dict:
        if method not in self.METHODS:
            raise WorkflowError("tool is not registered")
        return self.scopes.gate(scope_id, target, method, network=self.METHODS[method])

    def execute(self, scope_id: str, method: str, target: str) -> dict[str, Any]:
        manifest = self.gate(scope_id, method, target)
        with self._lock:
            queue = self._requests.setdefault(scope_id, collections.deque())
            now = time.monotonic()
            while queue and now - queue[0] >= 60:
                queue.popleft()
            if len(queue) >= manifest["requests_per_minute"]:
                raise ScopeError("scope rate limit reached")
            queue.append(now)
            sem = self._semaphores.setdefault(scope_id, threading.BoundedSemaphore(manifest["max_parallel"]))
        if not sem.acquire(blocking=False):
            raise ScopeError("scope parallelism limit reached")
        try:
            if method == "inventory":
                return {"program": manifest["program"], "allowed_assets": manifest["allowed_assets"], "excluded_assets": manifest["excluded_assets"], "policy_capture_sha256": manifest["policy_capture_sha256"]}
            if method == "file_metadata":
                path = Path(target[5:]).resolve(strict=True)
                if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
                    raise WorkflowError("file must be regular and at most 32 MiB")
                from .protocol import sha256
                return {"path": str(path), "size": path.stat().st_size, "mtime_ns": path.stat().st_mtime_ns, "sha256": sha256(path.read_bytes())}
            if method == "http_head":
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
                req = urllib.request.Request(target, method="HEAD", headers={"User-Agent": "XNET-Jcode-Harness/0.1"})
                try:
                    with opener.open(req, timeout=5) as res:
                        return {"status": res.status, "url": target, "headers": dict(list(res.headers.items())[:32])}
                except urllib.error.HTTPError as exc:
                    return {"status": exc.code, "url": target, "headers": dict(list(exc.headers.items())[:32])}
            raise WorkflowError("unknown tool")
        finally:
            sem.release()


class Ouroboros:
    PHASES = ("observe", "normalize", "plan", "gated_action", "verify", "receipt", "memory", "learn")

    def __init__(self, ledger: Ledger, scopes: ScopeAuthority, nullclaw: NullClaw):
        self.ledger = ledger
        self.scopes = scopes
        self.nullclaw = nullclaw
        self.tools = ToolRegistry(scopes)
        self.memory = MemoryStore(ledger)

    def run(self, *, task_id: str, scope_id: str, method: str, target: str, max_steps: int = 8) -> dict[str, Any]:
        if not 8 <= max_steps <= 64:
            raise WorkflowError("max_steps must accommodate the eight bounded phases")
        manifest = self.tools.gate(scope_id, method, target)
        request_hash = digest({"task_id": task_id, "scope_id": scope_id, "method": method, "target": target, "max_steps": max_steps})
        existing = self.ledger.run_start(task_id, request_hash)
        if existing is not None:
            return {**existing, "idempotent_replay": True}
        state: dict[str, Any] = {"task_id": task_id, "scope_id": scope_id, "method": method, "target": target, "steps": 0}
        try:
            for phase in self.PHASES:
                if state["steps"] >= max_steps:
                    raise WorkflowError("loop step limit reached")
                if self.nullclaw.is_cancelled(task_id):
                    state["status"] = "cancelled"
                    self.ledger.append(make_event(task_id, scope_id, "ouroboros.cancelled", {"phase": phase}, source="ouroboros"))
                    self.ledger.run_finish(task_id, "cancelled", state)
                    return state
                payload: dict[str, Any] = {"phase": phase, "method": method}
                if phase == "observe":
                    payload["target"] = target
                elif phase == "normalize":
                    state["scope_hash"] = digest({k: v for k, v in manifest.items() if k != "signature_hmac_sha256"})
                    payload["scope_hash"] = state["scope_hash"]
                elif phase == "plan":
                    payload["registered_tool"] = method
                elif phase == "gated_action":
                    state["result"] = self.tools.execute(scope_id, method, target)
                    payload["result_hash"] = digest(state["result"])
                elif phase == "verify":
                    state["result_hash"] = digest(state["result"])
                    payload["result_hash"] = state["result_hash"]
                elif phase == "receipt":
                    payload["result_hash"] = state["result_hash"]
                elif phase == "memory":
                    data = canonical(state["result"])
                    state["evidence_hash"] = self.ledger.put_evidence(data, source=f"tool:{method}", scope_id=scope_id, metadata={"task_id": task_id})
                    mem = self.ledger.memory_put(f"task:{task_id}", {"method": method, "result_hash": state["result_hash"]}, state["evidence_hash"], task_id)
                    payload.update({"evidence_hash": state["evidence_hash"], "contradiction": mem["contradiction"]})
                    if mem["contradiction"]:
                        state["status"] = "needs_review"
                elif phase == "learn":
                    payload["outcome"] = state.get("status", "completed")
                    self.memory.strategy_add(task_id, scope_id, f"{method} {target}", payload["outcome"], [state["evidence_hash"]])
                    payload["context_pack_hash"] = self.memory.context_pack(task_id)["pack_hash"]
                event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"xnet:{task_id}:{phase}"))
                self.ledger.append(make_event(task_id, scope_id, f"ouroboros.{phase}", payload, source="ouroboros", event_id=event_id))
                state["steps"] += 1
            state["status"] = state.get("status", "completed")
            self.ledger.run_finish(task_id, state["status"], state)
            return state
        except Exception as exc:
            state["status"] = "failed"
            state["error"] = str(exc)
            self.ledger.append(make_event(task_id, scope_id, "ouroboros.failed", {"error": type(exc).__name__}, source="ouroboros"))
            self.ledger.run_finish(task_id, "failed", state)
            raise
