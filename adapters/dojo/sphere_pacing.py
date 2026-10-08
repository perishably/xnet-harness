"""Wait for the original signed source-I/O quota on one owned sphere.

Every original execution is called once. Queues, counters, policy, parallelism,
and failure semantics remain the original controller's. No retries or resets.
Source gates are entered before the sphere OS lock; no model operation is here.
"""
from __future__ import annotations
import json
from pathlib import Path
import threading
from time import monotonic, sleep
from types import MethodType

from adapters.dojo.sphere_arbitration import _artifact, arbitration_binding, serialized
from xnet.context_callable_identity_v2 import code_sha256
from xnet.oroboros_sphere import SphereController, SphereTools
from xnet.protocol import canonical, sha256

SCHEMA = "xnet.dojo-sphere-pacing.v1"
MAX_WAIT_SECONDS = 65
_ATTRIBUTE = "_dojo_source_pacing"


def _code(function):
    return code_sha256(function.__code__)


class _Pacer:
    def __init__(self, sphere):
        self.sphere, self.tools = sphere, sphere.tools
        self.io = threading.RLock()
        self.io_binding = self.io
        self.original_execute = SphereTools.execute
        self.original_fetch, self.original_verify = SphereController.fetch, SphereController.verify
        self.scope_manifest = sphere.scopes.load(sphere.scope_id)
        self.originals = {"execute": self.original_execute, "fetch": self.original_fetch, "verify": self.original_verify}
        self.adapters = {"execute": _paced_execute, "fetch": _paced_fetch, "verify": _paced_verify}
        self.sources = [_artifact(__file__), _artifact(SphereTools.execute.__code__.co_filename)]
        self.binding_bytes = canonical({"schema": SCHEMA, "scope_id": sphere.scope_id,
            "source_artifacts": self.sources, "scope_manifest_sha256": sha256(canonical(self.scope_manifest)),
            "arbitration": arbitration_binding(sphere),
            "original_code_sha256": {name: _code(function) for name, function in self.originals.items()},
            "adapter_code_sha256": {name: _code(function) for name, function in self.adapters.items()},
            "requests_per_minute": self.scope_manifest["requests_per_minute"],
            "max_parallel": self.scope_manifest["max_parallel"], "max_wait_per_io_seconds": MAX_WAIT_SECONDS,
            "policy_changed": False, "queue_reset": False, "automatic_retries": 0,
            "original_execute_calls_per_admission": 1, "model_calls": 0})
        self.binding_pin = sha256(self.binding_bytes)

    def guard(self):
        sphere, tools = self.sphere, self.tools
        binding = json.loads(self.binding_bytes)
        if (type(sphere) is not SphereController or type(tools) is not SphereTools or
                sphere.__dict__.get(_ATTRIBUTE) is not self or tools.__dict__.get(_ATTRIBUTE) is not self or
                sphere.tools is not tools or tools.scopes is not sphere.scopes or self.io is not self.io_binding or
                getattr(tools.execute, "__self__", None) is not tools or getattr(tools.execute, "__func__", None) is not _paced_execute or
                getattr(sphere.fetch, "__self__", None) is not sphere or getattr(sphere.fetch, "__func__", None) is not _paced_fetch or
                getattr(sphere.verify, "__self__", None) is not sphere or getattr(sphere.verify, "__func__", None) is not _paced_verify or
                SphereTools.execute is not self.original_execute or SphereController.fetch is not self.original_fetch or
                SphereController.verify is not self.original_verify or sha256(self.binding_bytes) != self.binding_pin or
                sphere.scopes.load(sphere.scope_id) != self.scope_manifest or
                binding["scope_id"] != sphere.scope_id or binding["source_artifacts"] != self.sources or
                [_artifact(row["path"]) for row in self.sources] != self.sources or
                binding["original_code_sha256"] != {name: _code(function) for name, function in self.originals.items()} or
                binding["adapter_code_sha256"] != {name: _code(function) for name, function in self.adapters.items()}):
            raise ValueError("owned sphere source pacing identity/policy changed")
        return binding

    def admit(self, scope_id, method, target, **kwargs):
        with serialized(self.sphere), self.io:
            self.guard()
            if scope_id != self.sphere.scope_id:
                raise ValueError("only the declared sphere scope is paced")
            started = monotonic()
            while True:
                # Admit exactly the original method/asset before considering a
                # wait. Its original execute will recheck again before I/O.
                manifest = self.tools.gate(scope_id, method, target)
                if manifest != self.scope_manifest:
                    raise ValueError("signed source pacing policy changed")
                now = monotonic()
                with self.tools._lock:
                    queue = self.tools._requests.get(scope_id, ())
                    active = [stamp for stamp in queue if now - stamp < 60]
                if len(active) < manifest["requests_per_minute"]:
                    break
                if now - started >= MAX_WAIT_SECONDS:
                    raise TimeoutError("bounded source quota wait exhausted")
                wait = max(0.001, active[0] + 60 - now + 0.001)
                sleep(min(wait, 1.0, MAX_WAIT_SECONDS - (now - started)))
                self.guard()
            result = self.original_execute(self.tools, scope_id, method, target, **kwargs)
            self.guard()
            return result


def _paced_execute(self, scope_id, method, target, *, root, raw=None, expected_sha256):
    pacer = self.__dict__.get(_ATTRIBUTE)
    if type(pacer) is not _Pacer or pacer.tools is not self:
        raise ValueError("installed owned source pacer required")
    return pacer.admit(scope_id, method, target, root=root, raw=raw, expected_sha256=expected_sha256)


def _paced_fetch(self, silo_id, packet_sha256, lane="powershell"):
    pacer = self.__dict__.get(_ATTRIBUTE)
    if type(pacer) is not _Pacer or pacer.sphere is not self:
        raise ValueError("installed owned source pacer required")
    with serialized(self):
        pacer.guard()
        result = pacer.original_fetch(self, silo_id, packet_sha256, lane)
        pacer.guard()
        return result


def _paced_verify(self, lane="powershell"):
    pacer = self.__dict__.get(_ATTRIBUTE)
    if type(pacer) is not _Pacer or pacer.sphere is not self:
        raise ValueError("installed owned source pacer required")
    with serialized(self):
        pacer.guard()
        result = pacer.original_verify(self, lane)
        pacer.guard()
        return result


def install_source_pacing(sphere):
    """Install before any source packet; preserve the exact controller type."""
    arbitration_binding(sphere)
    if sphere.__dict__.get(_ATTRIBUTE) is not None:
        return pacing_binding(sphere)
    if (type(sphere.tools) is not SphereTools or "execute" in sphere.tools.__dict__ or
            "fetch" in sphere.__dict__ or "verify" in sphere.__dict__ or sphere._state()["records"]):
        raise ValueError("fresh original sphere I/O required before source pacing")
    pacer = _Pacer(sphere)
    sphere.__dict__[_ATTRIBUTE] = pacer
    sphere.tools.__dict__[_ATTRIBUTE] = pacer
    sphere.tools.execute = MethodType(_paced_execute, sphere.tools)
    sphere.fetch = MethodType(_paced_fetch, sphere)
    sphere.verify = MethodType(_paced_verify, sphere)
    return pacer.guard()


def pacing_binding(sphere):
    """Recheck detached binding without taking a source admission lock."""
    if type(sphere) is not SphereController:
        raise ValueError("exact owned paced sphere required")
    pacer = sphere.__dict__.get(_ATTRIBUTE)
    if type(pacer) is not _Pacer or pacer.sphere is not sphere:
        raise ValueError("installed source pacing required")
    return pacer.guard()
