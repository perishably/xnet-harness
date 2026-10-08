"""Serialize source cycles on one fresh caller-owned sphere instance.

The existing class, OS lock, scopes, CAS checks and explicit expected-head
contract are unchanged. This gate never retries a call or owns inference.
Use serialized(sphere) when a source transaction samples an explicit head or
collects a multi-read completion proof. Never hold it across model completion.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import threading
from types import MethodType

from adapters.jcode.sphere_peer import JcodeSpherePeer
from xnet.context_callable_identity_v2 import code_sha256
from xnet.oroboros_sphere import SphereController
from xnet.protocol import canonical, digest, sha256
from xnet.relay_log import _no_links

SCHEMA = "xnet.dojo-sphere-arbitration.v1"
_ATTRIBUTE = "_dojo_sphere_arbitration"


def _artifact(path):
    path = Path(path).absolute()
    _no_links(path, regular_file=True)
    before = path.stat()
    with path.open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    after = path.stat()
    _no_links(path, regular_file=True)
    if (len(raw) > 2 * 1024 * 1024 or
            (before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError("sphere arbitration source changed during bounded read")
    return {"path": str(path), "sha256": sha256(raw)}


class _Gate:
    def __init__(self, sphere):
        self.sphere = sphere
        self.lock = threading.RLock()
        self.original = SphereController.cycle
        self.sources = [_artifact(__file__), _artifact(self.original.__code__.co_filename),
            _artifact(JcodeSpherePeer.admit.__code__.co_filename)]
        self.binding_bytes = canonical({"schema": SCHEMA, "scope_id": sphere.scope_id,
            "config_sha256": digest(sphere.config), "source_artifacts": self.sources,
            "original_code_sha256": code_sha256(self.original.__code__),
            "adapter_code_sha256": code_sha256(_serial_cycle.__code__),
            "instance_only": True, "automatic_retries": 0, "model_calls": 0})
        self.binding_pin = sha256(self.binding_bytes)

    def guard(self):
        sphere = self.sphere
        callback = sphere.cycle
        binding = json.loads(self.binding_bytes)
        if (type(sphere) is not SphereController or
                sphere.__dict__.get(_ATTRIBUTE) is not self or
                getattr(callback, "__self__", None) is not sphere or
                getattr(callback, "__func__", None) is not _serial_cycle or
                SphereController.cycle is not self.original or
                sha256(self.binding_bytes) != self.binding_pin or
                binding["scope_id"] != sphere.scope_id or
                binding["config_sha256"] != digest(sphere.config) or
                binding["original_code_sha256"] != code_sha256(self.original.__code__) or
                binding["adapter_code_sha256"] != code_sha256(_serial_cycle.__code__) or
                binding["source_artifacts"] != self.sources or
                [_artifact(row["path"]) for row in self.sources] != self.sources):
            raise ValueError("caller-owned sphere arbitration identity changed")
        return binding


def _serial_cycle(self, packet, lane, expected_head=None):
    gate = self.__dict__.get(_ATTRIBUTE)
    if type(gate) is not _Gate or gate.sphere is not self:
        raise ValueError("installed caller-owned sphere gate required")
    with gate.lock:
        gate.guard()
        # The original method chooses a missing head here, after admission to
        # this instance gate. Explicit CAS expectations are preserved verbatim.
        result = gate.original(self, packet, lane, expected_head=expected_head)
        gate.guard()
        return result


def install_serial_cycle(sphere):
    """Install once, before any packet is admitted to this exact instance."""
    if type(sphere) is not SphereController:
        raise ValueError("exact caller-owned SphereController required")
    existing = sphere.__dict__.get(_ATTRIBUTE)
    if existing is not None:
        return arbitration_binding(sphere)
    if (getattr(sphere.cycle, "__self__", None) is not sphere or
            getattr(sphere.cycle, "__func__", None) is not SphereController.cycle or
            "cycle" in sphere.__dict__):
        raise ValueError("original sphere cycle required before installation")
    state = sphere._state()
    if state["records"] or state["chain"]["events"] != 1:
        raise ValueError("fresh sphere bootstrap required; retained cycles are preserved")
    gate = _Gate(sphere)
    sphere.__dict__[_ATTRIBUTE] = gate
    sphere.cycle = MethodType(_serial_cycle, sphere)
    return gate.guard()


def arbitration_binding(sphere):
    """Recheck and return a detached source/config binding."""
    if type(sphere) is not SphereController:
        raise ValueError("exact installed SphereController required")
    gate = sphere.__dict__.get(_ATTRIBUTE)
    if type(gate) is not _Gate or gate.sphere is not sphere:
        raise ValueError("installed sphere arbitration required")
    with gate.lock:
        return gate.guard()


@contextmanager
def serialized(sphere):
    """Borrow the source-only gate; exceptions propagate without a retry."""
    if type(sphere) is not SphereController:
        raise ValueError("exact installed SphereController required")
    gate = sphere.__dict__.get(_ATTRIBUTE)
    if type(gate) is not _Gate or gate.sphere is not sphere:
        raise ValueError("installed sphere arbitration required")
    with gate.lock:
        gate.guard()
        yield sphere
        gate.guard()


class SerializedJcodeSpherePeer(JcodeSpherePeer):
    """Keep source admission and proof reads together; inference is separate."""
    def admit(self, packet, lane="powershell", *, expected_sphere_head=None):
        with serialized(self.sphere):
            return super().admit(packet, lane, expected_sphere_head=expected_sphere_head)

    def public_context(self, selected_events, *, max_bytes=8192, lane="powershell"):
        with serialized(self.sphere):
            return super().public_context(selected_events, max_bytes=max_bytes, lane=lane)
