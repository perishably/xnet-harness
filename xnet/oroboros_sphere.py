"""Four bounded storage silos, with source-only ingress and audited return.

Only canonical public envelopes move. Local sync-folder readback is measured;
remote provider upload and semantic correctness are not attested here.
"""
from __future__ import annotations

import hashlib
import hmac
import collections
import json
import os
import re
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from adapters.openclaw import validate_source_packet, gate_contract
from .brains import _exclusive_file_lock
from .ledger import Ledger
from .nullclaw import NullClaw
from .protocol import canonical, digest, make_event, sha256
from .scope import ScopeAuthority
from .workflow import ToolRegistry

SCHEMA = "xnet.oroboros-sphere-config.v1"
SILOS = ("c_nvme", "d_4tb", "proton", "google")
CYCLE = (*SILOS, "c_nvme")
LANES = ("powershell", "git-bash")
MAX_FRAME_BYTES = 65_536
_HEX = re.compile(r"[0-9a-f]{64}")
_REPO = Path(__file__).resolve().parent.parent
_SOURCES = (
    "xnet/oroboros_sphere.py", "scripts/oroboros-sphere.py",
    "xnet/protocol.py", "xnet/scope.py", "xnet/ledger.py",
    "xnet/nullclaw.py", "xnet/brains.py", "xnet/workflow.py",
    "xnet/rag.py", "adapters/openclaw/source_gate.py",
    "adapters/openclaw/__init__.py",
    "xnet/memory.py", "xnet/routing_protocols.py", "xnet/__init__.py",
    "scripts/oroboros-membrane.ps1",
    "scripts/oroboros-membrane.sh",
)


class SphereError(ValueError):
    pass


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SphereError("duplicate JSON key")
        result[key] = value
    return result


def load_json_file(path: Path) -> dict:
    _safe_path(Path(path))
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FRAME_BYTES + 1)
    if len(raw) > MAX_FRAME_BYTES:
        raise SphereError("JSON frame exceeds 64 KiB")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    if type(value) is not dict:
        raise SphereError("JSON frame must be an object")
    return value


def _safe_path(path: Path, root: Path | None = None) -> Path:
    if not path.is_absolute() or str(path).startswith(("\\\\", "//")):
        raise SphereError("local absolute path required")
    # Check lexical ancestors before resolve follows a junction or symlink.
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise SphereError("storage path may not traverse a link or junction")
    resolved = path.resolve(strict=False)
    if root is not None:
        try:
            resolved.relative_to(root.resolve(strict=False))
        except ValueError as exc:
            raise SphereError("storage path escapes designated silo") from exc
    # Google Drive's mounted filesystem reports st_nlink=0 for ordinary
    # files. Reject reported multiple links; zero is unknown, not a link.
    if path.exists() and path.is_file() and path.stat().st_nlink > 1:
        raise SphereError("hard-linked storage file refused")
    return resolved


def _atomic_new_or_same(path: Path, data: bytes, root: Path) -> bool:
    _safe_path(path, root)
    if path.exists():
        if not path.is_file() or _bounded_bytes(path, root) != data:
            raise SphereError("existing object differs; preserve it for review")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    _safe_path(path.parent, root)
    fd, name = tempfile.mkstemp(prefix=".sphere-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        # Controller OS lock serializes its own writers; don't replace an
        # externally created conflicting file at the final publication point.
        if path.exists():
            if _bounded_bytes(path, root) != data:
                raise SphereError("conflicting object appeared during transfer")
            return False
        os.rename(name, path)
        return True
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _bounded_bytes(path: Path, root: Path) -> bytes:
    _safe_path(path, root)
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise SphereError("regular storage file required")
    with path.open("rb") as stream:
        raw = stream.read(MAX_FRAME_BYTES + 1)
    if len(raw) > MAX_FRAME_BYTES:
        raise SphereError("stored object exceeds 64 KiB")
    return raw


def _source_pins() -> dict[str, str]:
    pins = {name: sha256((_REPO / name).read_bytes()) for name in _SOURCES}
    # Namespace packages must stay namespaces within this source identity.
    name = "adapters/__init__.py"
    pins[name] = sha256((_REPO / name).read_bytes()) if (_REPO / name).exists() else "absent"
    return pins


def bootstrap_config(config_path: Path, control_root: Path,
                     silos: dict[str, Path]) -> dict:
    """Initialize one new private controller, without touching silo folders."""
    path = _safe_path(Path(config_path))
    control = _safe_path(Path(control_root))
    if path != control / "config.json" or path.exists():
        raise SphereError("bootstrap requires a new control_root/config.json")
    if set(silos) != set(SILOS):
        raise SphereError("exactly four designated silos required")
    roots = {key: _safe_path(Path(silos[key])) for key in SILOS}
    all_roots = [control, *roots.values()]
    for i, left in enumerate(all_roots):
        for right in all_roots[i + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise SphereError("controller and silos must have independent roots")
    control.mkdir(parents=True, exist_ok=True)
    if any(control.iterdir()):
        raise SphereError("bootstrap controller must be empty")
    authority = ScopeAuthority(control)
    scope = authority.create(
        program="Operator-owned XNET four-silo public capsule loop",
        policy_url="local:operator-authorized-sphere-v1",
        policy_capture=b"Public source-only capsules in four designated directories; no inference or arbitrary commands.",
        allowed_assets=["path:" + str(root) for root in roots.values()],
        methods=["sphere_transfer", "sphere_verify"],
        requests_per_minute=600, max_parallel=1, fixture=True,
        allow_live_network=False,
    )
    config = {
        "schema": SCHEMA, "control_root": str(control),
        "silos": {key: str(roots[key]) for key in SILOS},
        "cycle": list(CYCLE), "scope_id": scope["scope_id"],
        "source_pins": _source_pins(), "created_at": int(time.time()),
        "max_frame_bytes": MAX_FRAME_BYTES,
        "provider_upload_verified": False,
    }
    config["signature_hmac_sha256"] = hmac.new(authority._key(), canonical(config), hashlib.sha256).hexdigest()
    _atomic_new_or_same(path, canonical(config), control)
    ledger = Ledger(control)
    ledger.append(make_event("sphere-bootstrap", scope["scope_id"], "sphere.bootstrap",
                             {"config_sha256": sha256(path.read_bytes()), "source_pins": config["source_pins"]}, source="sphere"))
    return config


class SphereTools(ToolRegistry):
    """Fixed filesystem-only methods; packet prose is never executed."""
    METHODS = {"sphere_transfer": False, "sphere_verify": False}

    def execute(self, scope_id: str, method: str, target: str, *,
                root: Path, raw: bytes | None = None,
                expected_sha256: str) -> dict[str, Any]:
        manifest = self.gate(scope_id, method, target)
        with self._lock:
            queue = self._requests.setdefault(scope_id, collections.deque())
            now = time.monotonic()
            while queue and now - queue[0] >= 60:
                queue.popleft()
            if len(queue) >= manifest["requests_per_minute"]:
                raise SphereError("scope rate limit reached")
            queue.append(now)
            sem = self._semaphores.setdefault(scope_id, threading.BoundedSemaphore(manifest["max_parallel"]))
        if not sem.acquire(blocking=False):
            raise SphereError("scope parallelism limit reached")
        try:
            return self._execute(scope_id, method, target, root=root, raw=raw, expected_sha256=expected_sha256)
        finally:
            sem.release()

    def _execute(self, scope_id: str, method: str, target: str, *,
                 root: Path, raw: bytes | None, expected_sha256: str) -> dict[str, Any]:
        path = _safe_path(Path(target[5:]), root)
        copied = False
        if raw is not None:
            if method != "sphere_transfer" or len(raw) > MAX_FRAME_BYTES or sha256(raw) != expected_sha256:
                raise SphereError("invalid fixed transfer request")
            copied = _atomic_new_or_same(path, raw, root)
        if not path.is_file():
            raise SphereError("designated object unavailable")
        data = _bounded_bytes(path, root)
        if len(data) > MAX_FRAME_BYTES or sha256(data) != expected_sha256:
            raise SphereError("silo object hash mismatch")
        self.gate(scope_id, method, target)
        _safe_path(path, root)
        return {"data": data, "copied": copied, "bytes": len(data), "path": str(path)}


class SphereController:
    def __init__(self, config_path: Path):
        self.config_path = _safe_path(Path(config_path))
        config = load_json_file(self.config_path)
        fields = {"schema", "control_root", "silos", "cycle", "scope_id", "source_pins", "created_at", "max_frame_bytes", "provider_upload_verified", "signature_hmac_sha256"}
        if set(config) != fields or config["schema"] != SCHEMA:
            raise SphereError("sphere config schema mismatch")
        self.control = _safe_path(Path(config["control_root"]))
        if self.config_path != self.control / "config.json":
            raise SphereError("config must reside in its private control root")
        self.scopes = ScopeAuthority(self.control)
        unsigned = {key: value for key, value in config.items() if key != "signature_hmac_sha256"}
        expected = hmac.new(self.scopes._key(), canonical(unsigned), hashlib.sha256).hexdigest()
        if type(config["signature_hmac_sha256"]) is not str or not hmac.compare_digest(expected, config["signature_hmac_sha256"]):
            raise SphereError("sphere config signature mismatch")
        if config["source_pins"] != _source_pins():
            raise SphereError("sphere source identity changed; create a new control root")
        if (set(config["silos"]) != set(SILOS) or config["cycle"] != list(CYCLE)
                or type(config["max_frame_bytes"]) is not int or config["max_frame_bytes"] != MAX_FRAME_BYTES
                or config["provider_upload_verified"] is not False):
            raise SphereError("sphere topology or bounds changed")
        self.roots = {key: _safe_path(Path(config["silos"][key])) for key in SILOS}
        self.config = config
        self.scope_id = config["scope_id"]
        self.scopes.load(self.scope_id)
        if not (self.control / "ledger" / "xnet.sqlite3").is_file():
            raise SphereError("controller ledger missing; do not silently reinitialize")
        self.ledger = Ledger(self.control)
        self.nullclaw = NullClaw(self.control, self.ledger)
        self.tools = SphereTools(self.scopes)
        self.lock_path = self.control / "sphere.lock"
        self._state()

    def _state(self) -> dict:
        if self.config["source_pins"] != _source_pins():
            raise SphereError("sphere source identity changed at round boundary")
        chain = self.ledger.verify_chain()
        events = self.ledger.events()
        boot = [event for event in events if event["kind"] == "sphere.bootstrap"]
        if len(boot) != 1 or boot[0]["payload"]["config_sha256"] != sha256(_bounded_bytes(self.config_path, self.control)):
            raise SphereError("controller bootstrap binding mismatch")
        records: dict[str, dict] = {}
        for event in events:
            payload = event["payload"]
            if event["kind"].startswith("sphere.") and (event["scope_id"] != self.scope_id or event["source"] != "sphere"):
                raise SphereError("sphere event scope or source binding mismatch")
            if event["kind"] == "sphere.admitted":
                key = payload["packet_id"]
                if key in records:
                    raise SphereError("duplicate packet admission in ledger")
                records[key] = {**payload, "hops": [], "completed": False}
            elif event["kind"] == "sphere.hop":
                record = records.get(payload["packet_id"])
                index = payload["hop_index"]
                if record is None or index != len(record["hops"]) or index >= 4 or payload["object_sha256"] != record["object_sha256"] or payload["source"] != CYCLE[index] or payload["destination"] != CYCLE[index + 1]:
                    raise SphereError("invalid hop sequence in ledger")
                record["hops"].append(payload)
            elif event["kind"] == "sphere.completed":
                record = records.get(payload["packet_id"])
                if (record is None or len(record["hops"]) != 4 or record["completed"]
                        or payload["object_sha256"] != record["object_sha256"] or payload["hop_count"] != 4):
                    raise SphereError("invalid cycle completion in ledger")
                record["completed"] = True
            if event["kind"] in ("sphere.admitted", "sphere.hop", "sphere.completed"):
                record = records[payload["packet_id"]]
                if event["task_id"] != record["task_id"]:
                    raise SphereError("sphere event task binding mismatch")
        return {"chain": chain, "records": records}

    def _guard(self, packet: dict, lane: str) -> None:
        if lane not in LANES:
            raise SphereError("unknown membrane lane")
        if self.nullclaw.is_cancelled(packet["task_id"]):
            raise SphereError("NullClaw task cancellation active")
        if self.nullclaw.is_contained(lane) or self.nullclaw.is_contained(packet["producer"]):
            raise SphereError("NullClaw source containment active")

    def _path(self, silo: str, object_hash: str, *, returned: bool = False) -> Path:
        if silo not in SILOS or type(object_hash) is not str or not _HEX.fullmatch(object_hash):
            raise SphereError("invalid silo or object digest")
        return self.roots[silo] / ("returns" if returned else "cas") / "sha256" / object_hash[:2] / (object_hash + ".json")

    def _read(self, silo: str, record: dict, lane: str, *, returned: bool = False) -> bytes:
        path = self._path(silo, record["object_sha256"], returned=returned)
        result = self.tools.execute(self.scope_id, "sphere_verify", "path:" + str(path), root=self.roots[silo], expected_sha256=record["object_sha256"])
        packet = json.loads(result["data"].decode("utf-8"), object_pairs_hook=_no_duplicates)
        # Expired storage can be verified as historical data; it cannot be
        # admitted to a new cycle or gain new tool authority through fetch.
        checked = validate_source_packet(packet, now=record["created_at"])
        if checked["packet_sha256"] != record["packet_sha256"]:
            raise SphereError("stored packet differs from admission")
        self._guard(checked, lane)
        return result["data"]

    def plan(self) -> dict:
        state = self._state()
        for key, root in self.roots.items():
            self.tools.gate(self.scope_id, "sphere_verify", "path:" + str(root))
        return {"schema": "xnet.oroboros-sphere-plan.v1", "scope_id": self.scope_id,
                "cycle": list(CYCLE), "silos": self.config["silos"],
                "head": state["chain"]["head"], "packets": len(state["records"]),
                "OpenClaw": gate_contract(), "NullClaw": "local audited cancellation and containment",
                "provider_upload_verified": False, "model_calls": 0}

    def cycle(self, packet: dict, lane: str, expected_head: str | None = None) -> dict:
        checked = validate_source_packet(packet)
        raw = canonical(checked)
        if len(raw) > MAX_FRAME_BYTES:
            raise SphereError("canonical packet frame exceeds 64 KiB")
        object_hash = sha256(raw)
        self._guard(checked, lane)
        if expected_head is None:
            expected_head = self._state()["chain"]["head"]
        with _exclusive_file_lock(self.lock_path):
            state = self._state()
            if expected_head is not None and expected_head != state["chain"]["head"]:
                raise SphereError("stale expected_head refused")
            record = state["records"].get(checked["packet_id"])
            if record is not None and record["object_sha256"] != object_hash:
                raise SphereError("packet_id already binds different bytes")
            try:
                if record is None:
                    self._guard(checked, lane)
                    path = self._path("c_nvme", object_hash)
                    self.tools.execute(self.scope_id, "sphere_transfer", "path:" + str(path), root=self.roots["c_nvme"], raw=raw, expected_sha256=object_hash)
                    payload = {key: checked[key] for key in ("packet_id", "packet_sha256", "task_id", "producer", "created_at")}
                    payload.update({"object_sha256": object_hash, "bytes": len(raw), "lane": lane})
                    self.ledger.append(make_event(checked["task_id"], self.scope_id, "sphere.admitted", payload, source="sphere"))
                    record = {**payload, "hops": [], "completed": False}
                if record["completed"]:
                    for silo in SILOS:
                        self._read(silo, record, lane)
                    self._read("c_nvme", record, lane, returned=True)
                    return self._result(record, True)
                # Resume verifies all committed hop destinations, rather than
                # assuming a receipt means the drive still holds those bytes.
                self._read("c_nvme", record, lane)
                for hop in record["hops"]:
                    self._read(hop["destination"], record, lane, returned=hop["hop_index"] == 3)
                for index in range(len(record["hops"]), 4):
                    validate_source_packet(checked)
                    self._guard(checked, lane)
                    start = time.monotonic_ns()
                    source, destination = CYCLE[index:index + 2]
                    data = self._read(source, record, lane)
                    self._guard(checked, lane)
                    path = self._path(destination, object_hash, returned=index == 3)
                    result = self.tools.execute(self.scope_id, "sphere_transfer", "path:" + str(path), root=self.roots[destination], raw=data, expected_sha256=object_hash)
                    self._guard(checked, lane)
                    payload = {"packet_id": checked["packet_id"], "object_sha256": object_hash,
                               "hop_index": index, "source": source, "destination": destination,
                               "read_path": str(self._path(source, object_hash)), "write_path": str(path),
                               "bytes": result["bytes"], "copied": result["copied"], "lane": lane,
                               "elapsed_ns": time.monotonic_ns() - start, "provider_upload_verified": False}
                    self.ledger.append(make_event(checked["task_id"], self.scope_id, "sphere.hop", payload, source="sphere"))
                    record["hops"].append(payload)
                if self._read("c_nvme", record, lane, returned=True) != raw:
                    raise SphereError("full-cycle return mismatch")
                self.ledger.append(make_event(checked["task_id"], self.scope_id, "sphere.completed", {"packet_id": checked["packet_id"], "object_sha256": object_hash, "hop_count": 4, "lane": lane}, source="sphere"))
                record["completed"] = True
                return self._result(record, False)
            except Exception as exc:
                self.ledger.append(make_event(checked["task_id"], self.scope_id, "sphere.pending", {"packet_id": checked["packet_id"], "object_sha256": object_hash, "error_type": type(exc).__name__, "committed_hops": len(record["hops"]) if record else 0, "lane": lane}, source="sphere"))
                raise

    def _result(self, record: dict, replay: bool) -> dict:
        return {"status": "completed", "scope_id": self.scope_id, "idempotent_replay": replay,
                "packet_sha256": record["packet_sha256"], "object_sha256": record["object_sha256"],
                "hops": record["hops"], "head": self.ledger.verify_chain()["head"],
                "provider_upload_verified": False, "model_calls": 0}

    def fetch(self, silo_id: str, packet_sha256: str, lane: str = "powershell") -> bytes:
        with _exclusive_file_lock(self.lock_path):
            records = self._state()["records"].values()
            match = [record for record in records if record["packet_sha256"] == packet_sha256]
            if len(match) != 1:
                raise SphereError("packet digest not uniquely admitted")
            return self._read(silo_id, match[0], lane)

    def verify(self, lane: str = "powershell") -> dict:
        if lane not in LANES:
            raise SphereError("unknown membrane lane")
        with _exclusive_file_lock(self.lock_path):
            state = self._state()
            errors = []
            reads = hops = completed = 0
            for record in state["records"].values():
                hops += len(record["hops"])
                completed += int(record["completed"])
                required = [("c_nvme", False)] + [(hop["destination"], hop["hop_index"] == 3) for hop in record["hops"]]
                for silo, returned in required:
                    try:
                        self._read(silo, record, lane, returned=returned)
                        reads += 1
                    except Exception as exc:
                        errors.append({"packet_id": record["packet_id"], "silo": silo, "error_type": type(exc).__name__, "error": str(exc)})
                if not record["completed"]:
                    errors.append({"packet_id": record["packet_id"], "error": "cycle pending"})
            return {"ok": not errors and bool(state["records"]), "packets": len(state["records"]),
                    "completed": completed, "hops": hops, "verified_reads": reads, "errors": errors,
                    "head": state["chain"]["head"], "events": state["chain"]["events"],
                    "provider_upload_verified": False, "model_calls": 0}
