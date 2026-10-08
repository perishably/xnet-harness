"""Bounded public transport objects and explicit readback evidence.

This module accepts public source packets and projects receipt metadata. It does
not walk source directories, export a runtime root, upload files, or own provider
authentication. The caller owns public classification and provider observations.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import time
import copy
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from adapters.openclaw import make_source_packet, validate_source_packet
from .brains import _exclusive_file_lock
from .protocol import canonical, digest, sha256
from .rag import SECRET_PATTERNS
from .scope import ScopeAuthority
from .workflow import ToolRegistry

SCHEMA = "xnet.oroboros-public-export.v1"
RECEIPT_SCHEMA = "xnet.oroboros-public-receipt.v1"
READBACK_SCHEMA = "xnet.oroboros-public-readback.v1"
PROVIDER_DOWNLOAD_SCHEMA = "xnet.oroboros-provider-download.v1"
MAX_OBJECT_BYTES = 65_536
MAX_OBJECTS = 64
MAX_EXPORT_BYTES = 4 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_NAMESPACE_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_PRIVATE_KEY = re.compile(rb"(?i)-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----")
_HASH_FIELDS = frozenset({"object_sha256", "packet_sha256", "head", "receipt_head",
                          "evidence_sha256", "source_sha256", "manifest_sha256"})
_ID_FIELDS = frozenset({"task_id", "scope_id", "status", "packet_id"})
_COUNT_FIELDS = frozenset({"model_calls", "verified_reads", "hop_count", "bytes"})


class PublicExportError(ValueError):
    pass


def _namespace(value: str) -> str:
    if (type(value) is not str or len(value) > 256 or "\\" in value
            or not value or value.startswith("/")
            or any(not _NAMESPACE_PART.fullmatch(part) for part in value.split("/"))):
        raise PublicExportError("namespace must be an exact bounded relative name")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or not _HEX.fullmatch(value):
        raise PublicExportError("invalid SHA256")
    return value


def _screen(raw: bytes) -> bytes:
    if len(raw) > MAX_OBJECT_BYTES:
        raise PublicExportError("public object exceeds 64 KiB")
    if _PRIVATE_KEY.search(raw) or any(pattern.search(raw) for pattern in SECRET_PATTERNS):
        raise PublicExportError("known credential or private key content refused")
    return raw


def _receipt_projection(receipt: dict) -> dict:
    if type(receipt) is not dict or any(type(key) is not str for key in receipt):
        raise PublicExportError("receipt must be a plain JSON object")
    try:
        original = canonical(receipt)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PublicExportError("receipt must contain bounded JSON values") from exc
    if len(original) > MAX_OBJECT_BYTES:
        raise PublicExportError("original receipt exceeds 64 KiB")
    projected: dict[str, Any] = {"schema": RECEIPT_SCHEMA,
                                "origin_receipt_sha256": sha256(original),
                                "authority": "none", "classification": "public"}
    for field in _HASH_FIELDS:
        if field in receipt:
            projected[field] = _hash(receipt[field])
    for field in _ID_FIELDS:
        if field in receipt:
            value = receipt[field]
            if type(value) is not str or not _ID.fullmatch(value):
                raise PublicExportError("receipt identifier is not a bounded public label")
            projected[field] = value
    for field in _COUNT_FIELDS:
        if field in receipt:
            value = receipt[field]
            if type(value) is not int or not 0 <= value <= 2**63 - 1:
                raise PublicExportError("receipt count must be a nonnegative integer")
            projected[field] = value
    # Paths, signatures, keys, arbitrary payloads, generated text, hidden answers,
    # model bytes and private control state have no field in this projection.
    _screen(canonical(projected))
    return projected


def _public_packet(packet: dict) -> dict:
    if type(packet) is not dict:
        raise PublicExportError("only public source packet objects are accepted")
    created = packet.get("created_at")
    if type(created) is not int or not 0 <= created <= int(time.time()):
        raise PublicExportError("source creation time must be recorded and not in the future")
    try:
        return validate_source_packet(packet, now=created)
    except (TypeError, ValueError) as exc:
        raise PublicExportError("capsule failed the public source gate") from exc


def build_public_export(*, namespace: str, sources: Sequence[dict] = (),
                        capsules: Sequence[dict] = (), receipts: Sequence[dict] = ()) -> dict:
    """Build exact immutable public bytes in memory; no filesystem access.

    Sources and capsules use the existing source-only packet contract. Historical
    packets are checked at their recorded creation time: export is archival and
    grants no admission or renewed lifetime to the packet.
    """
    namespace = _namespace(namespace)
    if any(type(items) not in (list, tuple) for items in (sources, capsules, receipts)):
        raise PublicExportError("explicit packet/receipt lists required; directory export refused")
    if not 1 <= len(sources) + len(capsules) + len(receipts) <= MAX_OBJECTS:
        raise PublicExportError("export requires 1 to 64 explicit objects")
    objects: dict[str, bytes] = {}
    members: dict[str, dict] = {}
    for packet in (*sources, *capsules):
        checked = _public_packet(packet)
        raw = _screen(canonical(checked))
        pin = sha256(raw)
        path = f"capsules/sha256/{pin[:2]}/{pin}.json"
        objects[path] = raw
        members[path] = {"path": path, "kind": "source_packet", "sha256": pin,
                         "bytes": len(raw), "packet_sha256": checked["packet_sha256"]}
    for receipt in receipts:
        raw = canonical(_receipt_projection(receipt))
        pin = sha256(raw)
        path = f"receipts/sha256/{pin[:2]}/{pin}.json"
        objects[path] = raw
        members[path] = {"path": path, "kind": "receipt_projection",
                         "sha256": pin, "bytes": len(raw)}
    total = sum(map(len, objects.values()))
    if total > MAX_EXPORT_BYTES:
        raise PublicExportError("export exceeds 4 MiB")
    body = {"schema": SCHEMA, "namespace": namespace, "authority": "none",
            "classification": "public", "members": sorted(members.values(), key=lambda m: m["path"]),
            "bytes": total, "model_calls": 0, "network_calls": 0,
            "provider_upload_verified": False,
            "secret_screening": "known patterns; caller owns classification"}
    manifest = {**body, "manifest_sha256": digest(body)}
    return {"manifest": manifest, "objects": objects}


def _manifest(manifest: dict) -> dict:
    fields = {"schema", "namespace", "authority", "classification", "members", "bytes",
              "model_calls", "network_calls", "provider_upload_verified", "secret_screening",
              "manifest_sha256"}
    if type(manifest) is not dict or set(manifest) != fields or manifest["schema"] != SCHEMA:
        raise PublicExportError("export manifest schema mismatch")
    body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    if not hmac.compare_digest(_hash(manifest["manifest_sha256"]), digest(body)):
        raise PublicExportError("export manifest digest mismatch")
    _namespace(manifest["namespace"])
    if (manifest["authority"] != "none" or manifest["classification"] != "public"
            or type(manifest["model_calls"]) is not int or manifest["model_calls"] != 0
            or type(manifest["network_calls"]) is not int or manifest["network_calls"] != 0
            or manifest["provider_upload_verified"] is not False
            or manifest["secret_screening"] != "known patterns; caller owns classification"
            or type(manifest["members"]) is not list
            or not 1 <= len(manifest["members"]) <= MAX_OBJECTS):
        raise PublicExportError("export manifest bounds or authority mismatch")
    paths = set()
    for member in manifest["members"]:
        if type(member) is not dict or member.get("kind") not in ("source_packet", "receipt_projection"):
            raise PublicExportError("invalid export member")
        expected_fields = {"path", "kind", "sha256", "bytes"}
        kind = member["kind"]
        if kind == "source_packet":
            expected_fields.add("packet_sha256")
            _hash(member.get("packet_sha256"))
        pin = _hash(member.get("sha256"))
        prefix = "capsules" if kind == "source_packet" else "receipts"
        if (set(member) != expected_fields or member["path"] != f"{prefix}/sha256/{pin[:2]}/{pin}.json"
                or member["path"] in paths or type(member["bytes"]) is not int
                or not 1 <= member["bytes"] <= MAX_OBJECT_BYTES):
            raise PublicExportError("invalid export member path or byte count")
        paths.add(member["path"])
    total = sum(member["bytes"] for member in manifest["members"])
    if type(manifest["bytes"]) is not int or manifest["bytes"] != total or total > MAX_EXPORT_BYTES:
        raise PublicExportError("export manifest total mismatch")
    return manifest


def verify_public_readback(manifest: dict, member_path: str, readback: bytes, *,
                           evidence_level: str, namespace: str,
                           provider_download: dict | None = None) -> dict:
    """Check exact bytes and namespace from a caller's observed transport.

    A provider-download observation comes from a caller-owned official connector
    or browser adapter, never a client folder. Its receipt binds the independently
    downloaded raw bytes and provider object/parent identity. Metadata and origin
    labels are caller observations, not authentication performed by this helper.
    """
    manifest = _manifest(manifest)
    if evidence_level not in ("local", "client_folder", "provider_download", "injected_test"):
        raise PublicExportError("unknown readback evidence level")
    if _namespace(namespace) != manifest["namespace"]:
        raise PublicExportError("readback namespace mismatch")
    matches = [member for member in manifest["members"] if member["path"] == member_path]
    if len(matches) != 1 or type(readback) is not bytes or len(readback) > MAX_OBJECT_BYTES:
        raise PublicExportError("readback must identify one bounded manifest member")
    member = matches[0]
    observed = sha256(readback)
    if len(readback) != member["bytes"] or not hmac.compare_digest(observed, member["sha256"]):
        raise PublicExportError("readback byte count or SHA256 mismatch")
    provider = None
    remote = False
    observation_pin = None
    if evidence_level == "provider_download":
        fields = {"schema", "provider", "namespace", "parent_id", "observed_parent_id",
                  "object_id", "observed_object_id", "member_path", "sha256", "bytes",
                  "transport", "receipt_sha256"}
        observation = provider_download
        if type(observation) is not dict or set(observation) != fields:
            raise PublicExportError("provider download requires an exact raw-download observation")
        provider = observation["provider"]
        transports = {"google": "google_drive_connector_raw_download",
                      "proton": "proton_browser_raw_download"}
        if (observation["schema"] != PROVIDER_DOWNLOAD_SCHEMA or provider not in transports
                or observation["transport"] != transports[provider]
                or observation["namespace"] != namespace or observation["member_path"] != member_path
                or observation["sha256"] != observed or type(observation["bytes"]) is not int
                or observation["bytes"] != len(readback)):
            raise PublicExportError("provider download hash, transport or namespace mismatch")
        for expected, actual in (("parent_id", "observed_parent_id"), ("object_id", "observed_object_id")):
            value = observation[expected]
            if (type(value) is not str or not 1 <= len(value) <= 256
                    or any(ord(char) < 33 for char in value) or value != observation[actual]):
                raise PublicExportError("provider object or parent binding mismatch")
        observation_pin = _hash(observation["receipt_sha256"])
        if observation_pin != digest({k: v for k, v in observation.items() if k != "receipt_sha256"}):
            raise PublicExportError("provider observation receipt digest mismatch")
        remote = True
    elif provider_download is not None:
        raise PublicExportError("local, client-folder and injected reads cannot carry provider proof")
    body = {"schema": READBACK_SCHEMA, "namespace": namespace, "member_path": member_path,
            "manifest_sha256": manifest["manifest_sha256"], "expected_sha256": member["sha256"],
            "observed_sha256": observed, "bytes": len(readback), "evidence_level": evidence_level,
            "hash_verified": True, "namespace_verified": True, "provider": provider,
            "provider_observation_sha256": observation_pin, "remote_cloud_verified": remote,
            "provider_authentication_attested_by_helper": False, "authority": "none", "model_calls": 0}
    return {**body, "receipt_sha256": digest(body)}


def _safe_path(path: Path, root: Path | None = None) -> Path:
    if not path.is_absolute() or str(path).startswith(("\\\\", "//")):
        raise PublicExportError("local absolute export path required")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise PublicExportError("export path cannot traverse links or junctions")
    resolved = path.resolve(strict=False)
    if root is not None and not resolved.is_relative_to(root.resolve(strict=False)):
        raise PublicExportError("export path escapes destination")
    if path.exists() and path.is_file() and path.stat().st_nlink > 1:
        raise PublicExportError("hard-linked export file refused")
    return resolved


def _transport_object(path: Path, raw: bytes, root: Path) -> None:
    """The registered tool also enforces the allowlist if called directly."""
    _safe_path(path, root)
    relative = path.relative_to(root).as_posix()
    _screen(raw)

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise PublicExportError("duplicate transport JSON field")
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        if type(value) is not dict or canonical(value) != raw:
            raise PublicExportError("canonical public JSON object required")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise PublicExportError("invalid transport JSON") from exc
    if relative == "public-manifest.json":
        _manifest(value)
        return
    pin = sha256(raw)
    if relative == f"capsules/sha256/{pin[:2]}/{pin}.json":
        _public_packet(value)
        return
    if relative == f"receipts/sha256/{pin[:2]}/{pin}.json":
        required = {"schema", "origin_receipt_sha256", "authority", "classification"}
        permitted = required | _HASH_FIELDS | _ID_FIELDS | _COUNT_FIELDS
        if (not required <= set(value) or set(value) - permitted
                or value["schema"] != RECEIPT_SCHEMA or value["authority"] != "none"
                or value["classification"] != "public"):
            raise PublicExportError("transport receipt projection mismatch")
        _hash(value["origin_receipt_sha256"])
        for field in _HASH_FIELDS & set(value):
            _hash(value[field])
        for field in _ID_FIELDS & set(value):
            if type(value[field]) is not str or not _ID.fullmatch(value[field]):
                raise PublicExportError("invalid transport receipt label")
        for field in _COUNT_FIELDS & set(value):
            if type(value[field]) is not int or not 0 <= value[field] <= 2**63 - 1:
                raise PublicExportError("invalid transport receipt count")
        return
    raise PublicExportError("only fixed manifest and public content-addressed objects are writable")


class PublicExportTools(ToolRegistry):
    METHODS = {"public_export_write": False, "public_export_read": False}

    def publish(self, scope_id: str, path: Path, raw: bytes, root: Path) -> None:
        self.gate(scope_id, "public_export_write", "path:" + str(path))
        _transport_object(path, raw, root)
        path.parent.mkdir(parents=True, exist_ok=True)
        _safe_path(path.parent, root)
        try:
            with path.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if self.read(scope_id, path, root) != raw:
                raise PublicExportError("different prior export preserved for review")
        self.gate(scope_id, "public_export_write", "path:" + str(path))

    def read(self, scope_id: str, path: Path, root: Path) -> bytes:
        self.gate(scope_id, "public_export_read", "path:" + str(path))
        _safe_path(path, root)
        if not path.is_file():
            raise PublicExportError("export member unavailable")
        with path.open("rb") as stream:
            raw = stream.read(MAX_OBJECT_BYTES + 1)
        if len(raw) > MAX_OBJECT_BYTES:
            raise PublicExportError("export read exceeds 64 KiB")
        _transport_object(path, raw, root)
        self.gate(scope_id, "public_export_read", "path:" + str(path))
        _safe_path(path, root)
        return raw


def export_public_artifacts(destination: Path, *, namespace: str,
                            sources: Sequence[dict] = (), capsules: Sequence[dict] = (),
                            receipts: Sequence[dict] = (), authority: ScopeAuthority,
                            scope_id: str) -> dict:
    """Write only fixed immutable JSON objects and a manifest under signed scope.

    A failed/interrupted exclusive creation leaves a conflicting file visible;
    resume refuses it. No private control directory is copied or reconstructed.
    """
    built = build_public_export(namespace=namespace, sources=sources, capsules=capsules, receipts=receipts)
    root = _safe_path(Path(destination))
    authority.load(scope_id)
    tools = PublicExportTools(authority)
    manifest = built["manifest"]
    outputs = {**built["objects"], "public-manifest.json": _screen(canonical(manifest))}
    # Admit all paths before any mutation; a partially permitted scope cannot
    # begin an export and leave a misleading partial package.
    for relative in outputs:
        path = root.joinpath(*PurePosixPath(relative).parts)
        _safe_path(path, root)
        for method in tools.METHODS:
            tools.gate(scope_id, method, "path:" + str(path))
    for relative, raw in outputs.items():
        path = root.joinpath(*PurePosixPath(relative).parts)
        tools.publish(scope_id, path, raw, root)
        if tools.read(scope_id, path, root) != raw:
            raise PublicExportError("export readback differs")
    return manifest


class PublicArchiveStage:
    """Borrow the sphere/export gates for an outer queue's archive callback.

    The private reservation holds only a public packet and a hash of the outer
    request. Authentication and real provider downloads remain caller-owned.
    """
    METHODS = {**PublicExportTools.METHODS, "public_archive_state_read": False,
               "public_archive_state_write": False}

    def __init__(self, sphere, destination: Path, *, namespace: str,
                 authority: ScopeAuthority, scope_id: str, lane: str = "powershell",
                 provider_verifier=None):
        from .oroboros_sphere import SphereController, LANES
        if type(sphere) is not SphereController or lane not in LANES:
            raise PublicExportError("an existing borrowed sphere controller and fixed lane are required")
        self.sphere = sphere
        self.destination = _safe_path(Path(destination))
        self.namespace = _namespace(namespace)
        if len(namespace) > 191:
            raise PublicExportError("archive namespace must leave room for reservation identity")
        self.authority, self.scope_id, self.lane = authority, scope_id, lane
        authority.load(scope_id)
        self.private_root = _safe_path(Path(authority.data_dir))
        # A public export cannot share a tree with scope keys or controller state.
        private_roots = (self.private_root, sphere.control)
        for private in private_roots:
            for public in (self.destination, *sphere.roots.values()):
                if private == public or private in public.parents or public in private.parents:
                    raise PublicExportError("private authority and public transport roots must be separate")
        self.provider_verifier = provider_verifier
        # ToolRegistry.gate is reused; fixed state methods below constrain paths.
        class ArchiveTools(PublicExportTools):
            METHODS = PublicArchiveStage.METHODS
        self.tools = ArchiveTools(authority)

    def _gate_state(self, method: str, path: Path) -> None:
        _safe_path(path, self.private_root)
        relative = path.relative_to(self.private_root).as_posix()
        if not (relative == "public-archive.lock"
                or re.fullmatch(r"archive-stages/[0-9a-f]{64}/packet.json", relative)):
            raise PublicExportError("fixed private archive reservation path required")
        self.tools.gate(self.scope_id, method, "path:" + str(path))

    def _packet(self, request: dict, summary: str, reservation: str) -> dict:
        path = self.private_root / "archive-stages" / reservation / "packet.json"
        lock = self.private_root / "public-archive.lock"
        for method in ("public_archive_state_read", "public_archive_state_write"):
            self._gate_state(method, path)
        self._gate_state("public_archive_state_write", lock)
        with _exclusive_file_lock(lock):
            request_pin = digest(request)
            if path.exists():
                self._gate_state("public_archive_state_read", path)
                with path.open("rb") as stream:
                    raw = stream.read(MAX_OBJECT_BYTES + 1)
                if len(raw) > MAX_OBJECT_BYTES:
                    raise PublicExportError("private archive reservation exceeds 64 KiB")
                state = json.loads(raw)
                if (type(state) is not dict or set(state) != {"schema", "request_sha256", "packet"}
                        or state["schema"] != "xnet.public-archive-reservation.v1"
                        or state["request_sha256"] != request_pin or canonical(state) != raw):
                    raise PublicExportError("archive reservation already binds another request")
                packet = _public_packet(state["packet"])
                if packet["text"] != summary:
                    raise PublicExportError("archive summary differs from its reservation")
                return packet
            task = request["task_id"]
            packet_task = task if len(task) <= 64 else "archive-task-" + sha256(task.encode())[:48]
            packet = make_source_packet(task_id=packet_task, packet_id="archive-" + reservation[:48],
                                        producer="operator", kind="evidence", text=summary)
            state = {"schema": "xnet.public-archive-reservation.v1", "request_sha256": request_pin,
                     "packet": packet}
            raw = canonical(state)
            path.parent.mkdir(parents=True, exist_ok=True)
            _safe_path(path, self.private_root)
            self._gate_state("public_archive_state_write", path)
            with path.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._gate_state("public_archive_state_read", path)
            with path.open("rb") as stream:
                confirmed = stream.read(MAX_OBJECT_BYTES + 1)
            if confirmed != raw:
                raise PublicExportError("private archive reservation readback differs")
            return packet

    def stage(self, request: dict) -> dict:
        """Archive only payload.archive.public_summary; previous outputs stay private."""
        if (type(request) is not dict or request.get("schema") != "xnet.oroboros-outer-request.v1"
                or request.get("stage") != "archive" or type(request.get("payload")) is not dict):
            raise PublicExportError("an outer archive request is required")
        for key in ("task_id", "reservation_id"):
            if type(request.get(key)) is not str or not _ID.fullmatch(request[key]):
                raise PublicExportError("bounded archive task and reservation labels required")
        if len(canonical(request)) > MAX_OBJECT_BYTES:
            raise PublicExportError("outer archive request exceeds 64 KiB")
        config = request["payload"].get("archive")
        if (type(config) is not dict or "public_summary" not in config
                or set(config) - {"public_summary", "require_remote", "remote_providers"}
                or type(config["public_summary"]) is not str
                or type(config.get("require_remote", False)) is not bool):
            raise PublicExportError("explicit public summary and bounded archive options required")
        providers = config.get("remote_providers", ["proton", "google"])
        if (type(providers) is not list or not 1 <= len(providers) <= 2
                or any(type(item) is not str or item not in ("proton", "google") for item in providers)
                or len(set(providers)) != len(providers)):
            raise PublicExportError("explicit unique Proton/Google provider selection required")
        reservation = digest({key: request[key] for key in ("task_id", "reservation_id")})
        namespace = _namespace(self.namespace + "/" + reservation)
        destination = self.destination / "reservations" / reservation
        packet = self._packet(request, config["public_summary"], reservation)
        raw = canonical(packet)
        # A retry borrows the same immutable packet and the sphere's existing
        # admitted identity. It never fabricates a second generation or task.
        cycle = self.sphere.cycle(packet, self.lane, expected_head=self.sphere.plan()["head"])
        for silo in self.sphere.roots:
            if self.sphere.fetch(silo, packet["packet_sha256"], self.lane) != raw:
                raise PublicExportError("archive four-silo FETCH differs from public packet")
        pin = sha256(raw)
        safe_cycle = {"schema": "xnet.public-archive-cycle.v1", "task_id": request["task_id"],
                      "scope_id": self.sphere.scope_id, "object_sha256": pin,
                      "packet_sha256": packet["packet_sha256"],
                      "hop_count": len(cycle["hops"]), "model_calls": 0}
        safe_fetch = {"schema": "xnet.public-archive-fetch.v1", "task_id": request["task_id"],
                      "scope_id": self.sphere.scope_id, "object_sha256": pin,
                      "verified_reads": 4, "bytes": len(raw), "model_calls": 0}
        manifest = export_public_artifacts(destination, namespace=namespace, capsules=[packet],
                                           receipts=[safe_cycle, safe_fetch],
                                           authority=self.authority, scope_id=self.scope_id)
        member = f"capsules/sha256/{pin[:2]}/{pin}.json"
        readiness = {provider: {"evidence_level": "client_folder", "hash_verified": True,
                               "remote_cloud_verified": False,
                               "reason": "actual authenticated raw provider download is pending"}
                     for provider in providers}
        provider_receipts = {}
        if config.get("require_remote", False) and self.provider_verifier is not None:
            public_request = {"schema": "xnet.public-archive-provider-request.v1", "namespace": namespace,
                              "manifest": copy.deepcopy(manifest), "member_path": member,
                              "object_sha256": pin, "providers": list(providers)}
            # The caller's adapter owns its provider scope, authentication and
            # durable dispatch/reconciliation; no private request is passed.
            observations = self.provider_verifier(public_request)
            if type(observations) is not list or len(observations) > len(providers):
                raise PublicExportError("bounded provider download results required")
            for observation in observations:
                if (type(observation) is not dict or set(observation) != {"readback", "observation"}
                        or type(observation["observation"]) is not dict):
                    raise PublicExportError("exact provider raw-download result required")
                provider = observation["observation"].get("provider")
                if provider not in providers or provider in provider_receipts:
                    raise PublicExportError("unexpected or duplicate provider download")
                proof = verify_public_readback(manifest, member, observation["readback"],
                                               namespace=namespace, evidence_level="provider_download",
                                               provider_download=observation["observation"])
                provider_receipts[provider] = proof["receipt_sha256"]
                readiness[provider] = {"evidence_level": "provider_download", "hash_verified": True,
                                       "remote_cloud_verified": True,
                                       "provider_observation_sha256": proof["provider_observation_sha256"]}
        require_remote = config.get("require_remote", False)
        completed = not require_remote or len(provider_receipts) == len(providers)
        return {"schema": "xnet.public-archive-stage-result.v1", "task_id": request["task_id"],
                "outer_reservation_id": request["reservation_id"],
                "stage": "archive", "status": "completed" if completed else "waiting",
                "reason": "requested archive evidence completed" if completed else "remote provider download pending",
                "namespace": namespace, "manifest_sha256": manifest["manifest_sha256"],
                "packet_sha256": packet["packet_sha256"], "object_sha256": pin,
                "sphere_head": cycle["head"], "sphere_scope_id": self.sphere.scope_id,
                "export_scope_id": self.scope_id, "verified_fetches": 4, "hop_count": len(cycle["hops"]),
                "public_export_members": len(manifest["members"]), "require_remote": require_remote,
                "provider_readiness": readiness, "provider_readback_receipts": provider_receipts,
                "authority": "none", "model_calls": 0}
