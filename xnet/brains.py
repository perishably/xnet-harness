"""Content-addressed hot/warm/cold brain connectors with read-only discovery."""
from __future__ import annotations

import ctypes
import json
import os
import re
import stat
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .protocol import ZERO_HASH, canonical, digest, sha256


class BrainError(ValueError):
    pass


PEER_SCHEMA = "xnet.brain-peer.v1"
REGISTRY_SCHEMA = "xnet.brains.v2"


_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


def _process_lock(path: Path) -> threading.RLock:
    """Return one in-process lock for a lock-file path across all Brain objects."""
    key = os.path.normcase(os.path.abspath(path))
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def _exclusive_file_lock(path: Path, *, timeout: float = 30.0) -> Iterator[None]:
    """Hold an advisory byte-range/file lock across threads and OS processes.

    The persistent lock file is intentional. The operating system releases the
    actual lock when a process exits, so a crash cannot leave a stale owner.
    """
    local_lock = _process_lock(path)
    if not local_lock.acquire(timeout=timeout):
        raise BrainError(f"timed out acquiring brain lock: {path.name}")
    fd: int | None = None
    locked = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and (path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())):
            raise BrainError("brain lock file may not be a link")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        deadline = time.monotonic() + timeout
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
                os.fsync(fd)
            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise BrainError(f"timed out acquiring brain lock: {path.name}") from exc
                    time.sleep(0.025)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise BrainError(f"timed out acquiring brain lock: {path.name}") from exc
                    time.sleep(0.025)
    except BaseException as exc:
        if fd is not None:
            os.close(fd)
        local_lock.release()
        if isinstance(exc, OSError):
            raise BrainError(f"brain lock is unavailable: {path.name}") from exc
        raise
    try:
        yield
    finally:
        try:
            if fd is not None and locked:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            finally:
                local_lock.release()


def _no_links(path: Path, base: Path) -> None:
    try:
        rel = path.relative_to(base)
    except ValueError as exc:
        raise BrainError("path escapes designated XNET root") from exc
    cur = base
    for part in rel.parts:
        cur = cur / part
        if cur.exists() and (cur.is_symlink() or (hasattr(cur, "is_junction") and cur.is_junction())):
            raise BrainError("links or junctions inside brain root are forbidden")


class Brain:
    def __init__(self, name: str, base_root: Path, *, expected_peer_id: str | None = None):
        if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in name.lower()):
            raise BrainError("invalid brain name")
        self.name = name
        self.base_root = Path(base_root)
        self.root = self.base_root / "XNET"
        self.expected_peer_id = expected_peer_id
        self.lock = threading.RLock()

    def health(self) -> dict[str, Any]:
        return {"name": self.name, "base_root": str(self.base_root), "state": "ready" if self.root.is_dir() else "available" if self.base_root.is_dir() else "absent", "xnet_root": str(self.root)}

    @property
    def identity_file(self) -> Path:
        return self.root / "peer.json"

    def _read_identity(self, *, required: bool) -> dict[str, str] | None:
        path = self.identity_file
        if not path.is_file():
            if required:
                raise BrainError("peer identity marker is absent; explicitly register the brain again")
            return None
        _no_links(path, self.root)
        try:
            marker = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BrainError("peer identity marker is unreadable") from exc
        if not isinstance(marker, dict) or marker.get("schema") != PEER_SCHEMA or marker.get("name") != self.name:
            raise BrainError("peer identity name or schema mismatch")
        peer_id = marker.get("peer_id")
        try:
            valid_id = str(uuid.UUID(peer_id)) if isinstance(peer_id, str) else ""
        except ValueError as exc:
            raise BrainError("peer identity UUID is invalid") from exc
        if not valid_id or valid_id != peer_id:
            raise BrainError("peer identity UUID is invalid")
        if self.expected_peer_id is not None and peer_id != self.expected_peer_id:
            raise BrainError("peer identity mismatch; the registered storage device is not mounted here")
        return {"schema": PEER_SCHEMA, "name": self.name, "peer_id": peer_id}

    def verify_identity(self) -> dict[str, str]:
        if not self.base_root.is_dir():
            raise BrainError("brain base root is unavailable")
        if not self.root.is_dir():
            raise BrainError("peer XNET root is absent; explicitly register the brain again")
        if self.root.is_symlink() or (hasattr(self.root, "is_junction") and self.root.is_junction()):
            raise BrainError("XNET brain root may not be a link")
        marker = self._read_identity(required=True)
        assert marker is not None
        return marker

    def initialize(self, *, create_identity: bool = False) -> dict[str, str] | None:
        if not self.base_root.is_dir():
            raise BrainError("brain base root is unavailable")
        if self.expected_peer_id is not None:
            self.verify_identity()
        if self.root.exists() and (self.root.is_symlink() or (hasattr(self.root, "is_junction") and self.root.is_junction())):
            raise BrainError("XNET brain root may not be a link")
        for sub in ("cas/sha256", "index", "conflicts"):
            target = self.root / sub
            _no_links(target, self.root)
            target.mkdir(parents=True, exist_ok=True)
        marker = self._read_identity(required=self.expected_peer_id is not None)
        if marker is None and create_identity:
            marker = {"schema": PEER_SCHEMA, "name": self.name, "peer_id": str(uuid.uuid4())}
            try:
                with self.identity_file.open("x", encoding="utf-8") as out:
                    json.dump(marker, out, sort_keys=True)
                    out.write("\n")
                    out.flush()
                    os.fsync(out.fileno())
            except FileExistsError:
                marker = self._read_identity(required=True)
        if self.expected_peer_id is not None:
            marker = self.verify_identity()
        return marker

    def _object_path(self, h: str) -> Path:
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise BrainError("invalid object hash")
        path = self.root / "cas" / "sha256" / h[:2] / h
        _no_links(path, self.root)
        return path

    def read_object(self, h: str) -> bytes:
        if self.expected_peer_id is not None:
            self.verify_identity()
        data = self._object_path(h).read_bytes()
        if sha256(data) != h:
            raise BrainError("brain object hash mismatch")
        if self.expected_peer_id is not None:
            self.verify_identity()
        return data

    @property
    def _receipt_lock_file(self) -> Path:
        return self.root / ".receipts.lock"

    @property
    def _store_lock_file(self) -> Path:
        return self.root / ".store.lock"

    def _receipt_state_unlocked(self, path: Path) -> tuple[int, str]:
        prev = ZERO_HASH
        seq = 0
        if not path.exists():
            return seq, prev
        _no_links(path, self.root)
        try:
            with path.open("rb") as inp:
                for raw_line in inp:
                    if not raw_line.strip():
                        continue
                    row = json.loads(raw_line)
                    seq += 1
                    if not isinstance(row, dict):
                        raise BrainError(f"receipt conflict at {self.name} sequence {seq}")
                    body = {k: v for k, v in row.items() if k != "receipt_hash"}
                    if (
                        row.get("seq") != seq
                        or row.get("prev_hash") != prev
                        or row.get("brain") != self.name
                        or digest(body) != row.get("receipt_hash")
                    ):
                        raise BrainError(f"receipt conflict at {self.name} sequence {seq}")
                    prev = row["receipt_hash"]
        except BrainError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            raise BrainError(f"receipt conflict at {self.name} sequence {seq + 1}") from exc
        return seq, prev

    def _receipt_unlocked(self, action: str, h: str, detail: dict[str, Any]) -> dict[str, Any]:
        path = self.root / "receipts.jsonl"
        seq, prev = self._receipt_state_unlocked(path)
        seq += 1
        body = {"seq": seq, "prev_hash": prev, "brain": self.name, "action": action, "object_hash": h, "detail": detail, "time_utc": int(time.time())}
        receipt = {**body, "receipt_hash": digest(body)}
        try:
            with path.open("ab") as out:
                out.write(canonical(receipt) + b"\n")
                out.flush()
                os.fsync(out.fileno())
        except OSError as exc:
            raise BrainError("receipt append failed") from exc
        return receipt

    def _receipt(self, action: str, h: str, detail: dict[str, Any]) -> dict[str, Any]:
        path = self.root / "receipts.jsonl"
        _no_links(path, self.root)
        _no_links(self._receipt_lock_file, self.root)
        with _exclusive_file_lock(self._receipt_lock_file):
            return self._receipt_unlocked(action, h, detail)

    def store_object(self, data: bytes, *, kind: str = "evidence", origin: str = "local") -> dict[str, Any]:
        if len(data) > 32 * 1024 * 1024:
            raise BrainError("object exceeds 32 MiB limit")
        self.initialize()
        h = sha256(data)
        target = self._object_path(h)
        _no_links(self._store_lock_file, self.root)
        _no_links(self._receipt_lock_file, self.root)
        with self.lock, _exclusive_file_lock(self._store_lock_file), _exclusive_file_lock(self._receipt_lock_file):
            # Refuse all content mutations when the audit chain is not intact.
            self._receipt_state_unlocked(self.root / "receipts.jsonl")
            if self.expected_peer_id is not None:
                self.verify_identity()
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if sha256(target.read_bytes()) != h:
                    conflict = {"hash": h, "path": str(target), "time_utc": int(time.time()), "reason": "existing object content does not match address"}
                    with (self.root / "conflicts" / f"{h}.{time.time_ns()}.json").open("x", encoding="utf-8") as out:
                        json.dump(conflict, out, sort_keys=True)
                    self._receipt_unlocked("conflict", h, conflict)
                    raise BrainError("existing object hash conflict; retained for manual review")
                action = "verified-existing"
            else:
                fd, tmp = tempfile.mkstemp(prefix=".xnet-", dir=target.parent)
                try:
                    with os.fdopen(fd, "wb") as out:
                        out.write(data)
                        out.flush()
                        os.fsync(out.fileno())
                    if sha256(Path(tmp).read_bytes()) != h:
                        raise BrainError("staged object hash mismatch")
                    os.replace(tmp, target)
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                action = "stored"
            metadata = {"hash": h, "size": len(data), "kind": kind, "origin": origin, "brain": self.name, "time_utc": int(time.time())}
            index_path = self.root / "index" / f"{h}.json"
            if not index_path.exists():
                with index_path.open("x", encoding="utf-8") as out:
                    json.dump(metadata, out, sort_keys=True)
                    out.flush()
                    os.fsync(out.fileno())
            receipt = self._receipt_unlocked(action, h, {"size": len(data), "origin": origin, "kind": kind})
            if self.expected_peer_id is not None:
                self.verify_identity()
            return receipt

    def verify_receipts(self) -> dict[str, Any]:
        path = self.root / "receipts.jsonl"
        if not self.root.exists():
            return {"brain": self.name, "receipts": 0, "head": ZERO_HASH, "intact": True}
        _no_links(path, self.root)
        _no_links(self._receipt_lock_file, self.root)
        with _exclusive_file_lock(self._receipt_lock_file):
            seq, prev = self._receipt_state_unlocked(path)
        return {"brain": self.name, "receipts": seq, "head": prev, "intact": True}


def discover_brains() -> list[dict[str, Any]]:
    """Inspect candidate roots only; never create XNET or traverse existing content."""
    candidates: list[tuple[str, Path, str]] = []
    if os.name == "nt":
        buf = ctypes.create_unicode_buffer(512)
        n = ctypes.windll.kernel32.GetLogicalDriveStringsW(512, buf)
        if n:
            for root in buf[:n].split("\x00"):
                if not root:
                    continue
                kind = ctypes.windll.kernel32.GetDriveTypeW(root)
                if kind == 2:
                    label = ctypes.create_unicode_buffer(256)
                    ctypes.windll.kernel32.GetVolumeInformationW(root, label, 256, None, None, None, None, 0)
                    candidates.append((f"volume-{root[0].lower()}", Path(root), label.value or "removable volume"))
    archive = os.environ.get("XNET_ARCHIVE_ROOT")
    if archive:
        candidates.append(("archive-drive", Path(archive), "configured archive root"))
    proton = os.environ.get("XNET_PROTON_DRIVE_ROOT")
    if proton:
        candidates.append(("proton-drive", Path(proton), "configured sync root"))
    else:
        for path in (Path.home() / "Proton Drive", Path.home() / "Documents" / "Proton Drive", Path.home() / "ProtonDrive"):
            if path.is_dir():
                candidates.append(("proton-drive", path, "detected sync root"))
                break
    for i, raw in enumerate(filter(None, os.environ.get("XNET_REMOVABLE_ROOTS", "").split(os.pathsep))):
        candidates.append((f"optional-{i+1}", Path(raw), "configured removable root"))
    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, root, description in candidates:
        normalized = os.path.normcase(os.path.abspath(root))
        if normalized in seen:
            continue
        seen.add(normalized)
        discovered.append({"name": name, "base_root": str(root), "description": description, "state": "available" if root.is_dir() else "absent", "xnet_initialized": (root / "XNET").is_dir()})
    return discovered


class BrainSet:
    def __init__(self, local_base: Path):
        self.local = Brain("laptop", local_base)
        self.config_file = self.local.root / "brains.json"
        self.registry_lock_file = self.local.root / ".brains.lock"

    def register(self, name: str, base_root: Path) -> dict[str, Any]:
        if name == "laptop":
            raise BrainError("laptop brain is implicit")
        self.local.initialize()
        peer = Brain(name, base_root)
        if not peer.base_root.is_dir():
            raise BrainError("peer base root does not exist")
        _no_links(self.registry_lock_file, self.local.root)
        with _exclusive_file_lock(self.registry_lock_file):
            registry = self._load_registry_unlocked()
            marker = peer.initialize(create_identity=True)
            assert marker is not None
            registry["peers"][name] = {"base_root": str(peer.base_root), "peer_id": marker["peer_id"]}
            registry["legacy"].pop(name, None)
            self._write_registry_unlocked(registry)
        return {**peer.health(), "peer_id": marker["peer_id"]}

    def registered(self) -> dict[str, str]:
        registry = self._load_registry()
        records = {name: row["base_root"] for name, row in registry["legacy"].items()}
        records.update({name: row["base_root"] for name, row in registry["peers"].items()})
        return records

    def _write_registry(self, registry: dict[str, Any]) -> None:
        self.local.initialize()
        _no_links(self.registry_lock_file, self.local.root)
        with _exclusive_file_lock(self.registry_lock_file):
            self._write_registry_unlocked(registry)

    def _write_registry_unlocked(self, registry: dict[str, Any]) -> None:
        # Validate the complete replacement before it can become authoritative.
        checked = self._validate_v2_registry(registry)
        _no_links(self.config_file, self.local.root)
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{self.config_file.name}.", suffix=".tmp", dir=self.config_file.parent
            )
        except OSError as exc:
            raise BrainError("brain registry write failed") from exc
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(checked, out, indent=2, sort_keys=True)
                out.write("\n")
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, self.config_file)
        except OSError as exc:
            raise BrainError("brain registry write failed") from exc
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _load_registry(self) -> dict[str, Any]:
        self.local.initialize()
        _no_links(self.registry_lock_file, self.local.root)
        with _exclusive_file_lock(self.registry_lock_file):
            return self._load_registry_unlocked()

    def _validate_v2_registry(self, raw: dict[str, Any]) -> dict[str, Any]:
        if raw.get("schema") != REGISTRY_SCHEMA:
            raise BrainError("brain registry schema is invalid")
        peers = raw.get("peers")
        legacy = raw.get("legacy", {})
        if not isinstance(peers, dict) or not isinstance(legacy, dict):
            raise BrainError("brain registry peers are invalid")
        checked: dict[str, dict[str, str]] = {}
        for name, row in peers.items():
            if not isinstance(name, str) or not isinstance(row, dict):
                raise BrainError("brain registry peer record is invalid")
            base_root, peer_id = row.get("base_root"), row.get("peer_id")
            try:
                normalized_id = str(uuid.UUID(peer_id)) if isinstance(peer_id, str) else ""
            except ValueError as exc:
                raise BrainError("brain registry peer UUID is invalid") from exc
            if not isinstance(base_root, str) or not base_root or normalized_id != peer_id:
                raise BrainError("brain registry peer record is invalid")
            Brain(name, Path(base_root))
            checked[name] = {"base_root": base_root, "peer_id": peer_id}
        checked_legacy: dict[str, dict[str, str]] = {}
        for name, row in legacy.items():
            if not isinstance(name, str) or not isinstance(row, dict) or not isinstance(row.get("base_root"), str):
                raise BrainError("legacy brain registry peer record is invalid")
            Brain(name, Path(row["base_root"]))
            checked_legacy[name] = {"base_root": row["base_root"]}
        return {"schema": REGISTRY_SCHEMA, "peers": checked, "legacy": checked_legacy}

    def _load_registry_unlocked(self) -> dict[str, Any]:
        empty: dict[str, Any] = {"schema": REGISTRY_SCHEMA, "peers": {}, "legacy": {}}
        if not self.config_file.exists():
            return empty
        _no_links(self.config_file, self.local.root)
        try:
            raw = json.loads(self.config_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BrainError("brain registry is unreadable") from exc
        if not isinstance(raw, dict):
            raise BrainError("brain registry is invalid")
        if raw.get("schema") == REGISTRY_SCHEMA:
            return self._validate_v2_registry(raw)

        # Version 1 was a name -> path mapping. It can be upgraded only when the
        # path already carries a matching identity marker; no marker is created
        # during discovery or mirroring.
        migrated: dict[str, dict[str, str]] = {}
        legacy: dict[str, dict[str, str]] = {}
        for name, base_root in raw.items():
            if not isinstance(name, str) or not isinstance(base_root, str):
                raise BrainError("legacy brain registry is invalid")
            peer = Brain(name, Path(base_root))
            try:
                marker = peer.verify_identity()
            except BrainError:
                legacy[name] = {"base_root": base_root}
            else:
                migrated[name] = {"base_root": base_root, "peer_id": marker["peer_id"]}
        registry = {"schema": REGISTRY_SCHEMA, "peers": migrated, "legacy": legacy}
        self._write_registry_unlocked(registry)
        return registry

    def mirror(self, h: str, name: str) -> dict[str, Any]:
        registry = self._load_registry()
        if name not in registry["peers"]:
            if name in registry["legacy"]:
                raise BrainError("legacy brain requires explicit re-registration before mirroring")
            raise BrainError("brain is not registered")
        row = registry["peers"][name]
        peer = Brain(name, Path(row["base_root"]), expected_peer_id=row["peer_id"])
        peer.verify_identity()
        data = self.local.read_object(h)
        receipt = peer.store_object(data, origin="laptop")
        peer.verify_identity()
        if peer.read_object(h) != data:
            raise BrainError("replica verification failed")
        self.local._receipt("replicated", h, {"peer": name, "peer_receipt_hash": receipt["receipt_hash"]})
        return receipt


# This seam deliberately does not call Brain initialization, registry migration,
# receipt locks or mirror(): every tier access below is read-only.
FROZEN_MIRROR_SCHEMA = "xnet.frozen-mirror-manifest.v1"


@dataclass(frozen=True)
class FrozenMirrorEntry:
    """Operator-approved PUBLIC file, independently of the supplied manifest."""
    entry_id: str
    source_id: str
    ring: str
    layout: str  # native or brain; root is the actual CAS owner's root
    relative_path: str
    sha256: str
    bytes: int


@dataclass(frozen=True)
class FrozenMirrorTier:
    """Caller-selected root: source/relative or mirror/ring/relative."""
    tier_id: str
    source_id: str
    ring: str
    root: Path
    namespace: str  # source or mirror (an orbit root)


@dataclass(frozen=True)
class FrozenMirrorLimits:
    max_manifest_bytes: int = 1024 * 1024
    max_entries: int = 1024
    max_tiers: int = 32
    max_object_bytes: int = 32 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    deadline_seconds: float = 30.0


@dataclass(frozen=True)
class FrozenMirrorReceipt:
    """Immutable canonical receipt bytes; a digest is integrity, not authentication."""
    payload: bytes
    sha256: str


@dataclass(frozen=True)
class FrozenMirrorFetch:
    data: bytes
    tier_id: str
    receipt: FrozenMirrorReceipt


def _frozen_id(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) is not None


def _frozen_sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _frozen_relative(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise BrainError("frozen path is invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise BrainError("frozen path is invalid") from exc
    parts = tuple(value.split("/"))
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if (len(parts) > 8 or any(not p or p in (".", "..") or p[-1:] in (".", " ")
                             or p.split(".", 1)[0].lower() in reserved
                             or any(ord(c) < 32 or c in '\\:< >"|?*'.replace(" ", "") for c in p)
                             for p in parts)):
        raise BrainError("frozen path is unsafe")
    return parts


def _frozen_row(entry: FrozenMirrorEntry) -> dict[str, Any]:
    return {"entry_id": entry.entry_id, "source_id": entry.source_id, "ring": entry.ring,
            "layout": entry.layout, "relative_path": entry.relative_path,
            "sha256": entry.sha256, "bytes": entry.bytes, "classification": "public"}


def _frozen_prepare(manifest_bytes: bytes, expected_manifest_sha256: str, task_id: str,
                    approved_entries: tuple[FrozenMirrorEntry, ...], tiers: tuple[FrozenMirrorTier, ...],
                    limits: FrozenMirrorLimits) -> tuple[tuple[FrozenMirrorEntry, ...], tuple[FrozenMirrorTier, ...], dict[str, Any]]:
    integer_limits = (limits.max_manifest_bytes, limits.max_entries, limits.max_tiers,
                      limits.max_object_bytes, limits.max_total_bytes)
    if (any(type(v) is not int or v <= 0 for v in integer_limits)
            or limits.max_manifest_bytes > 1024 * 1024 or limits.max_entries > 1024
            or limits.max_tiers > 32 or limits.max_object_bytes > 32 * 1024 * 1024
            or limits.max_total_bytes > 64 * 1024 * 1024
            or type(limits.deadline_seconds) not in (int, float)
            or not 0 < limits.deadline_seconds <= 30):
        raise BrainError("frozen verifier bounds are invalid")
    if (not isinstance(manifest_bytes, bytes) or not 0 < len(manifest_bytes) <= limits.max_manifest_bytes
            or not _frozen_sha(expected_manifest_sha256) or sha256(manifest_bytes) != expected_manifest_sha256
            or not _frozen_id(task_id)):
        raise BrainError("frozen manifest external pin is invalid")
    entries, selected_tiers = tuple(approved_entries), tuple(tiers)
    if not 0 < len(entries) <= limits.max_entries or not 0 < len(selected_tiers) <= limits.max_tiers:
        raise BrainError("frozen selection exceeds bounds")
    entry_ids: set[str] = set()
    locations: set[tuple[str, str]] = set()
    for entry in entries:
        if not isinstance(entry, FrozenMirrorEntry) or not all(_frozen_id(v) for v in (entry.entry_id, entry.source_id, entry.ring)):
            raise BrainError("frozen public selection is invalid")
        _frozen_relative(entry.ring)
        parts = _frozen_relative(entry.relative_path)
        if not _frozen_sha(entry.sha256) or type(entry.bytes) is not int or not 0 <= entry.bytes <= limits.max_object_bytes:
            raise BrainError("frozen public size/hash is invalid")
        object_path = ("cas", entry.sha256[:2], entry.sha256) if entry.layout == "native" else ("cas", "sha256", entry.sha256[:2], entry.sha256)
        ledger_path = ("audit.jsonl",) if entry.layout == "native" else ("receipts.jsonl",)
        if entry.layout not in ("native", "brain") or parts not in (object_path, ledger_path):
            raise BrainError("frozen entry does not match declared CAS/ledger layout")
        if entry.layout == "native" and parts == object_path and entry.bytes > 64 * 1024:
            raise BrainError("native frozen CAS exceeds its 64 KiB bound")
        location = (entry.ring, entry.relative_path.lower())
        if entry.entry_id in entry_ids or location in locations:
            raise BrainError("duplicate frozen entry or location")
        entry_ids.add(entry.entry_id)
        locations.add(location)
    tier_ids: set[str] = set()
    for tier in selected_tiers:
        if (not isinstance(tier, FrozenMirrorTier) or not all(_frozen_id(v) for v in (tier.tier_id, tier.source_id, tier.ring))
                or tier.tier_id in tier_ids or tier.namespace not in ("source", "mirror")
                or not isinstance(tier.root, Path) or not tier.root.is_absolute()
                or any(p == ".." for p in tier.root.parts)):
            raise BrainError("frozen tier selection is invalid")
        tier_ids.add(tier.tier_id)
        _frozen_relative(tier.ring)
        if not any(e.source_id == tier.source_id and e.ring == tier.ring for e in entries):
            raise BrainError("tier is not bound to an approved source/ring")
    if any(not any(t.source_id == e.source_id and t.ring == e.ring for t in selected_tiers) for e in entries):
        raise BrainError("approved entry has no declared tier")
    if sum(e.bytes for e in entries for t in selected_tiers if t.source_id == e.source_id and t.ring == e.ring) > limits.max_total_bytes:
        raise BrainError("frozen cycle read budget exceeds bound")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise BrainError("duplicate frozen manifest key")
            value[key] = item
        return value

    try:
        raw = json.loads(manifest_bytes.decode("utf-8", "strict"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise BrainError("frozen manifest is malformed") from exc
    rows = [_frozen_row(e) for e in entries]
    if (not isinstance(raw, dict) or set(raw) != {"schema", "task_id", "authority", "entries"}
            or raw.get("schema") != FROZEN_MIRROR_SCHEMA or raw.get("task_id") != task_id
            or raw.get("authority") != "none" or raw.get("entries") != rows
            or any(not isinstance(r, dict) or set(r) != set(rows[0]) or type(r.get("bytes")) is not int for r in raw.get("entries", []))):
        raise BrainError("manifest differs from independently approved public selection")
    policy = {"task_id": task_id, "approved_entries": rows,
              "tiers": [{"tier_id": t.tier_id, "source_id": t.source_id, "ring": t.ring,
                         "root": str(t.root), "namespace": t.namespace} for t in selected_tiers],
              "bounds": {"manifest": limits.max_manifest_bytes, "entries": limits.max_entries,
                         "tiers": limits.max_tiers, "object": limits.max_object_bytes,
                         "total": limits.max_total_bytes, "deadline_seconds": limits.deadline_seconds}}
    return entries, selected_tiers, policy


class _FrozenReadError(BrainError):
    def __init__(self, status: str, observed_bytes: int | None = None):
        super().__init__(status)
        self.status, self.observed_bytes = status, observed_bytes


def _frozen_path_identity(path: Path) -> tuple[tuple[int, int, int], ...]:
    """Check every ancestor, including caller root ancestors, without resolving links."""
    chain = tuple(reversed(path.parents)) + (path,)
    identities = []
    for node in chain:
        s = node.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400:
            raise _FrozenReadError("unsafe-link")
        if node != path and not stat.S_ISDIR(s.st_mode):
            raise _FrozenReadError("unsafe-path")
        if node == path and (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1):
            raise _FrozenReadError("unsafe-link")
        identities.append((s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode)))
    return tuple(identities)


def _frozen_open(path: Path) -> int:
    if os.name != "nt":
        return os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    # Deny concurrent writes/deletion for this held read on Windows. Opening a
    # cloud placeholder can still block inside the OS; deadline is cooperative.
    import msvcrt
    from ctypes import wintypes
    create = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    handle = create(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(wintypes.HANDLE(handle))
        raise


def _frozen_read(entry: FrozenMirrorEntry, tier: FrozenMirrorTier, deadline: float) -> tuple[bytes | None, dict[str, Any]]:
    path = tier.root.joinpath(*(([entry.ring] if tier.namespace == "mirror" else []) + list(_frozen_relative(entry.relative_path))))
    outcome: dict[str, Any] = {"entry_id": entry.entry_id, "tier_id": tier.tier_id,
                              "expected_sha256": entry.sha256, "expected_bytes": entry.bytes,
                              "observed_sha256": None, "observed_bytes": None, "status": "unverified"}
    fd: int | None = None
    data: bytes | None = None
    try:
        if time.monotonic() >= deadline:
            raise _FrozenReadError("deadline-exceeded")
        before_path = _frozen_path_identity(path)
        fd = _frozen_open(path)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) != before_path[-1]):
            raise _FrozenReadError("concurrent-change")
        outcome["observed_bytes"] = before.st_size
        if before.st_size != entry.bytes:
            raise _FrozenReadError("size-mismatch", before.st_size)
        chunks = []
        remaining = entry.bytes + 1
        while remaining:
            if time.monotonic() >= deadline:
                raise _FrozenReadError("deadline-exceeded")
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        after_path = _frozen_path_identity(path)
        snapshot = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if snapshot(before) != snapshot(after) or before_path != after_path:
            raise _FrozenReadError("concurrent-change")
        outcome["observed_bytes"], outcome["observed_sha256"] = len(data), sha256(data)
        if len(data) != entry.bytes:
            raise _FrozenReadError("size-mismatch", len(data))
        if outcome["observed_sha256"] != entry.sha256:
            raise _FrozenReadError("hash-mismatch")
        outcome["status"] = "match"
        outcome["path_identity"] = [list(v) for v in after_path]
    except _FrozenReadError as exc:
        outcome["status"] = exc.status
        if exc.observed_bytes is not None:
            outcome["observed_bytes"] = exc.observed_bytes
        data = None
    except FileNotFoundError:
        outcome["status"] = "confirmed-missing" if tier.root.is_dir() else "root-unavailable"
        data = None
    except PermissionError:
        outcome["status"], data = "access-denied", None
    except OSError:
        outcome["status"], data = "storage-unavailable", None
    finally:
        if fd is not None:
            os.close(fd)
    return data, outcome


def _frozen_receipt(kind: str, expected_manifest_sha256: str, policy: dict[str, Any],
                    outcomes: list[dict[str, Any]], **extra: Any) -> FrozenMirrorReceipt:
    body = {"schema": "xnet.frozen-mirror-receipt.v1", "operation": kind,
            "manifest_sha256": expected_manifest_sha256, "policy_sha256": digest(policy),
            "policy": policy, "outcomes": outcomes, "alarm": any(r["status"] != "match" for r in outcomes),
            "authority": "none", "model_calls": 0, "mirror_mutations": 0,
            "remote_cloud_verified": False, **extra}
    payload = canonical(body)
    return FrozenMirrorReceipt(payload, sha256(payload))


def verify_frozen_manifest(manifest_bytes: bytes, expected_manifest_sha256: str, *, task_id: str,
                           approved_entries: tuple[FrozenMirrorEntry, ...], tiers: tuple[FrozenMirrorTier, ...],
                           limits: FrozenMirrorLimits | None = None) -> FrozenMirrorReceipt:
    """Check every declared copy against the external frozen baseline, without writes."""
    limits = limits or FrozenMirrorLimits()
    entries, selected_tiers, policy = _frozen_prepare(manifest_bytes, expected_manifest_sha256, task_id, approved_entries, tiers, limits)
    deadline = time.monotonic() + limits.deadline_seconds
    outcomes = []
    for entry in entries:
        for tier in selected_tiers:
            if tier.source_id == entry.source_id and tier.ring == entry.ring:
                _, outcome = _frozen_read(entry, tier, deadline)
                outcomes.append(outcome)
    return _frozen_receipt("verify", expected_manifest_sha256, policy, outcomes)


def fetch_frozen_object(manifest_bytes: bytes, expected_manifest_sha256: str, *, task_id: str,
                        approved_entries: tuple[FrozenMirrorEntry, ...], tiers: tuple[FrozenMirrorTier, ...],
                        entry_id: str, limits: FrozenMirrorLimits | None = None) -> FrozenMirrorFetch:
    """Return the exact bytes hashed from one held read; tier order is caller declared."""
    limits = limits or FrozenMirrorLimits()
    entries, selected_tiers, policy = _frozen_prepare(manifest_bytes, expected_manifest_sha256, task_id, approved_entries, tiers, limits)
    entry = next((e for e in entries if e.entry_id == entry_id), None)
    if entry is None or not entry.relative_path.startswith("cas/"):
        raise BrainError("exact FETCH requires an approved CAS entry")
    deadline = time.monotonic() + limits.deadline_seconds
    outcomes = []
    for tier in selected_tiers:
        if tier.source_id == entry.source_id and tier.ring == entry.ring:
            data, outcome = _frozen_read(entry, tier, deadline)
            outcomes.append(outcome)
            if data is not None:
                receipt = _frozen_receipt("fetch", expected_manifest_sha256, policy, outcomes,
                                          entry_id=entry_id, selected_tier=tier.tier_id, returned_sha256=sha256(data))
                return FrozenMirrorFetch(data, tier.tier_id, receipt)
    # Failed fetches still expose their immutable, content-free diagnostic receipt.
    error = BrainError("no declared tier supplied the frozen exact object")
    error.receipt = _frozen_receipt("fetch", expected_manifest_sha256, policy, outcomes,
                                     entry_id=entry_id, selected_tier=None, returned_sha256=None)
    raise error
