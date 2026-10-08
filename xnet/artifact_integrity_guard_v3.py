"""Scoped, process-local continuity guard for already pinned runtime artifacts.

This module owns no process, transport, durable state, scheduler or permissions.
The caller supplies exact file/hash selections and its signed scope gate. The
caller must establish the guard before using artifacts, call ``verify_dispatch``
before and after each callback, and call ``full_boundary`` at the existing
explicit round/admission/release boundaries. Every reopen starts unestablished.

Large artifact bytes are fully hashed on establishment and explicit boundaries.
On Windows, retained read handles deny write/delete sharing for the guard's
lifetime. Dispatch checks bind those handles to the same one-link OS identity.
This prevents ordinary filesystem writers from changing bytes and restoring
timestamps. It does not defend against kernel/raw-disk changes. Explicit
``metadata-only`` mode has a weaker guarantee: it cannot detect content changes
which preserve every reported metadata field until the next full boundary.
Evidence names the protection mode; metadata continuity is never described as
fresh cryptographic content verification. Selected source files remain fully
hashed on every dispatch; this guard never caches their hash.

Windows CPython derives executable mode bits from an lstat filename suffix,
while descriptor fstat has no filename and omits those bits. Only those synthetic
execute bits are normalized on Windows. File type, read/write mode, readonly
attributes, device/inode, link count, reparse controls and byte hashes remain
part of admission and continuity. Non-Windows mode bits are kept unchanged.

Any observed drift, unavailable path or refused scope permanently poisons this
instance. Restoring bytes/metadata cannot heal it; use a new reviewed run root.
No caller can substitute a new declared hash after establishment.

V3 separately binds declared immutable transport EXE/DLL rows as a subset of
retained files. Borrowed transport checks verify only those held read leases;
they neither grant permissions nor replace the surrounding fresh source check.
The exact roles and every original hash remain in the frozen caller binding.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time

from .protocol import digest
from .relay_log import _no_links


SCHEMA = "xnet.artifact-integrity-guard.v3"
FROZEN_PREDECESSOR_SHA256 = "722288a719304ac3ff6b55f8129afd4e1dec4c0efb41fe18ef7ecaccb94e2807"
PATH_METHODS = ("artifact_guard_stat", "artifact_guard_hash", "artifact_guard_lease")
BOUNDARIES = frozenset({"round-entry", "round-exit", "learner-admission", "release", "restart"})


class ArtifactIntegrityError(ValueError):
    """Typed refusal; this guard cannot be reused after the refusal."""

    def __init__(self, reason, *, phase, path=None):
        self.reason, self.phase, self.path = reason, phase, path
        super().__init__(f"Artifact integrity refused: {reason} ({phase})" + (" path=" + str(path) if path is not None else ""))


@dataclass(frozen=True)
class _Snapshot:
    device: int
    inode: int
    size: int
    mtime_ns: int
    change_or_birth_ns: int
    mode: int
    nlink: int
    attributes: int

    @classmethod
    def from_stat(cls, value):
        # Bundled CPython 3.12 on Windows reports creation time through lstat's
        # st_ctime but change time through some fstat paths. st_birthtime_ns is
        # stable and consistent on both routes; write safety comes from the
        # retained Win32 read lease, not a claim that birth time tracks writes.
        timestamp = getattr(value, "st_birthtime_ns", value.st_ctime_ns) if os.name == "nt" else value.st_ctime_ns
        # Proven on the actual selected runner and native .exe: lstat adds
        # 0o111, fstat omits it. The difference describes the supplied filename,
        # not a Windows ACL or byte change. All other mode bits are preserved.
        mode = value.st_mode & ~0o111 if os.name == "nt" else value.st_mode
        return cls(value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                   timestamp, mode, value.st_nlink,
                   getattr(value, "st_file_attributes", 0))


class _WindowsReadLease:
    """One owned Win32 read handle; only FILE_SHARE_READ is granted."""

    def __init__(self, path):
        import ctypes
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        create.restype = wintypes.HANDLE
        close = kernel.CloseHandle
        close.argtypes = (wintypes.HANDLE,)
        close.restype = wintypes.BOOL
        # GENERIC_READ; FILE_SHARE_READ only; OPEN_EXISTING;
        # OPEN_REPARSE_POINT avoids silently following a newly substituted link.
        handle = create(str(path), 0x80000000, 0x1, None, 3, 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        descriptor = None
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            self.stream = os.fdopen(descriptor, "rb")
        except Exception:
            if descriptor is None:
                close(handle)
            else:
                os.close(descriptor)
            raise

    def snapshot(self):
        if self.stream.closed:
            raise OSError("Retained read lease is closed")
        return _Snapshot.from_stat(os.fstat(self.stream.fileno()))

    def close(self):
        self.stream.close()


def _selection(rows, *, role):
    if type(rows) is not list or not 1 <= len(rows) <= 128:
        raise ValueError(f"Explicit bounded {role} artifact selection required")
    selected = []
    for row in rows:
        if (type(row) is not dict or set(row) != {"path", "sha256"}
                or type(row["path"]) is not str or not row["path"] or "\x00" in row["path"]
                or not Path(row["path"]).is_absolute()
                or type(row["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError(f"Exact absolute {role} artifact path/hash required")
        # Inspect the supplied route before collapsing any dot components. This
        # validation is pure; actual path reads occur only after the caller gate.
        if any(part in (".", "..") for part in Path(row["path"]).parts):
            raise ValueError("Artifact paths must not contain dot components")
        selected.append({"path": os.path.abspath(row["path"]), "sha256": row["sha256"]})
    if len({os.path.normcase(row["path"]) for row in selected}) != len(selected):
        raise ValueError(f"Duplicate {role} artifact path")
    return tuple(sorted(selected, key=lambda row: os.path.normcase(row["path"])))


class ArtifactIntegrityGuard:
    """Separate cryptographic boundary checks from cheap per-dispatch continuity.

    ``retained_artifacts`` selects weights/runner/native binaries which are
    expensive to repeatedly read. ``source_artifacts`` selects adapter/SDK/code
    files which always retain full hashing. Selections cannot overlap: a source
    cannot be relabeled as a retained file to skip its per-dispatch content check.
    Classification and this module's source identity must also be part of the
    enclosing caller's frozen protocol/run identity.
    """

    def __init__(self, retained_artifacts, source_artifacts, gate, *, protection="auto", max_dispatch_checks=1024,
                 transport_artifacts=None):
        if not callable(gate):
            raise TypeError("A caller's signed scope gate is required")
        if type(max_dispatch_checks) is not int or not 1 <= max_dispatch_checks <= 4096:
            raise ValueError("A bounded dispatch check budget is required")
        if protection not in ("auto", "windows-read-lease", "metadata-only"):
            raise ValueError("An explicit supported artifact protection mode is required")
        if protection == "auto":
            protection = "windows-read-lease" if os.name == "nt" else "metadata-only"
        if protection == "windows-read-lease" and os.name != "nt":
            raise ValueError("Windows read leases are required but unavailable on this platform")
        self._retained = _selection(retained_artifacts, role="retained")
        self._sources = _selection(source_artifacts, role="source")
        self._transport = () if transport_artifacts is None or transport_artifacts == [] else _selection(transport_artifacts, role="transport")
        retained_paths = {os.path.normcase(row["path"]) for row in self._retained}
        if retained_paths & {os.path.normcase(row["path"]) for row in self._sources}:
            raise ValueError("Source and retained artifact selections must not overlap")
        retained_by_path = {os.path.normcase(row["path"]): row for row in self._retained}
        if any(Path(row["path"]).suffix.lower() not in (".exe", ".dll")
               or retained_by_path.get(os.path.normcase(row["path"])) != row for row in self._transport):
            raise ValueError("Transport EXE/DLL selection must exactly match retained pins")
        self._gate = gate
        self._frozen_gate = gate
        self._protection = protection
        self._leases = {}
        self._max_checks = max_dispatch_checks
        self._manifest = {"schema": SCHEMA, "retained_artifacts": list(self._retained),
                          "source_artifacts": list(self._sources), "max_dispatch_checks": max_dispatch_checks,
                          "transport_artifacts": list(self._transport),
                          "transport_policy": "caller-declared immutable EXE/DLL role; source declarations win overlap; held Windows deny-write/delete lease; full initial/boundary/release SHA256",
                          "protection": protection, "platform": os.name,
                          "predecessor_sha256": FROZEN_PREDECESSOR_SHA256,
                          "mode_policy": "Windows filename-derived execute bits excluded; file type/read/write mode and all attributes retained"}
        self._manifest_pin = digest(self._manifest)
        self._snapshots = None
        self._snapshot_pin = None
        self._poison = None
        self._closed = False
        self._lock = threading.RLock()
        self._full_checks = 0
        self._dispatch_checks = 0
        self._retained_bytes_hashed = 0
        self._source_bytes_hashed = 0
        self._transport_bytes_hashed = 0
        self._transport_checks = 0
        self._transport_wall_seconds = 0.0
        self._full_wall_seconds = 0.0
        self._dispatch_wall_seconds = 0.0
        self._last_boundary = None

    @property
    def manifest(self):
        return copy.deepcopy(self._manifest)

    def metrics(self):
        with self._lock:
            return {"schema": SCHEMA, "manifest_sha256": self._manifest_pin,
                "full_boundary_checks": self._full_checks, "dispatch_checks": self._dispatch_checks,
                "retained_bytes_hashed": self._retained_bytes_hashed,
                "source_bytes_hashed": self._source_bytes_hashed,
                "transport_bytes_hashed": self._transport_bytes_hashed,
                "transport_continuity_checks": self._transport_checks,
                "transport_continuity_wall_seconds": round(self._transport_wall_seconds, 9),
                "full_hash_wall_seconds": round(self._full_wall_seconds, 9),
                "dispatch_wall_seconds": round(self._dispatch_wall_seconds, 9),
                "established": self._snapshots is not None, "closed": self._closed,
                "poisoned": self._poison is not None, "last_full_boundary": self._last_boundary,
                "protection": self._protection, "platform": os.name,
                "write_delete_sharing_denied": self._protection == "windows-read-lease" and bool(self._leases),
                "residual": ("kernel-or-raw-disk-changes-not-prevented" if self._protection == "windows-read-lease"
                             else "same-metadata-content-change-detected-only-at-full-boundary"),
                "metadata_is_cryptographic_proof": False}

    def _refuse(self, reason, phase, path=None):
        error = ArtifactIntegrityError(reason, phase=phase, path=path)
        self._poison = error
        raise error

    def _ready(self, phase, *, initial=False):
        if self._poison is not None:
            raise ArtifactIntegrityError("prior-refusal", phase=phase) from self._poison
        if self._closed:
            self._refuse("closed", phase)
        if digest(self._manifest) != self._manifest_pin:
            self._refuse("selection-drift", phase)
        if (self._gate is not self._frozen_gate or list(self._retained) != self._manifest["retained_artifacts"]
                or list(self._sources) != self._manifest["source_artifacts"]
                or list(self._transport) != self._manifest["transport_artifacts"]
                or self._protection != self._manifest["protection"]
                or self._max_checks != self._manifest["max_dispatch_checks"]):
            self._refuse("guard-configuration-drift", phase)
        if self._snapshots is not None and digest({path: asdict(value) for path, value in self._snapshots.items()}) != self._snapshot_pin:
            self._refuse("retained-snapshot-drift", phase)
        if initial and self._snapshots is not None:
            self._refuse("already-established", phase)
        if not initial and self._snapshots is None:
            self._refuse("not-established", phase)

    def _admit(self, method, path, phase):
        try:
            self._gate(method, "path:" + str(path))
        except Exception as error:
            self._poison = ArtifactIntegrityError("scope-refused", phase=phase, path=str(path))
            raise self._poison from error

    def _snapshot(self, path, phase):
        path = Path(path)
        self._admit("artifact_guard_stat", path, phase)
        try:
            _no_links(path, regular_file=True)
            value = path.lstat()
            if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1
                    or stat.S_ISLNK(value.st_mode)
                    or getattr(value, "st_file_attributes", 0) & 0x400):
                self._refuse("linked-or-nonregular", phase, str(path))
            return _Snapshot.from_stat(value)
        except ArtifactIntegrityError:
            raise
        except (OSError, ValueError) as error:
            self._poison = ArtifactIntegrityError("path-unavailable-or-linked", phase=phase, path=str(path))
            raise self._poison from error

    def _unchanged(self, rows, phase, expected):
        for row in rows:
            path = row["path"]
            if self._snapshot(path, phase) != expected[path]:
                self._refuse("metadata-drift", phase, path)
            if self._protection == "windows-read-lease" and row in self._retained:
                lease = self._leases.get(path)
                try:
                    if lease is None or lease.snapshot() != expected[path]:
                        self._refuse("retained-lease-identity-drift", phase, path)
                except OSError as error:
                    self._poison = ArtifactIntegrityError("retained-lease-closed-or-unavailable", phase=phase, path=path)
                    raise self._poison from error

    def _acquire_leases(self, phase, expected):
        if self._protection != "windows-read-lease":
            return
        try:
            for row in self._retained:
                path = row["path"]
                self._admit("artifact_guard_lease", path, phase)
                lease = _WindowsReadLease(path)
                self._leases[path] = lease
                if lease.snapshot() != expected[path]:
                    self._refuse("retained-lease-identity-drift", phase, path)
        except ArtifactIntegrityError:
            for lease in self._leases.values():
                lease.close()
            self._leases.clear()
            raise
        except (OSError, ValueError) as error:
            for lease in self._leases.values():
                lease.close()
            self._leases.clear()
            self._poison = ArtifactIntegrityError("retained-read-lease-refused", phase=phase, path=path)
            raise self._poison from error

    def _hash(self, row, phase, *, role, expected):
        path = Path(row["path"])
        self._admit("artifact_guard_hash", path, phase)
        before = self._snapshot(path, phase)
        if before != expected[str(path)]:
            self._refuse("metadata-drift", phase, str(path))
        try:
            from contextlib import nullcontext
            retained_lease = self._leases.get(str(path)) if role == "retained" else None
            context = nullcontext(retained_lease.stream) if retained_lease is not None else path.open("rb")
            with context as stream:
                # Bind the opened handle to the exact OS identity inspected by
                # lstat, including the hardlink count. Do not hash a replaced path.
                if _Snapshot.from_stat(os.fstat(stream.fileno())) != before:
                    self._refuse("opened-file-identity-drift", phase, str(path))
                stream.seek(0)
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
                if _Snapshot.from_stat(os.fstat(stream.fileno())) != before:
                    self._refuse("changed-during-hash", phase, str(path))
        except ArtifactIntegrityError:
            raise
        except (OSError, ValueError) as error:
            self._poison = ArtifactIntegrityError("hash-read-unavailable", phase=phase, path=str(path))
            raise self._poison from error
        if role == "retained":
            self._retained_bytes_hashed += before.size
            if row in self._transport:
                self._transport_bytes_hashed += before.size
        else:
            self._source_bytes_hashed += before.size
        if self._snapshot(path, phase) != before:
            self._refuse("changed-during-hash", phase, str(path))
        if actual != row["sha256"]:
            self._refuse("content-hash-mismatch", phase, str(path))

    def _full(self, phase, *, initial):
        self._ready(phase, initial=initial)
        tick = time.monotonic()
        rows = (*self._retained, *self._sources)
        expected = ({row["path"]: self._snapshot(row["path"], phase) for row in rows}
                    if initial else self._snapshots)
        if initial:
            self._acquire_leases(phase, expected)
        self._unchanged(rows, phase, expected)
        for row in self._retained:
            self._hash(row, phase, role="retained", expected=expected)
        for row in self._sources:
            self._hash(row, phase, role="source", expected=expected)
        # A previously checked file can change while a later large file hashes.
        self._unchanged(rows, phase, expected)
        self._snapshots = expected
        self._snapshot_pin = digest({path: asdict(value) for path, value in expected.items()})
        self._full_checks += 1
        self._full_wall_seconds += time.monotonic() - tick
        self._last_boundary = phase
        return {"schema": SCHEMA, "manifest_sha256": self._manifest_pin,
                "check_kind": "full-content-sha256", "phase": phase,
                "boundary_number": self._full_checks, "retained_content_rehashed": True,
                "source_content_rehashed": True, "loaded_model_attested": False,
                "protection": self._protection, "platform": os.name,
                "write_delete_sharing_denied": self._protection == "windows-read-lease",
                "metadata_is_cryptographic_proof": False}

    def establish(self):
        """Initial complete hash pass; a previous attestation cannot be imported."""
        with self._lock:
            return self._full("initial", initial=True)

    def full_boundary(self, phase):
        """Mandatory complete selected hash pass at a caller's explicit boundary."""
        if type(phase) is not str or phase not in BOUNDARIES:
            raise ValueError("An explicit supported full boundary is required")
        with self._lock:
            return self._full(phase, initial=False)

    def verify_dispatch(self):
        """Metadata continuity for retained files, fresh SHA256 for all sources."""
        with self._lock:
            phase = "dispatch"
            self._ready(phase)
            if self._dispatch_checks >= self._max_checks:
                self._refuse("dispatch-check-budget", phase)
            tick = time.monotonic()
            rows = (*self._retained, *self._sources)
            self._unchanged(rows, phase, self._snapshots)
            for row in self._sources:
                self._hash(row, phase, role="source", expected=self._snapshots)
            self._unchanged(rows, phase, self._snapshots)
            self._dispatch_checks += 1
            self._dispatch_wall_seconds += time.monotonic() - tick
            return {"schema": SCHEMA, "manifest_sha256": self._manifest_pin,
                "check_kind": "metadata-continuity-and-source-sha256", "phase": phase,
                "last_full_boundary": self._last_boundary, "boundary_number": self._full_checks,
                "dispatch_number": self._dispatch_checks, "retained_content_rehashed": False,
                "source_content_rehashed": True, "loaded_model_attested": False,
                "protection": self._protection, "platform": os.name,
                "write_delete_sharing_denied": self._protection == "windows-read-lease",
                "metadata_is_cryptographic_proof": False}

    def verify_transport_artifacts(self, rows):
        """Borrow exact retained transport leases, never hash-cache or authority.

        Surrounding epoch dispatches still freshly verify sources. This method
        is Windows-only: metadata-only mode cannot satisfy a transport lease.
        Full boundary scheduling and ownership remain with the enclosing epoch.
        """
        with self._lock:
            phase = "transport-continuity"
            self._ready(phase)
            if self._protection != "windows-read-lease":
                self._refuse("transport-read-lease-required", phase)
            try:
                selected = _selection(rows, role="transport")
            except (TypeError, ValueError) as error:
                self._poison = ArtifactIntegrityError("invalid-transport-selection", phase=phase)
                raise self._poison from error
            if any(row not in self._transport for row in selected):
                self._refuse("unselected-transport-artifact", phase)
            if self._transport_checks >= self._max_checks:
                self._refuse("transport-check-budget", phase)
            tick = time.monotonic()
            self._unchanged(selected, phase, self._snapshots)
            self._unchanged(selected, phase, self._snapshots)
            self._transport_checks += 1
            self._transport_wall_seconds += time.monotonic() - tick
            return {"schema": SCHEMA, "manifest_sha256": self._manifest_pin,
                "check_kind": "held-transport-read-lease-continuity", "phase": phase,
                "artifacts": copy.deepcopy(list(selected)),
                "last_full_boundary": self._last_boundary, "boundary_number": self._full_checks,
                "transport_check_number": self._transport_checks,
                "retained_content_rehashed": False, "source_content_rehashed": False,
                "loaded_model_attested": False, "protection": self._protection,
                "platform": os.name, "write_delete_sharing_denied": True,
                "metadata_is_cryptographic_proof": False}

    def close(self):
        """Release this process-local guard; closing is not a release hash pass."""
        with self._lock:
            self._closed = True
            for lease in self._leases.values():
                lease.close()
            self._leases.clear()
