"""Append-only, verifiable raw history for the LFM context relay.

The model sees content IDs, never filesystem paths.  Each append keeps the
original Unicode text and divides it only at UTF-8 character boundaries.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .brains import BrainError, _exclusive_file_lock
from .protocol import ZERO_HASH, canonical, digest, _portable_json


class RelayLogError(ValueError):
    """A cold log or FETCH request failed the relay contract."""


SCHEMA_VERSION = "xnet.relay-log.v1"
CHUNK_MAX_BYTES = 4096
MAX_OWNER_BYTES = 128
MAX_FETCH_IDS = 1024
# Worst-case JSON escaping expands one raw byte to six encoded bytes.
MAX_RECORD_BYTES = 32768
STREAMS = frozenset({"user", "gpt", "qwen", "tool", "log", "operator"})
KINDS = frozenset({"raw", "decision", "open_item", "fact"})
ENTRY_FIELDS = frozenset({
    "schema_version", "seq", "id", "stream", "kind", "owner", "timestamp",
    "text", "previous_sha256", "entry_sha256",
})
_HASH = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^log-[0-9a-f]{64}$")
_MAX_INT = 2**63 - 1


def _no_links(path: Path, *, regular_file: bool = False) -> None:
    """Check the path and ancestors without resolving away a link."""
    for candidate in reversed((path, *path.parents)):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RelayLogError("relay log path is unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise RelayLogError("relay log paths may not contain links or junctions")
        if candidate == path and regular_file:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RelayLogError("relay log file must be a regular file with one link")


def _utf8(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not _portable_json(value):
        raise RelayLogError(f"{field} must be portable Unicode text")
    return value.encode("utf-8")


def _metadata(stream: Any, kind: Any, owner: Any, timestamp: Any) -> None:
    if not isinstance(stream, str) or stream not in STREAMS:
        raise RelayLogError("unsupported relay stream")
    if not isinstance(kind, str) or kind not in KINDS:
        raise RelayLogError("unsupported relay entry kind")
    owner_bytes = _utf8(owner, "owner")
    if len(owner_bytes) > MAX_OWNER_BYTES or any(ord(c) < 32 or ord(c) == 127 for c in owner):
        raise RelayLogError("owner must be at most 128 UTF-8 bytes without control characters")
    if type(timestamp) is not int or not 0 <= timestamp <= _MAX_INT:
        raise RelayLogError("timestamp must be a nonnegative integer in seconds")


def _chunks(text: str) -> Iterator[str]:
    """Yield bounded text, retaining all characters, including whitespace."""
    _utf8(text, "text")
    start = 0
    size = 0
    for offset, char in enumerate(text):
        width = len(char.encode("utf-8"))
        if size + width > CHUNK_MAX_BYTES:
            yield text[start:offset]
            start = offset
            size = 0
        size += width
    yield text[start:]


def _validate(entry: Any, *, seq: int, previous_sha256: str) -> dict[str, Any]:
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        raise RelayLogError("cold log entry fields do not match the schema")
    if entry["schema_version"] != SCHEMA_VERSION:
        raise RelayLogError("unsupported cold log schema")
    if type(entry["seq"]) is not int or not 1 <= entry["seq"] <= _MAX_INT or entry["seq"] != seq:
        raise RelayLogError("cold log sequence is incomplete or out of order")
    _metadata(entry["stream"], entry["kind"], entry["owner"], entry["timestamp"])
    if len(_utf8(entry["text"], "text")) > CHUNK_MAX_BYTES:
        raise RelayLogError("cold log chunk exceeds 4096 UTF-8 bytes")
    if not isinstance(entry["previous_sha256"], str) or not _HASH.fullmatch(entry["previous_sha256"]):
        raise RelayLogError("invalid previous cold log hash")
    if entry["previous_sha256"] != previous_sha256:
        raise RelayLogError("cold log hash chain is broken")
    entry_hash = entry["entry_sha256"]
    if not isinstance(entry_hash, str) or not _HASH.fullmatch(entry_hash):
        raise RelayLogError("invalid cold log entry hash")
    body = {key: value for key, value in entry.items() if key not in {"id", "entry_sha256"}}
    if digest(body) != entry_hash:
        raise RelayLogError("cold log entry hash does not match its content")
    if entry["id"] != "log-" + entry_hash:
        raise RelayLogError("cold log ID does not match its entry hash")
    return entry


class RelayLog:
    """An operator-designated cold log; all retrieval uses immutable IDs.

    Retain ``head_sha256`` from append receipts outside this directory when
    detecting a fully rewritten or truncated history is required.  A hash
    chain alone cannot authenticate its own starting point or latest head.
    """

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.path = self.root / "relay-log.jsonl"
        self.lock_path = self.root / ".relay-log.lock"
        self._check_paths()

    def _check_paths(self) -> None:
        _no_links(self.root)
        if self.root.exists() and not self.root.is_dir():
            raise RelayLogError("relay log root must be a directory")
        _no_links(self.path, regular_file=True)
        _no_links(self.lock_path, regular_file=True)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._check_paths()
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            self._check_paths()
            with _exclusive_file_lock(self.lock_path):
                self._check_paths()
                yield
        except (BrainError, OSError) as exc:
            raise RelayLogError("relay cold log is unavailable") from exc

    @contextmanager
    def _open(self, flags: int) -> Iterator[int]:
        _no_links(self.path, regular_file=True)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RelayLogError("relay log file must be a regular file with one link")
            _no_links(self.path, regular_file=True)
            current = self.path.lstat()
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise RelayLogError("relay log file changed while opening")
            yield fd
        finally:
            os.close(fd)

    def _entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        result: list[dict[str, Any]] = []
        previous = ZERO_HASH
        with self._open(os.O_RDONLY) as fd:
            with os.fdopen(os.dup(fd), "rb") as source:
                while line := source.readline(MAX_RECORD_BYTES + 1):
                    if len(line) > MAX_RECORD_BYTES:
                        raise RelayLogError("cold log record exceeds the encoded byte limit")
                    # Canonical JSON plus one LF is the only accepted encoding.
                    if not line.endswith(b"\n"):
                        raise RelayLogError("cold log ends with an incomplete entry")
                    try:
                        entry = json.loads(line[:-1].decode("utf-8"))
                    except (ValueError, UnicodeError, RecursionError) as exc:
                        raise RelayLogError("cold log contains invalid JSON or UTF-8") from exc
                    _validate(entry, seq=len(result) + 1, previous_sha256=previous)
                    if canonical(entry) + b"\n" != line:
                        raise RelayLogError("cold log entry is not canonical JSON")
                    result.append(entry)
                    previous = entry["entry_sha256"]
        return result

    def entries(self) -> list[dict[str, Any]]:
        """Return the entire log only after verifying its hashes and order."""
        with self._locked():
            return self._entries()

    def append(
        self, stream: str, text: str, *, kind: str = "raw", owner: str = "",
        timestamp: int | None = None,
    ) -> dict[str, Any]:
        """Append all text as contiguous chunks and return a trusted head receipt."""
        timestamp = int(time.time()) if timestamp is None else timestamp
        _metadata(stream, kind, owner, timestamp)
        chunks = list(_chunks(text))
        with self._locked():
            prior = self._entries()
            previous = prior[-1]["entry_sha256"] if prior else ZERO_HASH
            appended: list[dict[str, Any]] = []
            for offset, chunk in enumerate(chunks, start=len(prior) + 1):
                body = {
                    "schema_version": SCHEMA_VERSION,
                    "seq": offset,
                    "stream": stream,
                    "kind": kind,
                    "owner": owner,
                    "timestamp": timestamp,
                    "text": chunk,
                    "previous_sha256": previous,
                }
                entry_hash = digest(body)
                entry = {**body, "id": "log-" + entry_hash, "entry_sha256": entry_hash}
                _validate(entry, seq=offset, previous_sha256=previous)
                appended.append(entry)
                previous = entry_hash
            with self._open(os.O_WRONLY | os.O_CREAT | os.O_APPEND) as fd:
                pending = b"".join(canonical(entry) + b"\n" for entry in appended)
                while pending:
                    count = os.write(fd, pending)
                    if count <= 0:
                        raise RelayLogError("cold log append did not complete")
                    pending = pending[count:]
                os.fsync(fd)
            return {"entries": appended, "head_sha256": previous}

    def fetch(self, ids: Sequence[str], *, max_bytes: int = 65536) -> list[dict[str, Any]]:
        """Return requested raw entries in request order, within a UTF-8 budget."""
        if isinstance(ids, (str, bytes)) or not isinstance(ids, Sequence):
            raise RelayLogError("FETCH requires a sequence of cold log IDs")
        requested = list(ids)
        if len(requested) > MAX_FETCH_IDS:
            raise RelayLogError("FETCH may request at most 1024 cold log IDs")
        if any(not isinstance(item, str) or not _ID.fullmatch(item) for item in requested):
            raise RelayLogError("FETCH accepts only cold log IDs")
        if len(set(requested)) != len(requested):
            raise RelayLogError("FETCH may not repeat a cold log ID")
        if type(max_bytes) is not int or not 0 <= max_bytes <= _MAX_INT:
            raise RelayLogError("FETCH byte budget must be a nonnegative integer")
        with self._locked():
            by_id = {entry["id"]: entry for entry in self._entries()}
            if any(item not in by_id for item in requested):
                raise RelayLogError("FETCH contains an unknown cold log ID")
            selected = [by_id[item] for item in requested]
            if sum(len(entry["text"].encode("utf-8")) for entry in selected) > max_bytes:
                raise RelayLogError("FETCH raw text exceeds the UTF-8 byte budget")
            return selected
