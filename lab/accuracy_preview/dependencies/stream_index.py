"""Bounded metadata intake, advisory vicinity proposals and verified hot slices.

No model, network, shell, cloud writer, answer, grader or promotion interface.
The lexical ranking and exact UTF-8/CRLF chunk partition follow the existing
XNET RagCatalog pure slicing primitives; see inventory.json for source pins.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import time
from typing import Callable, Mapping

SCHEMA = "xnet.metadata-source.v1"
ZERO = "0" * 64
HASH = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[A-Za-z0-9_.:@/-]{1,192}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_]{2,64}")
SECRET = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i:authorization\s*:\s*bearer)|\bgh[pousr]_[A-Za-z0-9]{24,}\b|(?i:(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)[\"']?\s*[:=]\s*[\"']?[^\s\",;]{8,})")
FIELDS = frozenset({"schema", "scope_id", "task_id", "source_id", "adapter", "relative_path", "repo", "revision", "source_sha256", "source_bytes", "language", "task_family", "tags", "provenance", "upstream_receipt_sha256"})
BLOCKED_PARTS = frozenset({".ssh", ".env", "credentials", "secrets", "private_selftest", "evaluator-only", "protected-dataset"})


class IndexErrorClosed(ValueError):
    """Policy, identity, bounds or provenance failed closed."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha256(canonical(value))


def strict_json(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            if key in out:
                raise IndexErrorClosed("duplicate JSON key")
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(IndexErrorClosed("nonfinite JSON")))
    except (ValueError, UnicodeError) as exc:
        raise IndexErrorClosed("invalid JSON") from exc


def _integer(value, low, high, field):
    if type(value) is not int or not low <= value <= high:
        raise IndexErrorClosed(f"invalid {field}")
    return value


def _pin(value):
    if type(value) is not str or not HASH.fullmatch(value):
        raise IndexErrorClosed("full lowercase SHA256 required")
    return value


def _label(value):
    if type(value) is not str or not LABEL.fullmatch(value):
        raise IndexErrorClosed("bounded label required")
    return value


def _unlinked(path):
    for component in (Path(path), *Path(path).parents):
        if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
            raise IndexErrorClosed("linked paths are refused")
    return Path(path)


def _relative(value):
    if type(value) is not str or not 1 <= len(value) <= 256 or "\\" in value or ":" in value:
        raise IndexErrorClosed("relative POSIX locator required")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise IndexErrorClosed("escaping or ambiguous locator")
    if any(part.lower() in BLOCKED_PARTS for part in path.parts) or path.suffix.lower() in {".key", ".pem", ".pfx", ".p12", ".kdbx", ".parquet"}:
        raise IndexErrorClosed("private or protected source locator")
    return value


@dataclass(frozen=True)
class Limits:
    max_sources: int = 512
    max_events: int = 4096
    max_source_bytes: int = 262144
    chunk_bytes: int = 1024
    max_chunks: int = 512
    hot_bytes: int = 16384
    hot_items: int = 32
    hot_ttl_seconds: int = 300
    max_cas_bytes: int = 8 * 1024 * 1024

    def checked(self):
        for name, low, high in (("max_sources", 1, 4096), ("max_events", 4, 16384), ("max_source_bytes", 128, 1024 * 1024), ("chunk_bytes", 64, 4096), ("max_chunks", 1, 4096), ("hot_bytes", 64, 1024 * 1024), ("hot_items", 1, 256), ("hot_ttl_seconds", 1, 86400), ("max_cas_bytes", 128, 64 * 1024 * 1024)):
            _integer(getattr(self, name), low, high, name)
        if self.chunk_bytes > self.hot_bytes:
            raise IndexErrorClosed("chunk cannot fit hot window")
        return self


class ReadOnlyMount:
    """Explicit local mount only. A synced file is not remote-cloud proof.

    Roots may point to C:, D:, Proton or Google local mirrors. No enumeration,
    repair, upload, credentials or network operations occur here.
    """
    def __init__(self, root, *, tier="hot"):
        if tier not in {"hot", "warm", "cold", "ghost"}:
            raise IndexErrorClosed("unknown tier")
        self.root = _unlinked(Path(root)).resolve()
        self.tier = tier

    def health(self):
        return {"local_root_present": self.root.is_dir(), "tier": self.tier, "read_only": True, "remote_readiness": "unknown"}

    def read(self, relative_path, *, maximum):
        target = _unlinked(self.root / _relative(relative_path))
        try:
            target.resolve(strict=True).relative_to(self.root)
        except (ValueError, OSError) as exc:
            raise IndexErrorClosed("source absent or outside configured mount") from exc
        if not target.is_file() or target.stat().st_size > maximum:
            raise IndexErrorClosed("source is not a bounded regular file")
        with target.open("rb") as file:
            raw = file.read(maximum + 1)
        if len(raw) > maximum:
            raise IndexErrorClosed("source grew beyond bound")
        return raw


def source_descriptor(*, scope_id, task_id, source_id, adapter, relative_path, repo, revision, source_sha256, source_bytes, language, task_family, tags=(), provenance="workspace-source", upstream_receipt_sha256):
    return {"schema": SCHEMA, "scope_id": scope_id, "task_id": task_id, "source_id": source_id, "adapter": adapter, "relative_path": relative_path, "repo": repo, "revision": revision, "source_sha256": source_sha256, "source_bytes": source_bytes, "language": language, "task_family": task_family, "tags": sorted(set(tags)), "provenance": provenance, "upstream_receipt_sha256": upstream_receipt_sha256}


def source_byte_chunks(raw, maximum=1024):
    """Existing RagCatalog partition convention: exact bytes, UTF-8, CRLF."""
    raw.decode("utf-8")
    chunks, start = [], 0
    while start < len(raw):
        end = min(start + maximum, len(raw))
        while end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        if end < len(raw) and raw[end - 1:end + 1] == b"\r\n":
            end -= 1
        newline = raw.rfind(b"\n", start, end) + 1
        if newline >= start + maximum // 2:
            end = newline
        if end <= start:
            raise IndexErrorClosed("chunk boundary made no progress")
        piece = raw[start:end]
        chunks.append({"ordinal": len(chunks), "start_byte": start, "end_byte": end, "chunk_sha256": sha256(piece), "start_line": raw[:start].count(b"\n") + 1, "end_line": raw[:end].count(b"\n") + (0 if raw[end - 1:end] == b"\n" else 1), "complete_start_line": start == 0 or raw[start - 1:start] == b"\n", "complete_end_line": end == len(raw) or raw[end - 1:end] == b"\n", "complete_source": start == 0 and end == len(raw), "text": piece.decode("utf-8")})
        start = end
    return chunks


def _tokens(text):
    return [word.casefold() for word in TOKEN.findall(text)]


def rank_documents(texts, query):
    """RagCatalog BM25 constants k1=1.2,b=.75; stable input-order ties."""
    terms = sorted(set(_tokens(query)))
    docs = [_tokens(text) for text in texts]
    frequency = {term: sum(term in set(tokens) for tokens in docs) for term in terms}
    average = sum(map(len, docs)) / max(1, len(docs))
    scores = []
    for tokens in docs:
        score = 0.0
        for term in terms:
            count = tokens.count(term)
            if count:
                inverse = math.log1p((len(docs) - frequency[term] + .5) / (frequency[term] + .5))
                denominator = count + 1.2 * (.25 + .75 * len(tokens) / max(average, 1))
                score += inverse * count * 2.2 / denominator
        scores.append(round(score, 12))
    return scores


class MetadataIndex:
    """One owner per root; metadata is advisory, fetched bytes are evidence.

    ``expected_head`` is an optional external trusted checkpoint. Hashes detect
    edits relative to that checkpoint; they do not authenticate the producer.
    Evaluation accepts only same-scope/task evaluation-source descriptors.
    """
    def __init__(self, root, *, adapters: Mapping[str, ReadOnlyMount], scope_id, task_id, mode="practice", limits=Limits(), clock=time.time, expected_head=None):
        self.limits = limits.checked()
        self.scope_id, self.task_id = _label(scope_id), _label(task_id)
        if mode not in {"practice", "evaluation"} or not callable(clock):
            raise IndexErrorClosed("explicit mode and clock required")
        if not isinstance(adapters, Mapping) or not 1 <= len(adapters) <= 8 or any(not isinstance(value, ReadOnlyMount) for value in adapters.values()):
            raise IndexErrorClosed("1..8 explicit read-only mounts required")
        self.adapters = {_label(key): value for key, value in adapters.items()}
        self.root = _unlinked(Path(root))
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve()
        self.clock, self.mode = clock, mode
        self._closed = False
        self._lease = self.root / "owner.lease"
        _unlinked(self._lease)
        try:
            with self._lease.open("xb") as file:
                self._owner = canonical({"pid": os.getpid(), "nonce": os.urandom(16).hex()})
                file.write(self._owner)
        except FileExistsError as exc:
            raise IndexErrorClosed("another owner or unfinished lease; explicit recovery required") from exc
        self._records, self._current, self._hot, self._issued = {}, {}, OrderedDict(), OrderedDict()
        self._events, self._head, self._cas_bytes, self._cas_pins = [], ZERO, 0, set()
        self._journal = self.root / "events.jsonl"
        self._config = {"schema": "xnet.metadata-index.v1", "scope_id": scope_id, "task_id": task_id, "mode": mode, "limits": asdict(limits), "adapters": {name: {"root": str(value.root), "tier": value.tier} for name, value in sorted(self.adapters.items())}}
        try:
            config = self.root / "config.json"
            _unlinked(config)
            _unlinked(self._journal)
            if config.exists():
                if config.read_bytes() != canonical(self._config) or not self._journal.exists():
                    raise IndexErrorClosed("state configuration differs or journal missing")
            else:
                if self._journal.exists():
                    raise IndexErrorClosed("journal without configuration")
                self._write_new(config, canonical(self._config))
                self._write_new(self._journal, b"")
            self._replay()
            if expected_head is not None and _pin(expected_head) != self._head:
                raise IndexErrorClosed("trusted ledger checkpoint differs")
            self._signature = self._journal.stat().st_mtime_ns, self._journal.stat().st_size
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _write_new(path, raw):
        _unlinked(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())

    def _now(self):
        value = self.clock()
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            raise IndexErrorClosed("invalid clock")
        return int(value)

    def _check(self):
        _unlinked(self._lease)
        if self._closed or not self._lease.is_file() or self._lease.stat().st_size > 1024 or self._lease.read_bytes() != self._owner:
            raise IndexErrorClosed("index owner unavailable")
        _unlinked(self._journal)
        config = _unlinked(self.root / "config.json")
        if not config.is_file() or config.stat().st_size > 8192 or config.read_bytes() != canonical(self._config):
            raise IndexErrorClosed("state configuration changed outside this owner")
        if (self._journal.stat().st_mtime_ns, self._journal.stat().st_size) != self._signature:
            raise IndexErrorClosed("journal changed outside this owner")

    def _descriptor(self, row):
        if type(row) is not dict or set(row) != FIELDS or row["schema"] != SCHEMA:
            raise IndexErrorClosed("closed metadata source schema required")
        for field in ("scope_id", "task_id", "source_id", "adapter", "repo", "revision", "language", "task_family"):
            _label(row[field])
        if row["scope_id"] != self.scope_id or row["task_id"] != self.task_id or row["adapter"] not in self.adapters:
            raise IndexErrorClosed("source task/scope/mount differs")
        _relative(row["relative_path"])
        _pin(row["source_sha256"])
        _pin(row["upstream_receipt_sha256"])
        _integer(row["source_bytes"], 1, self.limits.max_source_bytes, "source_bytes")
        if type(row["tags"]) is not list or len(row["tags"]) > 16 or any(type(tag) is not str for tag in row["tags"]) or row["tags"] != sorted(set(row["tags"])):
            raise IndexErrorClosed("bounded unique sorted tags required")
        for tag in row["tags"]:
            _label(tag)
        if row["provenance"] not in {"practice-stream", "workspace-source", "evaluation-source"}:
            raise IndexErrorClosed("unknown provenance")
        if self.mode == "evaluation" and row["provenance"] != "evaluation-source":
            raise IndexErrorClosed("practice streams and workspace lessons excluded from evaluation")
        if self.mode == "practice" and row["provenance"] == "evaluation-source":
            raise IndexErrorClosed("evaluation sources cannot enter practice history")
        if SECRET.search(canonical(row)):
            raise IndexErrorClosed("metadata appears to contain credentials")
        return strict_json(canonical(row))

    def _replay(self):
        if self._journal.stat().st_size > self.limits.max_events * 8192:
            raise IndexErrorClosed("journal bound exceeded")
        raw = self._journal.read_bytes()
        if raw and not raw.endswith(b"\n"):
            raise IndexErrorClosed("unfinished journal append requires recovery")
        for line in raw.splitlines():
            event = strict_json(line)
            if type(event) is not dict or set(event) != {"sequence", "previous_sha256", "time", "kind", "payload", "event_sha256"}:
                raise IndexErrorClosed("invalid journal schema")
            body = {key: value for key, value in event.items() if key != "event_sha256"}
            if event["sequence"] != len(self._events) + 1 or event["previous_sha256"] != self._head or digest(body) != event["event_sha256"]:
                raise IndexErrorClosed("journal hash chain differs")
            _integer(event["time"], 0, 2**63 - 1, "time")
            if event["kind"] == "intake":
                row = self._descriptor(event["payload"])
                pin = digest(row)
                if pin in self._records or len(self._records) >= self.limits.max_sources:
                    raise IndexErrorClosed("duplicate or overflowing intake journal")
                self._records[pin] = row
                self._current[(row["repo"], row["source_id"])] = pin
            elif event["kind"] == "fetch":
                payload = event["payload"]
                if type(payload) is not dict or set(payload) != {"metadata_sha256", "source_sha256", "source_bytes", "cas_added_bytes", "slice_count", "hot_bytes"} or payload["metadata_sha256"] not in self._records:
                    raise IndexErrorClosed("invalid fetch receipt")
                row = self._records[payload["metadata_sha256"]]
                if payload["source_sha256"] != row["source_sha256"] or payload["source_bytes"] != row["source_bytes"]:
                    raise IndexErrorClosed("fetch provenance differs")
                for key in ("cas_added_bytes", "slice_count", "hot_bytes"):
                    _integer(payload[key], 0, self.limits.max_cas_bytes, key)
                self._cas_bytes += payload["cas_added_bytes"]
                self._cas_pins.add(payload["source_sha256"])
                if self._cas_bytes > self.limits.max_cas_bytes:
                    raise IndexErrorClosed("CAS receipt budget differs")
            elif event["kind"] != "checkpoint":
                raise IndexErrorClosed("unknown journal kind")
            self._events.append(event)
            self._head = event["event_sha256"]
            if len(self._events) > self.limits.max_events:
                raise IndexErrorClosed("event count bound exceeded")

    def _append(self, kind, payload):
        self._check()
        if len(self._events) >= self.limits.max_events:
            raise IndexErrorClosed("ledger segment full; archive checkpoint and use a new root")
        body = {"sequence": len(self._events) + 1, "previous_sha256": self._head, "time": self._now(), "kind": kind, "payload": payload}
        event = {**body, "event_sha256": digest(body)}
        raw = canonical(event) + b"\n"
        if len(raw) > 8192:
            raise IndexErrorClosed("event exceeds byte bound")
        with self._journal.open("ab") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        self._events.append(event)
        self._head = event["event_sha256"]
        self._signature = self._journal.stat().st_mtime_ns, self._journal.stat().st_size
        return event

    def ingest(self, descriptor, *, expected_metadata_sha256):
        self._check()
        row = self._descriptor(descriptor)
        pin = digest(row)
        if pin != _pin(expected_metadata_sha256):
            raise IndexErrorClosed("metadata differs from upstream pinned projection")
        if pin in self._records:
            return {"status": "duplicate", "metadata_sha256": pin, "index_sha256": self.index_pin()}
        if len(self._records) >= self.limits.max_sources:
            raise IndexErrorClosed("source metadata capacity exhausted")
        self._append("intake", row)
        key = row["repo"], row["source_id"]
        old = self._current.get(key)
        self._records[pin], self._current[key] = row, pin
        if old:
            for hot_key in list(self._hot):
                if hot_key[0] == old:
                    del self._hot[hot_key]
        self._issued.clear()
        return {"status": "indexed-metadata-only", "metadata_sha256": pin, "index_sha256": self.index_pin(), "source_read_bytes": 0}

    def step(self, rows, *, max_records=16):
        _integer(max_records, 1, 64, "max_records")
        if type(rows) is not list or len(rows) > max_records:
            raise IndexErrorClosed("bounded explicit metadata row batch required")
        return [self.ingest(row, expected_metadata_sha256=digest(row)) for row in rows]

    def index_pin(self):
        self._check()
        return digest({"config_sha256": digest(self._config), "current": sorted(self._current.items()), "records": sorted(self._records)})

    def query(self, query_text, *, repo, revision, task_family=None, limit=3):
        self._check()
        _label(repo), _label(revision)
        _integer(limit, 1, 8, "query limit")
        if type(query_text) is not str or not 1 <= len(query_text.encode("utf-8")) <= 512 or SECRET.search(query_text.encode("utf-8")):
            raise IndexErrorClosed("bounded non-secret trigger required")
        if task_family is not None:
            _label(task_family)
        rows = [(pin, self._records[pin]) for key, pin in sorted(self._current.items()) if key[0] == repo and self._records[pin]["revision"] == revision]
        texts = [" ".join([row["relative_path"], row["language"], row["task_family"], *row["tags"]]) for _, row in rows]
        scored = []
        for (pin, row), score in zip(rows, rank_documents(texts, query_text)):
            family_match = task_family is not None and task_family == row["task_family"]
            score += 2.0 if family_match else 0.0
            if score > 0:
                scored.append({"metadata_sha256": pin, "source_sha256": row["source_sha256"], "source_id": row["source_id"], "relative_path": row["relative_path"], "revision": row["revision"], "provenance": row["provenance"], "score": round(score, 12), "family_match": family_match, "qr_locator": "xnet://sha256/" + row["source_sha256"], "advisory_only": True, "authority": "source-data-only"})
        return sorted(scored, key=lambda row: (-row["score"], row["source_id"], row["metadata_sha256"]))[:limit]

    def propose_prefetch(self, trigger, *, repo, revision, task_family=None, limit=3):
        _integer(limit, 1, 3, "proposal source limit")
        rows = self.query(trigger, repo=repo, revision=revision, task_family=task_family, limit=limit)
        body = {"schema": "xnet.metadata-prefetch.v1", "scope_id": self.scope_id, "task_id": self.task_id, "index_sha256": self.index_pin(), "trigger": trigger, "repo": repo, "revision": revision, "task_family": task_family, "created_at": self._now(), "expires_at": self._now() + self.limits.hot_ttl_seconds, "rows": rows, "advisory_only": True}
        proposal = {**body, "proposal_sha256": digest(body)}
        self._issued[proposal["proposal_sha256"]] = canonical(proposal)
        while len(self._issued) > 16:
            self._issued.popitem(last=False)
        return proposal

    def _expire(self):
        now = self._now()
        for key in list(self._hot):
            if self._hot[key]["expires_at"] <= now:
                del self._hot[key]

    def _source(self, pin):
        row = self._records[pin]
        object_path = _unlinked(self.root / "cas" / row["source_sha256"][:2] / row["source_sha256"])
        added = 0
        if object_path.exists():
            if row["source_sha256"] not in self._cas_pins:
                raise IndexErrorClosed("unreceipted CAS write requires explicit recovery")
            if not object_path.is_file() or object_path.stat().st_size > self.limits.max_source_bytes:
                raise IndexErrorClosed("CAS source is not a bounded file")
            raw = object_path.read_bytes()
        else:
            raw = self.adapters[row["adapter"]].read(row["relative_path"], maximum=self.limits.max_source_bytes)
            added = len(raw)
        if len(raw) != row["source_bytes"] or sha256(raw) != row["source_sha256"]:
            raise IndexErrorClosed("source bytes or digest differ")
        try:
            raw.decode("utf-8")
        except UnicodeError as exc:
            raise IndexErrorClosed("source is not UTF-8") from exc
        if SECRET.search(raw):
            raise IndexErrorClosed("source appears to contain credentials")
        if added:
            if self._cas_bytes + added > self.limits.max_cas_bytes:
                raise IndexErrorClosed("immutable source CAS budget exhausted")
            chunks = source_byte_chunks(raw, self.limits.chunk_bytes)
            if len(chunks) > self.limits.max_chunks:
                raise IndexErrorClosed("source exceeds chunk capacity")
            self._write_new(object_path, raw)
        return raw, added

    def prefetch(self, proposal, *, cancelled: Callable[[], bool], max_chunks_per_source=3):
        self._check()
        _integer(max_chunks_per_source, 1, 8, "prefetch chunks")
        if type(proposal) is not dict or self._issued.get(proposal.get("proposal_sha256")) != canonical(proposal):
            raise IndexErrorClosed("proposal was not issued by this index owner")
        if proposal["index_sha256"] != self.index_pin() or proposal["expires_at"] <= self._now():
            raise IndexErrorClosed("stale prefetch proposal")
        if not callable(cancelled):
            raise IndexErrorClosed("explicit cancellation callback required")
        def stopped():
            value = cancelled()
            self._check()
            if type(value) is not bool:
                raise IndexErrorClosed("cancellation must return bool")
            return value
        result = []
        self._expire()
        if len(self._events) + len(proposal["rows"]) > self.limits.max_events:
            raise IndexErrorClosed("insufficient receipt capacity; no source fetch dispatched")
        for selected in proposal["rows"]:
            if stopped():
                result.append({"metadata_sha256": selected["metadata_sha256"], "status": "cancelled"})
                continue
            pin = selected["metadata_sha256"]
            raw, added = self._source(pin)
            if stopped():
                # A completed immutable read may remain in CAS, but no hot data
                # is exposed after cancellation. Account the durable write.
                self._cas_bytes += added
                receipt = self._append("fetch", {"metadata_sha256": pin, "source_sha256": sha256(raw), "source_bytes": len(raw), "cas_added_bytes": added, "slice_count": 0, "hot_bytes": self.hot_bytes()})
                self._cas_pins.add(sha256(raw))
                result.append({"metadata_sha256": pin, "status": "cancelled", "receipt_sha256": receipt["event_sha256"]})
                continue
            if proposal["index_sha256"] != self.index_pin() or proposal["expires_at"] <= self._now():
                raise IndexErrorClosed("proposal changed during fetch")
            chunks = source_byte_chunks(raw, self.limits.chunk_bytes)
            if len(chunks) > self.limits.max_chunks:
                raise IndexErrorClosed("source exceeds chunk capacity")
            scores = rank_documents([chunk["text"] for chunk in chunks], proposal["trigger"])
            ranked = sorted(zip(chunks, scores), key=lambda pair: (-pair[1], pair[0]["ordinal"]))[:max_chunks_per_source]
            staged_hot = OrderedDict(self._hot)
            staged_bytes = lambda: sum(len(value["text"].encode("utf-8")) for value in staged_hot.values())
            for chunk, score in ranked:
                key = pin, chunk["ordinal"]
                entry = {**chunk, "metadata_sha256": pin, "source_sha256": sha256(raw), "source_bytes": len(raw), "complete": chunk["complete_start_line"] and chunk["complete_end_line"], "revision": self._records[pin]["revision"], "source_id": self._records[pin]["source_id"], "relative_path": self._records[pin]["relative_path"], "expires_at": min(proposal["expires_at"], self._now() + self.limits.hot_ttl_seconds), "score": score, "authority": "source-data-only", "scope_id": self.scope_id, "task_id": self.task_id, "provenance": self._records[pin]["provenance"]}
                staged_hot.pop(key, None)
                while staged_hot and (staged_bytes() + len(chunk["text"].encode("utf-8")) > self.limits.hot_bytes or len(staged_hot) >= self.limits.hot_items):
                    staged_hot.popitem(last=False)
                staged_hot[key] = entry
            receipt = self._append("fetch", {"metadata_sha256": pin, "source_sha256": sha256(raw), "source_bytes": len(raw), "cas_added_bytes": added, "slice_count": len(ranked), "hot_bytes": staged_bytes()})
            self._cas_bytes += added
            self._cas_pins.add(sha256(raw))
            self._hot = staged_hot
            result.append({"metadata_sha256": pin, "status": "prefetched", "source_sha256": sha256(raw), "slice_count": len(ranked), "receipt_sha256": receipt["event_sha256"]})
        return result

    def hot_bytes(self):
        return sum(len(row["text"].encode("utf-8")) for row in self._hot.values())

    def fetch_verified_source(self, metadata_sha256, *, expected_source_sha256, require_current=True):
        """Read an already receipted immutable CAS source; never a cold mount.

        Used when a reviewer needs detail beyond a hot slice. This explicit
        full-source read is separately bounded, not automatic prompt packing.
        """
        self._check()
        pin = _pin(metadata_sha256)
        source_pin = _pin(expected_source_sha256)
        if type(require_current) is not bool or pin not in self._records:
            raise IndexErrorClosed("known metadata pin and explicit current policy required")
        row = self._records[pin]
        if row["source_sha256"] != source_pin or source_pin not in self._cas_pins:
            raise IndexErrorClosed("source is not the exact receipted CAS object")
        if require_current and self._current.get((row["repo"], row["source_id"])) != pin:
            raise IndexErrorClosed("source revision was superseded")
        path = _unlinked(self.root / "cas" / source_pin[:2] / source_pin)
        if not path.is_file() or path.stat().st_size > self.limits.max_source_bytes:
            raise IndexErrorClosed("CAS source absent or beyond bound")
        raw = path.read_bytes()
        if len(raw) != row["source_bytes"] or sha256(raw) != source_pin:
            raise IndexErrorClosed("immutable source CAS digest differs")
        return {"metadata_sha256": pin, "source_sha256": source_pin, "source_bytes": len(raw), "revision": row["revision"], "text": raw.decode("utf-8"), "authority": "source-data-only", "remote_reads": 0}

    def source_slices(self, query_text, *, repo, revision, task_family=None, budget_bytes=4096, max_items=4):
        """Only the hot window is read on the prompt path; misses are explicit."""
        allowed = {row["metadata_sha256"] for row in self.query(query_text, repo=repo, revision=revision, task_family=task_family, limit=8)}
        _integer(budget_bytes, 64, self.limits.hot_bytes, "slice byte budget")
        _integer(max_items, 1, 16, "slice item budget")
        self._expire()
        rows = [row for key, row in self._hot.items() if key[0] in allowed and self._current.get((repo, row["source_id"])) == key[0]]
        scores = rank_documents([row["text"] for row in rows], query_text)
        ranked = sorted(zip(rows, scores), key=lambda pair: (-pair[1], pair[0]["source_id"], pair[0]["start_byte"]))
        aliases = {}
        for row, _ in ranked:
            key = row["source_sha256"], row["start_byte"], row["end_byte"]
            aliases.setdefault(key, []).append({"metadata_sha256": row["metadata_sha256"], "source_id": row["source_id"], "relative_path": row["relative_path"], "revision": row["revision"]})
        output, used, seen = [], 0, set()
        for row, score in ranked:
            key = row["source_sha256"], row["start_byte"], row["end_byte"]
            if key in seen:
                continue
            size = len(row["text"].encode("utf-8"))
            if size + used > budget_bytes:
                continue
            if sha256(row["text"].encode("utf-8")) != row["chunk_sha256"]:
                raise IndexErrorClosed("hot slice digest differs")
            output.append({**row, "score": score, "source_aliases": aliases[key]})
            seen.add(key)
            used += size
            if len(output) >= max_items:
                break
        return {"status": "hot-hit" if output else "hot-miss", "index_sha256": self.index_pin(), "rows": output, "used_source_bytes": used, "budget_source_bytes": budget_bytes, "remote_reads": 0, "generated_facts": False, "accuracy_review_required": True}

    def checkpoint(self, payload=None):
        if payload is not None and (len(canonical(payload)) > 4096 or SECRET.search(canonical(payload))):
            raise IndexErrorClosed("checkpoint metadata bound exceeded")
        return self._append("checkpoint", {"index_sha256": self.index_pin(), "source_count": len(self._records), "hot_items": len(self._hot), "hot_bytes": self.hot_bytes(), "metadata": payload})

    def status(self):
        self._check()
        self._expire()
        return {"schema": "xnet.metadata-status.v1", "mode": self.mode, "scope_id": self.scope_id, "task_id": self.task_id, "index_sha256": self.index_pin(), "ledger_head_sha256": self._head, "events": len(self._events), "source_count": len(self._records), "current_sources": len(self._current), "hot_items": len(self._hot), "hot_bytes": self.hot_bytes(), "cas_receipted_bytes": self._cas_bytes, "adapters": {alias: value.health() for alias, value in self.adapters.items()}, "prediction_authority": "advisory", "learning_promotion": "not-provided", "accuracy_review_required": True}

    def close(self):
        if not self._closed:
            try:
                if self._lease.exists() and self._lease.read_bytes() == self._owner:
                    self._lease.unlink()
            finally:
                self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
