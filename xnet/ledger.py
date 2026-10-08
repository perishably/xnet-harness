"""Authoritative SQLite event ledger, evidence CAS, memory and finding lifecycle."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .protocol import ZERO_HASH, canonical, digest, sha256, validate_event


class LedgerError(ValueError):
    pass


SECRET_MARKERS = (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), re.compile(rb"(?i)(?:api[_-]?key|authorization|password)\s*[:=]\s*[^\s,;]{8,}"))
FINDING_NEXT = {"draft": {"triaged", "closed"}, "triaged": {"reproduced", "closed"}, "reproduced": {"ready", "closed"}, "ready": {"exported", "closed"}, "exported": {"closed"}, "closed": set()}


class Ledger:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "ledger" / "xnet.sqlite3"
        self.cas_dir = self.data_dir / "cas" / "sha256"
        self._initialize()

    @contextmanager
    def _conn(self):
        db = sqlite3.connect(self.db_path, timeout=20)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.cas_dir.mkdir(parents=True, exist_ok=True)
        with self._conn() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, event_json BLOB NOT NULL, event_hash TEXT NOT NULL, prev_hash TEXT NOT NULL, receipt_hash TEXT NOT NULL, admitted_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence (hash TEXT PRIMARY KEY, size INTEGER NOT NULL, source TEXT NOT NULL, scope_id TEXT NOT NULL, acquired_at INTEGER NOT NULL, metadata_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, evidence_hash TEXT NOT NULL, task_id TEXT NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS contradictions (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, old_json TEXT NOT NULL, new_json TEXT NOT NULL, task_id TEXT NOT NULL, observed_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, title TEXT NOT NULL, state TEXT NOT NULL, evidence_json TEXT NOT NULL, contradictions_json TEXT NOT NULL, reproduction TEXT NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS runs (task_id TEXT PRIMARY KEY, request_hash TEXT, status TEXT NOT NULL, result_json TEXT, started_at INTEGER NOT NULL, ended_at INTEGER);
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(runs)")}
            if "request_hash" not in columns:
                db.execute("ALTER TABLE runs ADD COLUMN request_hash TEXT")

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        validate_event(event)
        raw = canonical(event)
        event_hash = sha256(raw)
        with self._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT seq,event_hash,prev_hash,receipt_hash FROM events WHERE event_id=?", (event["event_id"],)).fetchone()
            if old:
                if old["event_hash"] != event_hash:
                    raise LedgerError("conflicting duplicate event_id")
                return {"seq": old["seq"], "event_hash": old["event_hash"], "prev_hash": old["prev_hash"], "receipt_hash": old["receipt_hash"], "duplicate": True}
            last = db.execute("SELECT seq,receipt_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["receipt_hash"] if last else ZERO_HASH
            seq = int(last["seq"]) + 1 if last else 1
            receipt_hash = digest({"seq": seq, "prev_hash": prev, "event_hash": event_hash})
            db.execute("INSERT INTO events(seq,event_id,event_json,event_hash,prev_hash,receipt_hash,admitted_at) VALUES(?,?,?,?,?,?,?)", (seq, event["event_id"], raw, event_hash, prev, receipt_hash, int(time.time())))
            return {"seq": seq, "event_hash": event_hash, "prev_hash": prev, "receipt_hash": receipt_hash, "duplicate": False}

    def verify_chain(self) -> dict[str, Any]:
        prev = ZERO_HASH
        count = 0
        with self._conn() as db:
            for row in db.execute("SELECT * FROM events ORDER BY seq"):
                count += 1
                if row["seq"] != count or row["prev_hash"] != prev or sha256(row["event_json"]) != row["event_hash"]:
                    raise LedgerError(f"event chain broken at sequence {count}")
                expected = digest({"seq": count, "prev_hash": prev, "event_hash": row["event_hash"]})
                if expected != row["receipt_hash"]:
                    raise LedgerError(f"receipt chain broken at sequence {count}")
                prev = row["receipt_hash"]
        return {"events": count, "head": prev, "intact": True}

    def events(self, task_id: str | None = None) -> list[dict[str, Any]]:
        with self._conn() as db:
            rows = db.execute("SELECT event_json FROM events ORDER BY seq").fetchall()
        parsed = [json.loads(r[0]) for r in rows]
        return [e for e in parsed if e["task_id"] == task_id] if task_id else parsed

    def put_evidence(self, content: bytes, *, source: str, scope_id: str, metadata: dict[str, Any] | None = None) -> str:
        if not isinstance(content, bytes) or len(content) > 32 * 1024 * 1024:
            raise LedgerError("evidence must be bytes of at most 32 MiB")
        if any(p.search(content) for p in SECRET_MARKERS):
            raise LedgerError("evidence appears to contain a secret; redact before import")
        h = sha256(content)
        path = self.cas_dir / h[:2] / h
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if sha256(path.read_bytes()) != h:
                raise LedgerError("CAS object hash conflict")
        else:
            fd, tmp = tempfile.mkstemp(prefix=".xnet-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(content)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        with self._conn() as db:
            db.execute("INSERT OR IGNORE INTO evidence(hash,size,source,scope_id,acquired_at,metadata_json) VALUES(?,?,?,?,?,?)", (h, len(content), source, scope_id, int(time.time()), canonical(metadata or {}).decode("utf-8")))
        return h

    def get_evidence(self, h: str) -> bytes:
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            raise LedgerError("invalid evidence hash")
        data = (self.cas_dir / h[:2] / h).read_bytes()
        if sha256(data) != h:
            raise LedgerError("evidence hash mismatch")
        return data

    def memory_put(self, key: str, value: Any, evidence_hash: str, task_id: str) -> dict[str, Any]:
        if not key or len(key) > 256:
            raise LedgerError("invalid memory key")
        self.get_evidence(evidence_hash)
        value_json = canonical(value).decode("utf-8")
        with self._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT value_json FROM memory WHERE key=?", (key,)).fetchone()
            if old and old["value_json"] != value_json:
                db.execute("INSERT INTO contradictions(key,old_json,new_json,task_id,observed_at) VALUES(?,?,?,?,?)", (key, old["value_json"], value_json, task_id, int(time.time())))
                return {"stored": False, "contradiction": True, "previous": json.loads(old["value_json"])}
            db.execute("INSERT INTO memory(key,value_json,evidence_hash,task_id,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,evidence_hash=excluded.evidence_hash,task_id=excluded.task_id,updated_at=excluded.updated_at", (key, value_json, evidence_hash, task_id, int(time.time())))
            return {"stored": True, "contradiction": False}

    def memory_get(self, key: str) -> dict[str, Any] | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM memory WHERE key=?", (key,)).fetchone()
        return {"key": row["key"], "value": json.loads(row["value_json"]), "evidence_hash": row["evidence_hash"], "task_id": row["task_id"]} if row else None

    def memory_search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._conn() as db:
            rows = db.execute("SELECT key,value_json,evidence_hash FROM memory WHERE key LIKE ? ORDER BY updated_at DESC LIMIT ?", (f"%{query}%", min(max(limit, 1), 100))).fetchall()
        return [{"key": r["key"], "value": json.loads(r["value_json"]), "evidence_hash": r["evidence_hash"]} for r in rows]

    def finding_create(self, *, scope_id: str, title: str, evidence_hashes: list[str], reproduction: str = "", contradictions: list[str] | None = None) -> dict[str, Any]:
        if not title or not evidence_hashes:
            raise LedgerError("finding requires title and evidence")
        for h in evidence_hashes:
            self.get_evidence(h)
        fid = str(uuid.uuid4())
        with self._conn() as db:
            db.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?)", (fid, scope_id, title, "draft", json.dumps(evidence_hashes), json.dumps(contradictions or []), reproduction, int(time.time())))
        return self.finding_get(fid)

    def finding_get(self, finding_id: str) -> dict[str, Any]:
        with self._conn() as db:
            row = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise LedgerError("finding not found")
        return {"id": row["id"], "scope_id": row["scope_id"], "title": row["title"], "state": row["state"], "evidence_hashes": json.loads(row["evidence_json"]), "contradictions": json.loads(row["contradictions_json"]), "reproduction": row["reproduction"], "updated_at": row["updated_at"]}

    def finding_transition(self, finding_id: str, state: str) -> dict[str, Any]:
        old = self.finding_get(finding_id)
        if state not in FINDING_NEXT[old["state"]]:
            raise LedgerError(f"invalid finding transition {old['state']} -> {state}")
        if state in ("reproduced", "ready") and not old["reproduction"]:
            raise LedgerError("reproduction packet is required")
        with self._conn() as db:
            db.execute("UPDATE findings SET state=?,updated_at=? WHERE id=?", (state, int(time.time()), finding_id))
        return self.finding_get(finding_id)

    def report(self, finding_id: str) -> str:
        f = self.finding_get(finding_id)
        lines = [f"# {f['title']}", "", f"Finding ID: `{f['id']}`", f"Scope ID: `{f['scope_id']}`", f"State: `{f['state']}`", "", "## Evidence", ""]
        lines += [f"- SHA-256 `{h}`" for h in f["evidence_hashes"]]
        lines += ["", "## Reproduction packet", "", f["reproduction"] or "Not yet reproduced.", "", "## Contradictions", ""]
        lines += [f"- {x}" for x in f["contradictions"]] or ["- None recorded."]
        lines += ["", "## Submission", "", "Operator review and submission are separate manual steps."]
        return "\n".join(lines) + "\n"

    def run_start(self, task_id: str, request_hash: str) -> dict[str, Any] | None:
        with self._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status,result_json,request_hash FROM runs WHERE task_id=?", (task_id,)).fetchone()
            if row:
                if row["request_hash"] != request_hash:
                    raise LedgerError("task ID replay has different scoped inputs")
                if row["status"] == "completed":
                    return json.loads(row["result_json"])
                raise LedgerError(f"task {task_id} is already {row['status']}")
            db.execute("INSERT INTO runs(task_id,request_hash,status,started_at) VALUES(?,?,?,?)", (task_id, request_hash, "running", int(time.time())))
        return None

    def run_finish(self, task_id: str, status: str, result: dict[str, Any]) -> None:
        if status not in ("completed", "cancelled", "failed", "needs_review"):
            raise LedgerError("invalid run status")
        with self._conn() as db:
            db.execute("UPDATE runs SET status=?,result_json=?,ended_at=? WHERE task_id=? AND status='running'", (status, canonical(result).decode("utf-8"), int(time.time()), task_id))

    def run_status(self, task_id: str) -> str | None:
        with self._conn() as db:
            row = db.execute("SELECT status FROM runs WHERE task_id=?", (task_id,)).fetchone()
        return row["status"] if row else None
