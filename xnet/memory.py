"""Seven-layer, rebuildable memory projection over the authoritative ledger/CAS."""
from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any

from .ledger import Ledger
from .protocol import canonical, digest


class MemoryError(ValueError):
    pass


class MemoryStore:
    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self._initialize()

    def _initialize(self):
        with self.ledger._conn() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS claims (claim_id TEXT NOT NULL, revision INTEGER NOT NULL, task_id TEXT NOT NULL, scope_id TEXT NOT NULL, statement TEXT NOT NULL, evidence_json TEXT NOT NULL, author TEXT NOT NULL, confidence REAL NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(claim_id,revision));
            CREATE TABLE IF NOT EXISTS entities (entity_id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL, properties_json TEXT NOT NULL, evidence_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS typed_edges (edge_id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL, relation TEXT NOT NULL, evidence_hash TEXT NOT NULL, FOREIGN KEY(from_id) REFERENCES entities(entity_id), FOREIGN KEY(to_id) REFERENCES entities(entity_id));
            CREATE TABLE IF NOT EXISTS operations (key TEXT NOT NULL, revision INTEGER NOT NULL, value_json TEXT NOT NULL, task_id TEXT NOT NULL, evidence_hash TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(key,revision));
            CREATE TABLE IF NOT EXISTS strategies (task_id TEXT NOT NULL, revision INTEGER NOT NULL, scope_id TEXT NOT NULL, goal TEXT NOT NULL, decision TEXT NOT NULL, expected_evidence_json TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(task_id,revision));
            """)
            try:
                db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS semantic_fts USING fts5(kind, ref, text)")
            except Exception:
                pass  # Search falls back to direct SQL if SQLite lacks FTS5.

    def claim_add(self, *, task_id: str, scope_id: str, statement: str, evidence_hashes: list[str], author: str, confidence: float, status: str = "proposed", claim_id: str | None = None) -> dict[str, Any]:
        if not statement or not evidence_hashes or not author or not 0.0 <= confidence <= 1.0 or status not in ("proposed", "supported", "contradicted", "withdrawn"):
            raise MemoryError("invalid evidence-linked claim")
        for h in evidence_hashes:
            self.ledger.get_evidence(h)
        claim_id = claim_id or str(uuid.uuid4())
        with self.ledger._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT revision,statement FROM claims WHERE claim_id=? ORDER BY revision DESC LIMIT 1", (claim_id,)).fetchone()
            revision = int(old["revision"]) + 1 if old else 1
            if old and old["statement"] != statement:
                db.execute("INSERT INTO contradictions(key,old_json,new_json,task_id,observed_at) VALUES(?,?,?,?,?)", (f"claim:{claim_id}", json.dumps(old["statement"]), json.dumps(statement), task_id, int(time.time())))
            db.execute("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?,?)", (claim_id, revision, task_id, scope_id, statement, canonical(evidence_hashes).decode("utf-8"), author, confidence, status, int(time.time())))
        return {"claim_id": claim_id, "revision": revision, "status": status, "evidence_hashes": evidence_hashes}

    def entity_add(self, *, kind: str, label: str, properties: dict[str, Any], evidence_hash: str) -> str:
        self.ledger.get_evidence(evidence_hash)
        if not kind or not label or not isinstance(properties, dict):
            raise MemoryError("invalid entity")
        entity_id = str(uuid.uuid4())
        with self.ledger._conn() as db:
            db.execute("INSERT INTO entities VALUES(?,?,?,?,?)", (entity_id, kind, label, canonical(properties).decode("utf-8"), evidence_hash))
        return entity_id

    def edge_add(self, from_id: str, to_id: str, relation: str, evidence_hash: str) -> str:
        self.ledger.get_evidence(evidence_hash)
        if not relation or from_id == to_id:
            raise MemoryError("invalid typed edge")
        edge_id = str(uuid.uuid4())
        with self.ledger._conn() as db:
            db.execute("INSERT INTO typed_edges VALUES(?,?,?,?,?)", (edge_id, from_id, to_id, relation, evidence_hash))
        return edge_id

    def operation_set(self, key: str, value: Any, task_id: str, evidence_hash: str) -> int:
        self.ledger.get_evidence(evidence_hash)
        if not key or len(key) > 128:
            raise MemoryError("invalid operation key")
        with self.ledger._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT MAX(revision) FROM operations WHERE key=?", (key,)).fetchone()[0]
            revision = (old or 0) + 1
            db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)", (key, revision, canonical(value).decode("utf-8"), task_id, evidence_hash, int(time.time())))
        return revision

    def strategy_add(self, task_id: str, scope_id: str, goal: str, decision: str, expected_evidence_hashes: list[str]) -> int:
        if not goal or not decision:
            raise MemoryError("strategy requires a goal and decision")
        for h in expected_evidence_hashes:
            self.ledger.get_evidence(h)
        with self.ledger._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT MAX(revision) FROM strategies WHERE task_id=?", (task_id,)).fetchone()[0]
            revision = (old or 0) + 1
            db.execute("INSERT INTO strategies VALUES(?,?,?,?,?,?,?)", (task_id, revision, scope_id, goal, decision, canonical(expected_evidence_hashes).decode("utf-8"), int(time.time())))
        return revision

    def rebuild_index(self) -> dict[str, Any]:
        with self.ledger._conn() as db:
            try:
                db.execute("DELETE FROM semantic_fts")
            except Exception:
                return {"index": "fallback-like", "rows": 0}
            count = 0
            for row in db.execute("SELECT key,value_json FROM memory"):
                db.execute("INSERT INTO semantic_fts VALUES(?,?,?)", ("memory", row["key"], f"{row['key']} {row['value_json']}"))
                count += 1
            for row in db.execute("SELECT claim_id,revision,statement FROM claims"):
                db.execute("INSERT INTO semantic_fts VALUES(?,?,?)", ("claim", f"{row['claim_id']}:{row['revision']}", row["statement"]))
                count += 1
            for row in db.execute("SELECT entity_id,kind,label FROM entities"):
                db.execute("INSERT INTO semantic_fts VALUES(?,?,?)", ("entity", row["entity_id"], f"{row['kind']} {row['label']}"))
                count += 1
        return {"index": "fts5", "rows": count}

    def semantic_search(self, query: str, limit: int = 20) -> list[dict[str, str]]:
        if not query or len(query) > 256:
            raise MemoryError("invalid search query")
        limit = max(1, min(limit, 100))
        with self.ledger._conn() as db:
            try:
                safe = '"' + query.replace('"', '""') + '"'
                rows = db.execute("SELECT kind,ref,text FROM semantic_fts WHERE semantic_fts MATCH ? LIMIT ?", (safe, limit)).fetchall()
                return [dict(row) for row in rows]
            except Exception:
                rows = db.execute("SELECT 'claim' kind,claim_id ref,statement text FROM claims WHERE statement LIKE ? LIMIT ?", (f"%{query}%", limit)).fetchall()
                return [dict(row) for row in rows]

    def context_pack(self, task_id: str, query: str = "", max_tokens: int = 2048) -> dict[str, Any]:
        if not 128 <= max_tokens <= 32768:
            raise MemoryError("context pack token budget must be 128..32768")
        candidates: list[dict[str, Any]] = []
        for event in self.ledger.events(task_id)[-12:]:
            candidates.append({"reason": "recent_task_event", "value": {"kind": event["kind"], "event_id": event["event_id"], "payload_sha256": event["payload_sha256"]}})
        with self.ledger._conn() as db:
            for row in db.execute("SELECT claim_id,revision,statement,evidence_json,status FROM claims WHERE task_id=? ORDER BY created_at DESC,revision DESC LIMIT 12", (task_id,)):
                candidates.append({"reason": "task_claim", "value": {"id": row["claim_id"], "revision": row["revision"], "statement": row["statement"], "evidence_hashes": json.loads(row["evidence_json"]), "status": row["status"]}})
            for row in db.execute("SELECT key,old_json,new_json FROM contradictions WHERE task_id=? ORDER BY id DESC LIMIT 12", (task_id,)):
                candidates.append({"reason": "contradiction", "value": dict(row)})
            for row in db.execute("SELECT goal,decision,expected_evidence_json FROM strategies WHERE task_id=? ORDER BY revision DESC LIMIT 4", (task_id,)):
                candidates.append({"reason": "strategy_revision", "value": {"goal": row["goal"], "decision": row["decision"], "expected_evidence_hashes": json.loads(row["expected_evidence_json"])}})
        if query:
            for result in self.semantic_search(query, limit=8):
                candidates.append({"reason": "semantic_match", "value": result})
        selected = []
        used = 0
        for item in candidates:
            cost = max(1, (len(canonical(item)) + 3) // 4)
            if used + cost <= max_tokens:
                selected.append(item)
                used += cost
        return {"task_id": task_id, "query": query, "max_tokens": max_tokens, "estimated_tokens": used, "selected": selected, "omitted": len(candidates) - len(selected), "pack_hash": digest(selected)}
