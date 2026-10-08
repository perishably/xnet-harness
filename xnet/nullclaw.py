"""Audited local cancellation, source containment, and staging quarantine."""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path

from .ledger import Ledger
from .protocol import digest, make_event, sha256


class NullClawError(PermissionError):
    pass


class NullClaw:
    def __init__(self, data_dir: Path, ledger: Ledger):
        self.data_dir = Path(data_dir)
        self.ledger = ledger
        self.cancel_dir = self.data_dir / "cancel"
        self.contain_file = self.data_dir / "contained_sources.json"
        self.staging = self.data_dir / "staging"
        self.quarantine_dir = self.data_dir / "quarantine"

    def _audit(self, task_id: str, kind: str, payload: dict) -> dict:
        return self.ledger.append(make_event(task_id, "local-defensive", kind, payload, source="nullclaw"))

    def cancel(self, task_id: str, reason: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", task_id) or not reason:
            raise NullClawError("invalid task or reason")
        self.cancel_dir.mkdir(parents=True, exist_ok=True)
        record = {"task_id": task_id, "reason": reason, "time_utc": int(time.time())}
        path = self.cancel_dir / f"{task_id}.json"
        requested = self._audit(task_id, "nullclaw.cancel.requested", {"reason": reason})
        path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        record["audit_receipt"] = self._audit(task_id, "nullclaw.cancel.applied", {"reason": reason})
        record["request_receipt"] = requested
        return record

    def is_cancelled(self, task_id: str) -> bool:
        return (self.cancel_dir / f"{task_id}.json").is_file()

    def contain_source(self, source: str, reason: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", source) or not reason:
            raise NullClawError("invalid source or reason")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        records = json.loads(self.contain_file.read_text(encoding="utf-8")) if self.contain_file.exists() else {}
        records[source] = {"reason": reason, "time_utc": int(time.time())}
        requested = self._audit(f"contain-{source}", "nullclaw.contain.requested", {"source": source, "reason": reason})
        tmp = self.contain_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.contain_file)
        return {"source": source, "request_receipt": requested, "audit_receipt": self._audit(f"contain-{source}", "nullclaw.contain.applied", {"source": source, "reason": reason})}

    def is_contained(self, source: str) -> bool:
        if not self.contain_file.exists():
            return False
        return source in json.loads(self.contain_file.read_text(encoding="utf-8"))

    def quarantine(self, path: Path, reason: str) -> dict:
        path = Path(path)
        root = self.staging.resolve(strict=False)
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise NullClawError("only XNET staging files can be quarantined") from exc
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()) or not resolved.is_file():
            raise NullClawError("quarantine requires a regular staging file")
        if resolved.stat().st_size > 32 * 1024 * 1024:
            raise NullClawError("quarantine file exceeds 32 MiB")
        h = sha256(resolved.read_bytes())
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = self.quarantine_dir / f"{h}.{time.time_ns()}"
        requested = self._audit(f"quarantine-{h[:16]}", "nullclaw.quarantine.requested", {"hash": h, "reason": reason, "source": str(resolved)})
        os.replace(resolved, dest)
        receipt = self._audit(f"quarantine-{h[:16]}", "nullclaw.quarantine.applied", {"hash": h, "reason": reason, "destination": str(dest)})
        return {"hash": h, "destination": str(dest), "request_receipt": requested, "audit_receipt": receipt}

    def ingest_worker_response(self, response: dict) -> dict:
        """Verify a Zig fixed-task receipt and record it as an admitted local result."""
        expected_fields = {"error", "op", "path", "policy_version", "receipt_sha256", "result", "scope_id", "status", "task_id", "time_utc", "v"}
        if not isinstance(response, dict) or set(response) != expected_fields or response["v"] != 1:
            raise NullClawError("invalid worker response shape")
        if response["op"] not in ("stat", "hash", "scan", "archive_inventory") or response["status"] not in ("ok", "error"):
            raise NullClawError("invalid worker operation or status")
        unsigned = {k: v for k, v in response.items() if k != "receipt_sha256"}
        if digest(unsigned) != response["receipt_sha256"]:
            raise NullClawError("worker receipt hash mismatch")
        if response["status"] == "ok":
            try:
                Path(response["path"]).resolve(strict=True).relative_to(self.data_dir.resolve(strict=True))
            except (OSError, ValueError) as exc:
                raise NullClawError("worker result path escapes local XNET") from exc
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"nullclaw-worker:{response['receipt_sha256']}"))
        event = make_event(response["task_id"], response["scope_id"], "nullclaw.worker_result", {"op": response["op"], "status": response["status"], "worker_receipt_sha256": response["receipt_sha256"], "result": response["result"]}, source="nullclaw", event_id=event_id)
        return self.ledger.append(event)
