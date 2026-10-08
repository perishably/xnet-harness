"""Source bridge controls with an in-memory gateway, zero native/model calls."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from adapters.bridge.peer import (BridgeError, BridgeImporter, BridgePolicy, BridgeValidationError,
                                 MAX_BUNDLE, validate_bridge_export)
from xnet.protocol import canonical, digest, sha256
from xnet_sdk import Client, XnetError


def bundle(texts=("public café 🧬\r\n", "second public note"), *, snapshot="a" * 64):
    value = {"schema": "xnet.bridge.export.v1", "task_id": "public-task", "producer_id": "producer-1",
             "session_id": "session-1", "origin": {"hemisphere": "wsl", "system": "openclaw",
                                                      "agent_id": "agent-1", "authenticated": False},
             "source": {"id": "capture-1", "sha256": snapshot, "bytes": 123}, "records": [],
             "context_only": True, "work_performed": False, "authority": "none", "importer_model_calls": 0}
    for index, text in enumerate(texts):
        identity = {"schema": "xnet.bridge.occurrence-id.v1", "task_id": value["task_id"],
                    "producer_id": value["producer_id"], "session_id": value["session_id"],
                    "message_id": f"m{index}", "block_index": 0}
        value["records"].append({"event_id": digest(identity), "message_id": f"m{index}", "block_index": 0,
                                 "role": "assistant", "kind": "note", "text": text,
                                 "text_sha256": sha256(text.encode()), "tool_use_id": None, "is_error": None})
    return value


def seal(value):
    body = {key: item for key, item in value.items() if key != "export_sha256"}
    return canonical({**body, "export_sha256": digest(body)})


def policy(value, raw):
    return BridgePolicy(task_id="public-task", admission_peer="peer", producer_id="producer-1",
                        source_id="capture-1", source_sha256=value["source"]["sha256"],
                        source_bytes=value["source"]["bytes"], raw_bundle_sha256=sha256(raw))


class FakeGateway:
    def __init__(self):
        self.events = {}
        self.objects = {}
        self.calls = []
        self.fail_on_id = None
        self.failure_after_commit = False
        self.pending = None
        self.corrupt_reply = False
        self.on_append = None

    def call(self, op, **fields):
        self.calls.append((op, copy.deepcopy(fields)))
        task = fields.get("task_id")
        rows = self.events.setdefault(task, []) if task is not None else []
        head = rows[-1]["event_digest"] if rows else None
        if op == "context_state":
            return {"task_id": task, "history_count": len(rows), "history_head": head, "pending": self.pending}
        if op == "context_history":
            end = fields["after"] + fields["limit"]
            return {"task_id": task, "history_count": len(rows), "history_head": head,
                    "events": copy.deepcopy(rows[fields["after"]:end]), "next_after": end if end < len(rows) else None}
        if op == "verify":
            count = sum(len(events) for events in self.events.values()) * 2
            return {"ok": True, "receipt_count": count, "head": digest({"global": count}) if count else None,
                    "external_checkpoint_verified": False}
        if op == "fetch":
            return {"digest": fields["digest"], "text": self.objects[fields["digest"]]}
        if op != "context_append":
            raise AssertionError(f"unexpected gateway operation: {op}")
        if self.on_append:
            self.on_append()
        event_id = fields["event_id"]
        fail = event_id == self.fail_on_id
        if fail and not self.failure_after_commit:
            raise ConnectionError("fixture dropped before commit")
        source = sha256(fields["text"].encode())
        for event in rows:
            if event["event_id"] == event_id:
                if (event["source_digest"] != source or event["peer"] != fields["peer"]
                        or event["kind"] != fields["kind"]):
                    raise XnetError("context_event_id_conflict")
                return {"event": copy.deepcopy(event), "history_head": head, "duplicate": True}
        if self.pending is not None:
            raise XnetError("context_handoff_pending")
        if fields["expected_head"] != head:
            raise XnetError("context_head_mismatch")
        event = {"seq": len(rows), "event_id": event_id, "peer": fields["peer"], "kind": fields["kind"],
                 "source_digest": source, "event_digest": digest({"prior": head, "id": event_id, "source": source})}
        rows.append(event)
        self.objects[source] = fields["text"]
        if fail:
            self.fail_on_id = None
            raise ConnectionError("fixture lost committed acknowledgement")
        if self.corrupt_reply:
            self.corrupt_reply = False
            return {"event": copy.deepcopy(event), "history_head": "f" * 64, "duplicate": False}
        return {"event": copy.deepcopy(event), "history_head": event["event_digest"], "duplicate": False}

    def append_calls(self):
        return [fields for op, fields in self.calls if op == "context_append"]


class BridgeAdapterTests(unittest.TestCase):
    def importer(self, gateway, root, value, raw=None):
        raw = seal(value) if raw is None else raw
        return BridgeImporter(gateway, Path(root).absolute(), policy=policy(value, raw), simulated=True), raw

    def test_exact_sources_origin_nested_digest_and_task_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = FakeGateway()
            value = bundle()
            adapter, raw = self.importer(gateway, tmp, value)
            result = adapter.ingest(raw)
            self.assertEqual(result["receipt"]["status"], "complete")
            self.assertFalse(result["receipt"]["external_checkpoint_verified"])
            self.assertTrue(result["receipt"]["simulation"])
            calls = gateway.append_calls()
            self.assertEqual(len(calls), 3)
            self.assertIsNone(calls[0]["expected_head"])
            self.assertEqual(calls[1]["expected_head"], gateway.events["public-task"][0]["event_digest"])
            for supplied, admitted in zip(value["records"], result["receipt"]["outcomes"][1:]):
                self.assertEqual(admitted["event"]["event_digest"], gateway.events["public-task"][admitted["event"]["seq"]]["event_digest"])
                source = json.loads(gateway.objects[admitted["source_digest"]])
                self.assertEqual(source["text"], supplied["text"])
                self.assertEqual(source["origin"], value["origin"])
                self.assertNotIn("source", source)
                self.assertEqual(source["source_id"], "capture-1")
                self.assertEqual(admitted["event"]["kind"], "raw")
                self.assertEqual(source["authority"], "none")

    def test_mixed_invalid_rows_prevalidate_before_first_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            value["records"][1]["text_sha256"] = "0" * 64
            adapter, raw = self.importer(gateway, tmp, value)
            gateway.on_append = lambda: self.assertTrue((Path(tmp) / "quarantine" / "row-0001.json").is_file())
            result = adapter.ingest(raw)
            self.assertEqual(result["receipt"]["status"], "partial-complete")
            self.assertEqual(len(gateway.append_calls()), 2)
            quarantined = [row for row in result["receipt"]["outcomes"] if row["status"] == "quarantined"]
            self.assertEqual(quarantined[0]["index"], 1)

    def test_authority_policy_and_raw_pin_errors_write_no_native_calls(self):
        for mutate in (lambda v: v.update(authority="execute"), lambda v: v.update(task_id="other"),
                       lambda v: v.update(declared_peer="assistant"), lambda v: v["origin"].update(authenticated=True)):
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory() as tmp:
                value = bundle(); mutate(value)
                gateway = FakeGateway()
                adapter, raw = self.importer(gateway, tmp, value)
                result = adapter.ingest(raw)
                self.assertEqual(result["receipt"]["status"], "rejected-bundle")
                self.assertEqual(gateway.calls, [])
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            adapter, raw = self.importer(gateway, tmp, value)
            self.assertEqual(adapter.ingest(raw + b" ")["receipt"]["status"], "rejected-bundle")
            self.assertEqual(gateway.calls, [])

    def test_duplicate_keys_depth_huge_integer_and_byte_bounds_are_normalized(self):
        value = bundle()
        for raw in (b'{"a":1,"a":2}', b'[' * 9 + b'0' + b']' * 9,
                    b'{"x":' + b'9' * 5000 + b'}', b' ' * (MAX_BUNDLE + 1), b'\xef\xbb\xbf{}'):
            with self.subTest(size=len(raw)), self.assertRaises(BridgeValidationError):
                validate_bridge_export(raw, policy=policy(value, raw))

    def test_duplicate_ids_and_escaped_text_are_quarantined_without_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            value = bundle(("valid", "\x00" * 16000))
            value["records"].append(copy.deepcopy(value["records"][0]))
            gateway = FakeGateway()
            adapter, raw = self.importer(gateway, tmp, value)
            result = adapter.ingest(raw)
            rejected = [row for row in result["receipt"]["outcomes"] if row["status"] == "quarantined"]
            self.assertEqual({row["reason"] for row in rejected}, {"native-envelope-or-frame-bound", "row-occurrence-id-or-duplicate"})
            self.assertEqual(len(gateway.append_calls()), 2)

    def test_exact_replay_after_other_task_write_retains_original_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            adapter, raw = self.importer(gateway, tmp, value)
            original = adapter.ingest(raw)
            before = len(gateway.append_calls())
            gateway.call("context_append", task_id="other-task", peer="operator", event_id="other-note", kind="raw",
                         text="unrelated public note", expected_head=None)
            replay = adapter.ingest(raw)
            self.assertTrue(replay["request_replayed"])
            self.assertEqual(replay["receipt"], original["receipt"])
            self.assertEqual(replay["completion"], original["completion"])
            self.assertEqual(len(gateway.append_calls()), before + 1)
            self.assertNotEqual(replay["current_verification"]["audit"]["head"], replay["receipt"]["audit"]["head"])

    def test_changed_capture_snapshot_replays_same_occurrences(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            first, raw = self.importer(gateway, Path(tmp) / "one", value)
            original = first.ingest(raw)
            changed = bundle(snapshot="b" * 64)
            second, new_raw = self.importer(gateway, Path(tmp) / "two", changed)
            result = second.ingest(new_raw)
            self.assertEqual([row["status"] for row in result["receipt"]["outcomes"]], ["admitted", "replayed", "replayed"])
            self.assertEqual(len(gateway.events["public-task"]), 4)
            self.assertEqual(result["receipt"]["outcomes"][1]["source_digest"], original["receipt"]["outcomes"][1]["source_digest"])

    def test_changed_text_under_same_identity_is_a_source_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle(("old text",))
            first, raw = self.importer(gateway, Path(tmp) / "one", value)
            original = first.ingest(raw)
            original_source = gateway.objects[original["receipt"]["outcomes"][1]["source_digest"]]
            changed = bundle(("new text",))
            second, raw = self.importer(gateway, Path(tmp) / "two", changed)
            result = second.ingest(raw)
            self.assertEqual(result["receipt"]["outcomes"][1]["status"], "refused")
            retained = gateway.objects[original["receipt"]["outcomes"][1]["source_digest"]]
            self.assertEqual(retained, original_source)
            self.assertEqual(json.loads(retained)["text"], "old text")
            self.assertEqual(len(gateway.events["public-task"]), 3)

    def test_lost_ack_blocks_repeat_then_explicit_reconciliation_finishes(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            gateway.fail_on_id = value["records"][0]["event_id"]
            gateway.failure_after_commit = True
            adapter, raw = self.importer(gateway, tmp, value)
            first = adapter.ingest(raw)
            self.assertEqual(first["receipt"]["status"], "pending-reconciliation")
            before = len(gateway.append_calls())
            self.assertEqual(adapter.ingest(raw)["receipt"]["status"], "pending-reconciliation")
            self.assertEqual(len(gateway.append_calls()), before)
            result = adapter.reconcile(sha256(raw))
            self.assertEqual(result["receipt"]["status"], "complete")
            self.assertEqual(result["receipt"]["outcomes"][1]["status"], "reconciled")
            self.assertEqual(len(gateway.append_calls()), before + 1)

    def test_uncommitted_uncertain_call_is_not_blindly_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            gateway.fail_on_id = value["records"][0]["event_id"]
            adapter, raw = self.importer(gateway, tmp, value)
            adapter.ingest(raw)
            before = len(gateway.append_calls())
            self.assertEqual(adapter.reconcile(sha256(raw))["receipt"]["status"], "pending-reconciliation")
            self.assertEqual(len(gateway.append_calls()), before)

    def test_pending_handoff_and_bad_ack_have_explicit_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            gateway.pending = {"plan_id": "f" * 64}
            adapter, raw = self.importer(gateway, tmp, value)
            result = adapter.ingest(raw)
            self.assertEqual(result["receipt"]["status"], "partial-complete")
            self.assertTrue(all(row["status"] == "refused" for row in result["receipt"]["outcomes"]))
            self.assertEqual(gateway.append_calls(), [])
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            gateway.corrupt_reply = True
            adapter, raw = self.importer(gateway, tmp, value)
            self.assertEqual(adapter.ingest(raw)["receipt"]["status"], "pending-reconciliation")
            self.assertEqual(adapter.reconcile(sha256(raw))["receipt"]["status"], "complete")

    def test_immutable_journal_tampering_and_missing_storage_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            adapter, raw = self.importer(gateway, tmp, value)
            adapter.ingest(raw)
            outcome = Path(tmp) / "rows" / "0000" / "outcome.json"
            parsed = json.loads(outcome.read_text())
            parsed["source_digest"] = "0" * 64
            outcome.write_text(json.dumps(parsed))
            before = len(gateway.append_calls())
            with self.assertRaises(BridgeError):
                adapter.ingest(raw)
            self.assertEqual(len(gateway.append_calls()), before)
        with tempfile.TemporaryDirectory() as tmp:
            gateway, value = FakeGateway(), bundle()
            adapter, raw = self.importer(gateway, Path(tmp) / "journal", value)
            (Path(tmp) / "journal" / "controller.json").unlink()
            with self.assertRaises((BridgeError, OSError)):
                adapter.ingest(raw)
            self.assertEqual(gateway.calls, [])

    def test_binary_hardlink_is_allowed_but_journal_hardlink_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / "source-binary"
            binary.write_bytes(b"synthetic binary identity only; never executed")
            selected = base / "selected-binary"
            os.link(binary, selected)
            gateway = object.__new__(Client)
            gateway.root = base / "gateway-root"
            gateway.root.mkdir()
            gateway.binary = selected
            gateway.binary_sha256 = sha256(selected.read_bytes())
            value = bundle()
            raw = seal(value)
            adapter = BridgeImporter(gateway, base / "journal", policy=policy(value, raw))
            self.assertEqual(adapter.gateway_identity["binary_sha256"], gateway.binary_sha256)
            self.assertFalse(adapter.simulated)
            self.assertGreater(selected.stat().st_nlink, 1)
            os.link(base / "journal" / "controller.json", base / "journal-copy")
            with self.assertRaises(ValueError):
                adapter._check()


if __name__ == "__main__":
    unittest.main()
