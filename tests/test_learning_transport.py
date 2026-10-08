"""Exact-byte learning transport fixtures; no model process or Kimi mutation."""
from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from adapters.kimi.learning_transport import (BorrowedLearningTransport,
    LearningTransportError, METHOD, PATH, PendingLearningTransport,
    build_repair_messages, transport_source_artifacts)
from xnet.learning_wing import build_proposal_request, seed_failure_feed
from xnet.ledger import Ledger
from xnet.protocol import canonical, digest, sha256
from xnet.repair_loop import _admit_public_context, _public_context_input, pilot_battery
from xnet.scope import ScopeAuthority, ScopeError
from xnet.swe_repair_suite import public_task


def raw_response(*, text='{"files":{"api.py":"fixture only"}}', usage=None, model="fixture-model"):
    return canonical({"id": "recording-fixture", "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 13, "completion_tokens": 5, "total_tokens": 18} if usage is None else usage})


class RecordingTransport:
    def __init__(self):
        self.calls = []
        self.response = raw_response()
        self.error = None
        self.adapter = None
        self.mutate = None

    def send(self, endpoint, path, payload_bytes, timeout_seconds):
        # The adapter must reserve durably before reaching borrowed transport.
        reservations = list((self.adapter.root / "attempts").rglob("reservation.json"))
        if not reservations:
            raise AssertionError("request dispatched before durable reservation")
        self.calls.append((endpoint, path, payload_bytes, timeout_seconds))
        if self.mutate is not None:
            self.mutate.write_bytes(b"changed after provider reply")
        if self.error is not None:
            raise self.error
        return self.response


class LearningTransportControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ledger = Ledger(self.root / "private-ledger")
        self.authority = ScopeAuthority(self.root / "scope-authority")
        self.scope = self.authority.create(program="recording-learning-fixture", policy_url="fixture://local",
            policy_capture=b"local recording fixture", allowed_assets=["127.0.0.1:18777"],
            methods=[METHOD], fixture=True, allow_live_network=True)
        self.recording = RecordingTransport()
        self.source = {"path": str(Path(__file__).absolute()), "sha256": sha256(Path(__file__).read_bytes())}
        tasks, _ = pilot_battery()
        task = public_task(tasks[0])
        self.request = {"nonce": "a" * 32, "model_id": "fixture", "model_sha256": "b" * 64,
                        "task": task, "base_files": copy.deepcopy(task["files"]), "public_feedback": None,
                        "contract": "Return only the requested files JSON; no tools.", "max_output_tokens": 650,
                        "hidden_cases_used": False}
        self.add_context()

    def tearDown(self):
        self.tmp.cleanup()

    def add_context(self):
        text = "Approved public context: inspect état.\nKeep Unicode and exact lines."
        record = {"record_id": "guide-1", "kind": "rag-slice", "text": text,
                  "source_sha256": "c" * 64, "text_sha256": sha256(text.encode()), "receipt_sha256": "d" * 64}
        policy = {"schema": "xnet.repair-public-context-policy.v1", "preparer_id": "fixture-context",
                  "preparer_artifacts": [copy.deepcopy(self.source)], "max_bytes": 2048, "model_ids": ["fixture"],
                  "tasks": {self.request["task"]["task_id"]: [{key: value for key, value in record.items() if key != "text"} | {"classification": "public"}]}}
        packet = {"schema": "xnet.repair-public-context.v1", "task_id": self.request["task"]["task_id"],
                  "input_sha256": _public_context_input(self.request), "records": [record], "authority": "none",
                  "work_performed": False, "hidden_cases_used": False, "context_only": True}
        self.request["public_context"] = _admit_public_context(packet, self.request, policy)
        self.request["learning_public_context_policy"] = policy

    def adapter(self, *, name="transport", **changes):
        args = {"base_url": "http://127.0.0.1:18777", "served_model": "fixture-model", "model_id": "fixture",
                "model_sha256": "b" * 64, "scope_authority": self.authority, "scope_id": self.scope["scope_id"],
                "callback_artifacts": [self.source], "transport": self.recording.send}
        result = BorrowedLearningTransport(self.ledger, self.root / name, **(args | changes))
        self.recording.adapter = result
        return result

    def test_exact_transmitted_context_private_bytes_usage_and_completed_reopen(self):
        adapter = self.adapter()
        before = copy.deepcopy(self.request)
        result = adapter.generate(self.request)
        self.assertEqual(self.request, before)
        self.assertEqual(result["usage"]["input_tokens"], 13)
        self.assertEqual(result["usage"]["output_tokens"], 5)
        self.assertEqual(result["model_sha256"], "b" * 64)
        endpoint, path, actual_bytes, timeout = self.recording.calls[0]
        payload = json.loads(actual_bytes)
        self.assertEqual(endpoint, "http://127.0.0.1:18777")
        self.assertEqual(path, PATH)
        self.assertEqual(timeout, 120)
        self.assertEqual(actual_bytes, canonical(payload))
        text = self.request["public_context"]["records"][0]["text"]
        self.assertEqual([row["content"] for row in payload["messages"]].count(text), 1)
        self.assertEqual([payload["messages"][0], payload["messages"][-1]], build_repair_messages(self.request))
        receipt = adapter.evidence(self.request["nonce"])
        reservation = receipt["reservation"]
        self.assertEqual(reservation["payload_sha256"], sha256(actual_bytes))
        self.assertEqual(reservation["message_evidence"]["messages_sha256"], digest(payload["messages"]))
        self.assertEqual(self.ledger.get_evidence(reservation["payload_sha256"]), actual_bytes)
        self.assertEqual(self.ledger.get_evidence(receipt["completed"]["response_raw_sha256"]), self.recording.response)
        self.assertFalse(receipt["completed"]["artifact_identity_authenticated"])
        with self.ledger._conn() as db:
            rows = db.execute("SELECT metadata_json FROM evidence WHERE source LIKE 'learning-transport-%'").fetchall()
        for row in rows:
            metadata = json.loads(row[0])
            self.assertEqual(metadata["visibility"], "private")
            self.assertFalse(metadata["cloud_export"])
        self.assertEqual(self.adapter().generate(self.request), result)
        self.assertEqual(len(self.recording.calls), 1)
        self.assertEqual(len(transport_source_artifacts()), 12)

    def test_pending_refuses_rerun_and_audited_reconcile_preserves_exact_result(self):
        adapter = self.adapter()
        self.recording.error = ConnectionResetError("unknown provider outcome")
        with self.assertRaises(ConnectionResetError):
            adapter.generate(self.request)
        self.recording.error = None
        with self.assertRaises(PendingLearningTransport) as pending:
            self.adapter().generate(self.request)
        self.assertEqual(pending.exception.nonce, self.request["nonce"])
        self.assertEqual(len(self.recording.calls), 1)
        pin = self.ledger.put_evidence(self.recording.response, source="confirmed-fixture-response",
            scope_id=self.scope["scope_id"], metadata={"visibility": "private"})
        args = {"evidence_sha256": pin, "justification": "Confirmed fixture reply belongs to this reserved exact request"}
        result = adapter.reconcile(self.request["nonce"], self.recording.response, **args)
        self.assertEqual(adapter.generate(self.request), result)
        self.assertEqual(adapter.reconcile(self.request["nonce"], self.recording.response, **args), result)
        self.assertEqual(len(self.recording.calls), 1)
        events = self.ledger.events("learning-transport-" + self.request["nonce"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "learning-transport-reconciled")
        conflicting = raw_response(text="different")
        conflicting_pin = self.ledger.put_evidence(conflicting, source="conflict", scope_id=self.scope["scope_id"])
        with self.assertRaisesRegex(LearningTransportError, "cannot be replaced"):
            adapter.reconcile(self.request["nonce"], conflicting,
                evidence_sha256=conflicting_pin, justification=args["justification"])

    def test_nonce_request_mutation_and_false_reconcile_evidence_are_refused(self):
        adapter = self.adapter()
        self.recording.error = TimeoutError()
        with self.assertRaises(TimeoutError):
            adapter.generate(self.request)
        changed = self.request | {"contract": "A changed contract"}
        with self.assertRaisesRegex(LearningTransportError, "different exact request"):
            adapter.generate(changed)
        with self.assertRaisesRegex(LearningTransportError, "confirmed raw evidence"):
            adapter.reconcile(self.request["nonce"], self.recording.response,
                evidence_sha256="f" * 64, justification="Confirmed old response")
        self.assertEqual(len(self.recording.calls), 1)

    def test_malformed_or_dishonest_responses_preserved_without_redispatch(self):
        candidates = [b'{"model":"fixture-model","model":"fixture-model"}',
                      raw_response(model="different-model"),
                      raw_response(usage={"prompt_tokens": 13}),
                      raw_response(usage={"prompt_tokens": 13, "input_tokens": 14, "completion_tokens": 5}),
                      raw_response(usage={"prompt_tokens": 13, "completion_tokens": 651}),
                      raw_response(usage={"prompt_tokens": True, "completion_tokens": 5})]
        for i, response in enumerate(candidates):
            with self.subTest(i=i):
                self.recording.response = response
                adapter = self.adapter(name="bad-" + str(i))
                for _ in range(2):
                    with self.assertRaises(ValueError):
                        adapter.generate(self.request)
                self.assertEqual((adapter.root / "attempts" / self.request["nonce"] / "response.raw").read_bytes(), response)
        self.assertEqual(len(self.recording.calls), len(candidates))

    def test_source_drift_after_reply_retains_response_and_recovers_without_dispatch(self):
        marker = self.root / "caller-source.fixture"
        marker.write_bytes(b"selected caller source")
        row = {"path": str(marker.absolute()), "sha256": sha256(marker.read_bytes())}
        adapter = self.adapter(callback_artifacts=[self.source, row])
        self.recording.mutate = marker
        with self.assertRaisesRegex(LearningTransportError, "source drift"):
            adapter.generate(self.request)
        self.assertEqual((adapter.root / "attempts" / self.request["nonce"] / "response.raw").read_bytes(), self.recording.response)
        marker.write_bytes(b"selected caller source")
        self.recording.mutate = None
        self.assertEqual(adapter.generate(self.request)["usage"]["output_tokens"], 5)
        self.assertEqual(len(self.recording.calls), 1)

    def test_endpoint_scope_expiry_wrong_port_and_unsigned_callback_refused(self):
        credential_endpoint = "http://" + "u:p" + "@127.0.0.1:18777"
        for endpoint in ("http://localhost:18777", "https://127.0.0.1:18777", "http://192.0.2.1:18777",
                         "http://127.0.0.1:18777/unapproved", credential_endpoint):
            with self.subTest(endpoint=endpoint), self.assertRaises(LearningTransportError):
                self.adapter(base_url=endpoint)
        with self.assertRaisesRegex(LearningTransportError, "source must be selected"):
            self.adapter(callback_artifacts=[])
        adapter = self.adapter()
        with patch("xnet.scope.time.time", return_value=self.scope["expires_at"] + 1), self.assertRaises(ScopeError):
            adapter.generate(self.request)
        wrong = self.adapter(name="wrong-port", base_url="http://127.0.0.1:18778")
        with self.assertRaises(ScopeError):
            wrong.generate(self.request)
        self.assertFalse((adapter.root / "attempts").exists())
        self.assertEqual(self.recording.calls, [])

    def test_proposal_transmits_fixed_failure_feed_and_replays_completed_bytes(self):
        request = build_proposal_request(seed_failure_feed()) | {"model_id": "fixture", "model_sha256": "b" * 64,
                                                               "reservation_id": "proposal-1"}
        self.recording.response = raw_response(text='{"scaffold_id":"candidate","steps":["inspect-contract"]}')
        adapter = self.adapter()
        output = adapter.propose(request)
        self.assertEqual(set(output), {"text", "usage"})
        payload = json.loads(self.recording.calls[0][2])
        self.assertEqual(payload["max_tokens"], 200)
        self.assertEqual(payload["messages"][1]["content"], request["prompt"])
        self.assertIn(canonical(request["failure_feed"]).decode(), payload["messages"][1]["content"])
        self.assertEqual(adapter.propose(request), output)
        self.assertEqual(len(self.recording.calls), 1)
        with self.assertRaisesRegex(LearningTransportError, "fixed public failure feed"):
            adapter.propose(request | {"reservation_id": "proposal-2", "prompt": "fabricated context"})

    def test_real_loopback_fixture_gets_exact_body_and_http_rejection_is_retained(self):
        bodies, status = [], [200]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                bodies.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
                raw = raw_response() if status[0] == 200 else canonical({"error": "fixture rejection"})
                self.send_response(status[0])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            from adapters.kimi.learning_transport import loopback_chat_transport
            port = server.server_address[1]
            scoped = self.authority.create(program="HTTP-learning-fixture", policy_url="fixture://local", policy_capture=b"local",
                allowed_assets=["127.0.0.1:" + str(port)], methods=[METHOD], fixture=True, allow_live_network=True)
            adapter = self.adapter(name="http", base_url="http://127.0.0.1:" + str(port),
                                   scope_id=scoped["scope_id"], transport=loopback_chat_transport)
            adapter.generate(self.request)
            evidence = adapter.evidence(self.request["nonce"])
            self.assertEqual(bodies[0][0], PATH)
            self.assertEqual(sha256(bodies[0][1]), evidence["reservation"]["payload_sha256"])
            text = self.request["public_context"]["records"][0]["text"]
            self.assertIn(text, [m["content"] for m in json.loads(bodies[0][1])["messages"]])
            status[0] = 503
            rejected_request = self.request | {"nonce": "rejected-http"}
            with self.assertRaisesRegex(LearningTransportError, "HTTP status"):
                adapter.generate(rejected_request)
            self.assertEqual((adapter.root / "attempts" / "rejected-http" / "response.raw").read_bytes(), canonical({"error": "fixture rejection"}))
            with self.assertRaisesRegex(LearningTransportError, "rejected by HTTP status"):
                adapter.generate(rejected_request)
            self.assertEqual(len(bodies), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
