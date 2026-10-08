"""Meaningful codec, source provenance and scoped real-CAS controls; no models."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xnet.hce_capsule_v1 import (HceCapsuleStore, HceError, INDEX_SCHEMA,
    MAX_SOURCE_BYTES, decode_capsule, encode_capsule, render_face)
from xnet.ledger import Ledger
from xnet.protocol import canonical, make_event, sha256
from xnet.repair_loop import _admit_public_context, _public_context_input
from xnet.scope import ScopeAuthority, ScopeError


def wire(text="original", **changes):
    source = text.encode("utf-8")
    args = {"expected_source_sha256": sha256(source), "ring": 7,
            "kind": "note", "classification": "public", **changes}
    return encode_capsule(source, **args)


class CodecTests(unittest.TestCase):
    def test_exact_unicode_delimiters_and_control_roundtrip(self):
        text = ':: [ ] " \\ \r\n\t\x00 中文 e\u0301 😀\u2028\u2029'
        raw = wire(text)
        value = decode_capsule(raw, expected_sha256=sha256(raw))
        self.assertEqual(value["text"].encode("utf-8"), text.encode("utf-8"))
        self.assertEqual(render_face(value, face="machine").encode("utf-8"), raw)

    def test_unicode_normalization_is_never_silent(self):
        nfc, nfd = wire("é"), wire("e\u0301")
        self.assertNotEqual(sha256(nfc), sha256(nfd))
        self.assertNotEqual(json.loads(nfc)["source_sha256"], json.loads(nfd)["source_sha256"])

    def test_metadata_changes_have_distinct_full_identities(self):
        rows = [wire(), wire(ring=8), wire(kind="repair")]
        self.assertEqual(len({sha256(raw) for raw in rows}), 3)
        self.assertEqual(len({json.loads(raw)["source_sha256"] for raw in rows}), 1)

    def test_strict_schema_and_bool_boundaries(self):
        original = json.loads(wire())
        bad = [{**original, "ring": value} for value in (True, False, 7.0, -1, 0, "7")]
        bad += [{**original, "classification": "private"}, {**original, "extra": True},
                {key: value for key, value in original.items() if key != "kind"},
                {**original, "schema": "kimi.hce-capsule.v1"}, {**original, "text": 1}]
        for value in bad:
            raw = canonical(value)
            with self.subTest(value=value), self.assertRaises(HceError):
                decode_capsule(raw, expected_sha256=sha256(raw))

    def test_duplicate_json_fields_nonfinite_and_malformed_unicode(self):
        original = wire()
        cases = [original[:-1] + b',"ring":7}', b'{"ring":NaN}', b'{"ring":Infinity}',
                 b'{"text":"\\ud800"}', b'{"text":"\xff"}', b'\xef\xbb\xbf' + original]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(HceError):
                decode_capsule(raw, expected_sha256=sha256(raw))

    def test_expected_full_hash_and_canonical_wire_are_required(self):
        raw = wire()
        for pin in (sha256(raw)[:16], sha256(raw).upper(), "../capsule", "0" * 64):
            with self.subTest(pin=pin), self.assertRaises(HceError):
                decode_capsule(raw, expected_sha256=pin)
        spaced = json.dumps(json.loads(raw), ensure_ascii=False, indent=2).encode("utf-8")
        with self.assertRaises(HceError):
            decode_capsule(spaced, expected_sha256=sha256(spaced))

    def test_source_pin_bounds_and_invalid_encoding(self):
        for raw in (b"", b"\xff", b"a" * (MAX_SOURCE_BYTES + 1), b"\x00" * MAX_SOURCE_BYTES, bytearray(b"original")):
            with self.subTest(type=type(raw), size=len(raw)), self.assertRaises(HceError):
                encode_capsule(raw, expected_source_sha256=sha256(bytes(raw)), ring=7, kind="note", classification="public")
        with self.assertRaises(HceError):
            wire(expected_source_sha256="0" * 64)

    def test_faces_are_explicit_derived_plain_text_not_translation(self):
        value = json.loads(wire(':: " Chinese 原文 \n'))
        quoted = json.dumps(value["text"], ensure_ascii=False)
        for face in ("zh", "en"):
            text = render_face(value, face=face)
            self.assertIn(quoted, text)
            self.assertIn(value["source_sha256"], text)
        with self.assertRaises(HceError):
            render_face(value, face="auto")


class ScopedStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xnet-hce-inert-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).absolute()
        self.ledger = Ledger(self.root / "data")
        self.authority = ScopeAuthority(self.root / "authority")
        self.scope = self.authority.create(program="inert HCE fixture only", policy_url="local:hce-test",
            policy_capture=b"Own temporary public source, Ledger and CAS fixture only. No model/network.",
            allowed_assets=["path:" + str(self.ledger.cas_dir), "path:" + str(self.ledger.db_path.parent)],
            methods=["hce_cas_read", "hce_cas_write", "hce_ledger_read", "hce_ledger_append", "fixture_mutate"],
            fixture=True, requests_per_minute=600, max_parallel=1)["scope_id"]
        self.admissions = []
        def gate(method, target):
            self.authority.gate(self.scope, target, method)
            self.admissions.append((method, target))
        self.gate = gate
        self.store = HceCapsuleStore(self.ledger, scope_gate=gate, scope_id=self.scope, task_id="hce-task")

    def add(self, text="original", ring=7, kind="note"):
        source = text.encode("utf-8")
        return self.store.store(source, expected_source_sha256=sha256(source), ring=ring,
                                kind=kind, classification="public")

    def fixture_write(self, path, raw):
        self.gate("fixture_mutate", "path:" + str(path))
        path.write_bytes(raw)

    def test_real_cas_provenance_index_and_existing_context_seam(self):
        first, second = self.add(), self.add("second", ring=12)
        pin = self.store.store_index([second, first])
        self.assertEqual([v["text"] for v in self.store.fetch_ring(expected_index_sha256=pin, ring=7)], ["original"])
        context = self.store.context_record(first, record_id="hce-public-7", face="machine", max_bytes=16384)
        self.assertEqual(context["classification"], "public")
        self.assertEqual(set(context["record"]), {"record_id", "kind", "text", "source_sha256", "text_sha256", "receipt_sha256"})
        request = {"task": {"task_id": "hce-task"}, "public_feedback": []}
        packet = {"schema": "xnet.repair-public-context.v1", "task_id": "hce-task",
            "input_sha256": _public_context_input(request), "records": [context["record"]],
            "authority": "none", "work_performed": False, "hidden_cases_used": False, "context_only": True}
        admitted = _admit_public_context(packet, request, {"tasks": {"hce-task": [context["selection"]]}, "max_bytes": 16384})
        self.assertEqual(admitted["records"], [context["record"]])
        self.assertTrue({"hce_cas_read", "hce_cas_write", "hce_ledger_read", "hce_ledger_append"} <= {m for m, _ in self.admissions})

    def test_identical_source_in_distinct_rings_does_not_overwrite(self):
        first, second, third = self.add(), self.add(ring=12), self.add(kind="repair")
        self.assertEqual(len({r["capsule_sha256"] for r in (first, second, third)}), 3)
        self.assertEqual([self.store.fetch(r)["ring"] for r in (first, second, third)], [7, 12, 7])

    def test_tampered_and_missing_cas_sources_are_refused(self):
        ref = self.add()
        path = self.ledger.cas_dir / ref["capsule_sha256"][:2] / ref["capsule_sha256"]
        self.fixture_write(path, path.read_bytes() + b" ")
        with self.assertRaises(HceError):
            self.store.fetch(ref)
        self.gate("fixture_mutate", "path:" + str(path)); path.unlink()
        with self.assertRaises(HceError):
            self.store.fetch(ref)

    def test_ref_ring_source_and_borrowed_task_identity_are_checked(self):
        ref = self.add()
        for changes in ({"ring": 12}, {"kind": "repair"}, {"source_sha256": "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(HceError):
                self.store.fetch({**ref, **changes})
        other = HceCapsuleStore(self.ledger, scope_gate=self.gate, scope_id=self.scope, task_id="another-task")
        with self.assertRaises(HceError):
            other.fetch(ref)

    def test_index_metadata_must_match_actual_capsule_not_just_selection(self):
        ref = self.add()
        bad = {**ref, "ring": 12}
        body = {"schema": INDEX_SCHEMA, "classification": "public", "scope_id": self.scope,
                "task_id": "hce-task", "records": [bad]}
        self.gate("hce_cas_write", "path:" + str(self.ledger.cas_dir))
        self.gate("hce_ledger_append", "path:" + str(self.ledger.db_path.parent))
        pin = self.ledger.put_evidence(canonical(body), source="forged-inert-index", scope_id=self.scope)
        self.gate("hce_ledger_append", "path:" + str(self.ledger.db_path.parent))
        self.ledger.append(make_event("hce-task", self.scope, "hce.index-only", {"index_sha256": pin}, source="hce-source-adapter"))
        with self.assertRaises(HceError):
            self.store.fetch_ring(expected_index_sha256=pin, ring=7)

    def test_unwitnessed_index_and_duplicate_index_rows_are_refused(self):
        ref = self.add()
        with self.assertRaises(HceError):
            self.store.store_index([ref, ref])
        body = {"schema": INDEX_SCHEMA, "classification": "public", "scope_id": self.scope,
                "task_id": "hce-task", "records": [ref]}
        self.gate("hce_cas_write", "path:" + str(self.ledger.cas_dir))
        self.gate("hce_ledger_append", "path:" + str(self.ledger.db_path.parent))
        pin = self.ledger.put_evidence(canonical(body), source="unwitnessed-inert-index", scope_id=self.scope)
        with self.assertRaises(HceError):
            self.store.fetch_ring(expected_index_sha256=pin, ring=7)

    def test_scope_denial_precedes_cas_or_ledger_io(self):
        ref = self.add()
        def denied(method, target):
            raise ScopeError("fixed refusal")
        refused = HceCapsuleStore(self.ledger, scope_gate=denied, scope_id=self.scope, task_id="hce-task")
        with patch.object(self.ledger, "get_evidence") as get, patch.object(self.ledger, "put_evidence") as put, patch.object(self.ledger, "append") as append:
            with self.assertRaises(ScopeError):
                refused.fetch(ref)
            with self.assertRaises(ScopeError):
                refused.store(b"original", expected_source_sha256=sha256(b"original"), ring=7, kind="note", classification="public")
            get.assert_not_called(); put.assert_not_called(); append.assert_not_called()

    def test_short_or_path_like_reference_is_refused_before_io(self):
        ref = self.add()
        with patch.object(self.ledger, "get_evidence") as get:
            for pin in (ref["capsule_sha256"][:16], "../../private"):
                with self.assertRaises(HceError):
                    self.store.fetch({**ref, "capsule_sha256": pin})
            get.assert_not_called()

    def test_context_budget_refuses_without_clipping_or_new_receipt(self):
        ref = self.add("enough source text")
        with patch.object(self.ledger, "put_evidence") as put, patch.object(self.ledger, "append") as append:
            with self.assertRaises(HceError):
                self.store.context_record(ref, record_id="bounded", face="machine", max_bytes=1)
            put.assert_not_called(); append.assert_not_called()
        with self.assertRaises(HceError):
            self.store.context_record(ref, record_id="bounded", face="machine", max_bytes=True)

    def test_public_classification_is_explicit_not_inferred(self):
        with patch.object(self.ledger, "put_evidence") as put:
            with self.assertRaises(HceError):
                self.store.store(b"original", expected_source_sha256=sha256(b"original"), ring=7, kind="note", classification="private")
            put.assert_not_called()

    def test_hardlinked_cas_object_is_refused(self):
        ref = self.add()
        path = self.ledger.cas_dir / ref["source_sha256"][:2] / ref["source_sha256"]
        linked = self.ledger.cas_dir / "fixture-hardlink"
        self.gate("fixture_mutate", "path:" + str(linked)); os.link(path, linked)
        with self.assertRaises(HceError):
            self.store.fetch(ref)
        with self.assertRaises(HceError):
            self.add()


if __name__ == "__main__":
    unittest.main()
