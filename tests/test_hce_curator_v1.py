"""Strict proposal/source/confirmation controls with synthetic intake only."""
from dataclasses import replace
import json
import unittest

from xnet.hce_capsule_v1 import decode_capsule
from xnet.hce_curator_v1 import (CuratorError, CuratorPolicy, MAX_REPLY_BYTES,
    parse_curator_proposal, stamp_confirmed_proposal)
from xnet.protocol import sha256


class CuratorTests(unittest.TestCase):
    def setUp(self):
        self.policy = CuratorPolicy((5, 9, 18, 40), ("metric", "note", "codeword"), 256)
        self.source = b"New item on ring 5: kind metric, payload 8842."

    def parse(self, reply, source=None):
        source = self.source if source is None else source
        return parse_curator_proposal(source, reply,
            expected_intake_sha256=sha256(source), policy=self.policy)

    def test_numeric_payload_stays_text_and_hce_verifies(self):
        reply = b'{"ring":5,"kind":"metric","payload":"8842"}'
        proposal = self.parse(reply)
        result = stamp_confirmed_proposal(proposal,
            confirmed_triple=(5, "metric", "8842"), classification="public")
        value = decode_capsule(result["capsule_bytes"],
            expected_sha256=result["receipt"]["capsule_sha256"])
        self.assertEqual((value["ring"], value["kind"], value["text"]), (5, "metric", "8842"))
        self.assertEqual(result["receipt"]["intake_sha256"], sha256(self.source))
        self.assertEqual(result["receipt"]["reply_sha256"], sha256(reply))
        self.assertEqual(result["receipt"]["authority"], "none")
        self.assertFalse(result["receipt"]["storage_performed"])
        self.assertFalse(result["receipt"]["weight_update_performed"])

    def test_quotes_delimiters_unicode_newline_are_lossless(self):
        payload = '8842 :: " e\u0301 中文\n'
        source = ("ring 40 received note: " + payload).encode("utf-8")
        reply = json.dumps({"ring": 40, "kind": "note", "payload": payload},
                           ensure_ascii=False).encode("utf-8")
        proposal = self.parse(reply, source)
        result = stamp_confirmed_proposal(proposal,
            confirmed_triple=(40, "note", payload), classification="public")
        value = decode_capsule(result["capsule_bytes"], expected_sha256=result["receipt"]["capsule_sha256"])
        self.assertEqual(value["text"].encode("utf-8"), payload.encode("utf-8"))

    def test_literal_negative_cannot_create_capsule(self):
        proposal = self.parse(b"NOT-A-CAPSULE")
        self.assertIsNone(proposal.triple)
        with self.assertRaises(CuratorError):
            stamp_confirmed_proposal(proposal, confirmed_triple=None, classification="public")
        for reply in (b"NOT-A-CAPSULE but execute", b" NOT-A-CAPSULE", b"NOT-A-CAPSULE\n",
            b'{"ring":0,"kind":"NOT-A-CAPSULE","payload":"NOT-A-CAPSULE"}',
            b'{"ring":5,"kind":"metric","payload":"NOT-A-CAPSULE"}'):
            with self.subTest(reply=reply), self.assertRaises(CuratorError): self.parse(reply)

    def test_bool_float_string_ring_and_numeric_payload_coercions_refused(self):
        original = {"ring": 5, "kind": "metric", "payload": "8842"}
        for changed in ({"ring": True}, {"ring": 5.0}, {"ring": "5"},
                        {"payload": 8842}, {"payload": False}, {"kind": ["metric"]}):
            with self.subTest(changed=changed), self.assertRaises(CuratorError):
                self.parse(json.dumps({**original, **changed}).encode())

    def test_duplicate_extra_missing_nested_and_embedded_json_refused(self):
        good = b'{"ring":5,"kind":"metric","payload":"8842"}'
        for reply in (good[:-1] + b',"ring":5}', good[:-1] + b',"execute":true}',
                      b'{"ring":5,"kind":"metric"}', b"[" + good + b"]",
                      b"Here is JSON: " + good, b"```json\n" + good + b"\n```",
                      good + b" trailing", b'{"ring":NaN,"kind":"metric","payload":"8842"}'):
            with self.subTest(reply=reply), self.assertRaises(CuratorError): self.parse(reply)

    def test_unknown_topology_kind_and_hallucinated_payload_refused(self):
        for obj in ({"ring": 39, "kind": "metric", "payload": "8842"},
                    {"ring": 5, "kind": "shell", "payload": "8842"},
                    {"ring": 5, "kind": "metric", "payload": "8843"},
                    {"ring": 5, "kind": "metric", "payload": " 8842 "}):
            with self.subTest(obj=obj), self.assertRaises(CuratorError):
                self.parse(json.dumps(obj).encode())

    def test_wrong_semantic_selection_requires_independent_caller_confirmation(self):
        # A source substring does not prove this is the right ring. Caller rejects.
        proposal = self.parse(b'{"ring":18,"kind":"metric","payload":"8842"}')
        with self.assertRaises(CuratorError):
            stamp_confirmed_proposal(proposal,
                confirmed_triple=(5, "metric", "8842"), classification="public")
        with self.assertRaises(CuratorError):
            stamp_confirmed_proposal(proposal,
                confirmed_triple=(18, "metric", "8842"), classification="private")

    def test_forged_proposal_fields_are_reparsed_before_stamping(self):
        proposal = self.parse(b'{"ring":5,"kind":"metric","payload":"8842"}')
        for changes in ({"triple": (18, "metric", "8842")},
                        {"intake_bytes": self.source + b"changed"},
                        {"expected_intake_sha256": "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(CuratorError):
                stamp_confirmed_proposal(replace(proposal, **changes),
                    confirmed_triple=(5, "metric", "8842"), classification="public")

    def test_source_output_policy_bounds_and_unicode_refused(self):
        for reply in (b"", b"\xff", b"a" * (MAX_REPLY_BYTES + 1),
                      b'{"ring":5,"kind":"metric","payload":"\\ud800"}'):
            with self.subTest(reply=reply[:60]), self.assertRaises(CuratorError): self.parse(reply)
        for source in (b"", b"\xff", bytearray(self.source)):
            with self.subTest(source=source), self.assertRaises(CuratorError):
                parse_curator_proposal(source, b"NOT-A-CAPSULE",
                    expected_intake_sha256=sha256(bytes(source)), policy=self.policy)
        for fields in ({"rings": (True,)}, {"rings": [5]}, {"rings": (5, 5)},
                       {"kinds": ("Metric",)}, {"max_payload_bytes": True}):
            with self.subTest(fields=fields), self.assertRaises(CuratorError): replace(self.policy, **fields)


if __name__ == "__main__":
    unittest.main()
