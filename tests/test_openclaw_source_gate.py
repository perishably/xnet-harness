"""OpenClaw source-envelope controls; no runner, model, or storage operations."""
import copy
import unittest
from unittest.mock import patch

from adapters.openclaw import (
    SourcePacketError, gate_contract, make_source_packet, validate_source_packet,
)
from xnet.protocol import canonical, digest, sha256


NOW = 1_791_288_000


def packet(**changes):
    value = make_source_packet(task_id="sphere-1", producer="operator", kind="note",
                               text="Public sphere note: café 🧬\n", packet_id="p-1", now=NOW)
    value.update(changes)
    if changes:
        value["packet_sha256"] = digest({key: item for key, item in value.items()
                                         if key != "packet_sha256"})
    return value


class SourceGateTests(unittest.TestCase):
    def test_round_trip_pins_bytes_and_independent_copy(self):
        source = packet()
        checked = validate_source_packet(source, now=NOW)
        self.assertEqual(checked, source)
        self.assertIsNot(checked, source)
        self.assertIsNot(checked["tools"], source["tools"])
        self.assertEqual(source["text_sha256"], sha256(source["text"].encode("utf-8")))
        self.assertEqual(source["packet_sha256"], digest({key: value for key, value in source.items()
                                                        if key != "packet_sha256"}))
        checked["tools"].append("not-an-admitted-action")
        self.assertEqual(source["tools"], [])

    def test_all_declared_labels(self):
        for producer in ("operator", "model", "peer"):
            for kind in ("note", "evidence", "strategy", "proposal"):
                with self.subTest(producer=producer, kind=kind):
                    self.assertEqual(validate_source_packet(packet(producer=producer, kind=kind), now=NOW)["kind"], kind)

    def test_default_uuid_and_current_clock(self):
        with patch("adapters.openclaw.source_gate.time.time", return_value=NOW):
            value = make_source_packet(task_id="sphere-1", producer="model", kind="proposal", text="public")
            self.assertEqual(validate_source_packet(value)["created_at"], NOW)
            self.assertEqual(value["expires_at"], NOW + 86_400)
            self.assertEqual(len(value["packet_id"]), 36)

    def test_extra_or_missing_fields_are_refused_even_resealed(self):
        for extra in ("command", "shell", "exec", "hidden_report", "benchmark_answers", "api_key", "scope_id"):
            with self.subTest(extra=extra), self.assertRaises(SourcePacketError):
                validate_source_packet(packet(**{extra: "never executed"}), now=NOW)
        for missing in packet():
            value = packet()
            del value[missing]
            with self.subTest(missing=missing), self.assertRaises(SourcePacketError):
                validate_source_packet(value, now=NOW)

    def test_authority_context_tools_and_hops_refused(self):
        for change in ({"authority": "execute"}, {"context_only": False}, {"context_only": 1},
                       {"tools": ["powershell"]}, {"tools": ()}, {"max_hops": 0},
                       {"max_hops": 5}, {"max_hops": True}, {"max_hops": 4.0}):
            with self.subTest(change=change), self.assertRaises(SourcePacketError):
                validate_source_packet(packet(**change), now=NOW)

    def test_hidden_and_benchmark_classifications_and_kinds_refused(self):
        for change in ({"classification": "hidden"}, {"classification": "benchmark-artifacts"},
                       {"classification": "private"}, {"kind": "answer"}, {"kind": "gold"},
                       {"kind": "hidden"}, {"kind": "benchmark-artifacts"}, {"producer": "admin"}):
            with self.subTest(change=change), self.assertRaises(SourcePacketError):
                validate_source_packet(packet(**change), now=NOW)

    def test_hash_tampering_and_bad_digest_types(self):
        for field in ("text_sha256", "packet_sha256"):
            for replacement in ("0" * 64, "A" * 64, "g" * 64, "short", None, 1):
                value = packet()
                value[field] = replacement
                with self.subTest(field=field, replacement=replacement), self.assertRaises(SourcePacketError):
                    validate_source_packet(value, now=NOW)
        value = packet()
        value["text"] += " changed"
        with self.assertRaises(SourcePacketError):
            validate_source_packet(value, now=NOW)
        value = packet()
        value["producer"] = "model"
        with self.assertRaises(SourcePacketError):
            validate_source_packet(value, now=NOW)

    def test_expired_future_and_invalid_lifetimes(self):
        self.assertEqual(validate_source_packet(packet(), now=NOW + 86_399)["max_hops"], 4)
        with self.assertRaises(SourcePacketError):
            validate_source_packet(packet(), now=NOW + 86_400)
        for change in ({"created_at": NOW + 1}, {"created_at": -1}, {"created_at": True},
                       {"expires_at": NOW}, {"expires_at": NOW + 86_401},
                       {"expires_at": 2**63}, {"expires_at": float(NOW + 100)}):
            with self.subTest(change=change), self.assertRaises(SourcePacketError):
                validate_source_packet(packet(**change), now=NOW)

    def test_ttl_and_now_strict_integer_types(self):
        for ttl in (0, -1, 86_401, True, 1.0, "100"):
            with self.subTest(ttl=ttl), self.assertRaises(SourcePacketError):
                make_source_packet(task_id="sphere-1", producer="operator", kind="note", text="public", now=NOW, ttl_seconds=ttl)
        for now in (-1, True, 1.0, "now", 2**63):
            with self.subTest(now=now), self.assertRaises(SourcePacketError):
                validate_source_packet(packet(), now=now)

    def test_utf8_budget_and_surrogates(self):
        for text in ("a" * 16_384, "🧬" * 4096, ""):
            value = make_source_packet(task_id="sphere-1", producer="operator", kind="note", text=text, now=NOW)
            self.assertEqual(validate_source_packet(value, now=NOW)["text"], text)
        for text in ("a" * 16_385, "🧬" * 4097, "\ud800", b"bytes", 123):
            with self.subTest(length=len(text) if type(text) in (str, bytes) else None), self.assertRaises(SourcePacketError):
                make_source_packet(task_id="sphere-1", producer="operator", kind="note", text=text, now=NOW)

    def test_known_private_keys_and_credentials_refused(self):
        private_key_header = "-----BEGIN " + "PRIVATE KEY-----"
        encrypted_key_header = "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"
        rsa_key_header = "-----begin " + "rsa private key-----"
        bearer_header = "Authorization" + ": Bearer fictional_test_value_123456789"
        aws_access_key = "AK" + "IA" + "0" * 16
        for text in (
            private_key_header + "\nfictional-test-value",
            encrypted_key_header + "\nfictional-test-value",
            rsa_key_header + "\nfictional-test-value",
            "api_key = fictional_test_value_123456789",
            bearer_header,
            "password: fictional_test_value_123456789",
            aws_access_key,
            "ghp_" + "x" * 30,
        ):
            with self.subTest(text=text[:35]), self.assertRaises(SourcePacketError):
                make_source_packet(task_id="sphere-1", producer="operator", kind="note", text=text, now=NOW)
        value = packet()
        value["text"] = "client_secret: fictional_test_value_123456789"
        value["text_sha256"] = sha256(value["text"].encode())
        value["packet_sha256"] = digest({key: item for key, item in value.items() if key != "packet_sha256"})
        with self.assertRaises(SourcePacketError):
            validate_source_packet(value, now=NOW)

    def test_safe_ids_and_plain_builtin_types_only(self):
        for field in ("packet_id", "task_id"):
            for value in ("", "../escape", "/absolute", "x" * 65, "café", "a\nb", 1, True):
                with self.subTest(field=field, value=value), self.assertRaises(SourcePacketError):
                    validate_source_packet(packet(**{field: value}), now=NOW)
        class FakeString(str):
            pass
        class FakeDict(dict):
            pass
        class FakeList(list):
            pass
        for value in (FakeDict(packet()), [], b"{}", None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(SourcePacketError):
                validate_source_packet(value, now=NOW)
        value = packet()
        value["text"] = FakeString(value["text"])
        with self.assertRaises(SourcePacketError):
            validate_source_packet(value, now=NOW)
        value = packet()
        value["tools"] = FakeList()
        with self.assertRaises(SourcePacketError):
            validate_source_packet(value, now=NOW)

    def test_command_text_is_preserved_as_inert_data(self):
        text = "Public proposal: do not run this example: Remove-Item -Recurse /tmp/example; $(echo example)"
        with patch("subprocess.run", side_effect=AssertionError("no process may run")), \
                patch("socket.socket", side_effect=AssertionError("no network may run")):
            value = make_source_packet(task_id="sphere-1", producer="model", kind="proposal", text=text, now=NOW)
            self.assertEqual(validate_source_packet(value, now=NOW)["text"], text)
            self.assertEqual(gate_contract()["model_calls"], 0)

    def test_unknown_python_objects_are_refused_without_calling_hooks(self):
        class Hostile:
            def __bool__(self):
                raise AssertionError("untrusted boolean hook called")

            def __str__(self):
                raise AssertionError("untrusted string hook called")

            def __repr__(self):
                raise AssertionError("untrusted repr hook called")

        for field in packet():
            value = packet()
            value[field] = Hostile()
            with self.subTest(field=field), self.assertRaises(SourcePacketError):
                validate_source_packet(value, now=NOW)
        with self.assertRaises(SourcePacketError):
            make_source_packet(task_id="sphere-1", producer="operator", kind="note", text="public",
                               packet_id=Hostile(), now=NOW)
        with self.assertRaises(SourcePacketError):
            validate_source_packet(packet(), now=Hostile())

    def test_contract_reports_data_only_limits_without_authentication_claim(self):
        value = gate_contract()
        self.assertFalse(value["OpenClaw_runner_executed"])
        self.assertFalse(value["tools"])
        self.assertFalse(value["producer_authentication"])
        self.assertFalse(value["truth_attested"])
        self.assertEqual(value["classification_owner"], "caller")
        self.assertEqual(value["max_hops"], 4)
        self.assertIn("not complete DLP", value["secret_screening"])
        self.assertEqual(copy.deepcopy(value), value)
        self.assertIsInstance(canonical(value), bytes)


if __name__ == "__main__":
    unittest.main()
