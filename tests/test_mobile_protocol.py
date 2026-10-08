"""In-memory protocol checks; no phone, listener, VPN, or model is used."""
from __future__ import annotations

import json
import unittest

from xnet.mobile_protocol import (
    MAX_PROMPT_BYTES,
    MobileProtocolError,
    build_pair_request,
    build_pair_response,
    build_request,
    build_response,
    inspect_pair_request,
    inspect_pair_response,
    inspect_request,
    inspect_response,
    load_bounded_json,
    translate_model_lane_for_remote_home,
    validate_private_mesh_address,
)
from xnet.protocol import canonical, sha256


HCE = "a" * 64
SOURCE = "b" * 64
PRIOR = "c" * 64
MODEL = "d" * 64


def request_bytes(**changes):
    values = {
        "request_id": "request-1",
        "device_id": "iphone-1",
        "sequence": 1,
        "sent_at": 1000,
        "task_id": "repair-1",
        "prompt": "Fix the bounded parser.",
        "hce_sha256": HCE,
        "source_sha256": [SOURCE],
        "requested_lane": "home-4b",
        "prior_outcome_sha256": PRIOR,
    }
    values.update(changes)
    return build_request(**values)


class MobileProtocolTests(unittest.TestCase):
    def test_pairing_messages_are_canonical_and_authority_free(self):
        request = build_pair_request(code="A" * 32, device_id="iphone-1", device_name="Felix iPhone")
        parsed = inspect_pair_request(request)
        self.assertTrue(parsed["policy"]["explicit_user_pair"])
        self.assertEqual(parsed["policy"]["tool_authority"], "none")
        response = build_pair_response(device_id="iphone-1", bearer_token="B" * 43,
                                       expires_at=2000)
        paired = inspect_pair_response(response)
        self.assertFalse(paired["policy"]["vpn_control"])
        self.assertEqual(paired["bearer_token"], "B" * 43)

    def test_request_pins_sources_hce_prompt_and_fixed_ladder(self):
        wire = request_bytes()
        value = inspect_request(wire)
        self.assertEqual(value["route"]["ordered_lanes"],
                         ["apple-native", "home-4b", "home-14b"])
        self.assertEqual(value["route"]["after_lane"], "apple-native")
        self.assertEqual(value["route"]["parameter_ceiling_billion"], 14)
        self.assertEqual(value["input"]["hce_sha256"], HCE)
        self.assertEqual(value["input"]["source_sha256"], [SOURCE])
        self.assertEqual(value["input"]["capability"], "code")
        self.assertEqual(value["input"]["prompt_sha256"],
                         sha256(b"Fix the bounded parser."))
        self.assertTrue(value["policy"]["explicit_user_send"])
        self.assertEqual(value["policy"]["tool_authority"], "none")
        self.assertFalse(value["policy"]["vpn_control"])

    def test_home_14b_declares_prior_4b_route_and_ceiling_cannot_change(self):
        wire = request_bytes(requested_lane="home-14b")
        self.assertEqual(inspect_request(wire)["route"]["after_lane"], "home-4b")
        value = json.loads(wire)
        value["route"]["parameter_ceiling_billion"] = 30
        with self.assertRaises(MobileProtocolError):
            inspect_request(canonical(value))
        with self.assertRaises(MobileProtocolError):
            request_bytes(requested_lane="apple-native")

    def test_device_byom_lane_needs_explicit_evidenced_remote_home_translation(self):
        receipt = translate_model_lane_for_remote_home(
            "xnet-4b", source_location="device-qualified",
            explicit_user_route=True, lane_evidence_sha256="f" * 64)
        self.assertEqual(receipt.source_lane, "xnet-4b")
        self.assertEqual(receipt.source_location, "device-qualified")
        self.assertEqual(receipt.requested_lane, "home-4b")
        self.assertEqual(receipt.lane_evidence_sha256, "f" * 64)
        for changes in (
            {"explicit_user_route": False},
            {"source_location": "home-remote"},
            {"lane_evidence_sha256": "missing"},
        ):
            values = {"source_location": "device-qualified", "explicit_user_route": True,
                      "lane_evidence_sha256": "f" * 64}
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(MobileProtocolError):
                translate_model_lane_for_remote_home("xnet-4b", **values)
        with self.assertRaises(MobileProtocolError):
            request_bytes(requested_lane="xnet-4b")

    def test_response_binds_request_model_output_and_source_evidence(self):
        wire = request_bytes()
        request = inspect_request(wire)
        response = build_response(request, request_sha256=sha256(wire),
                                  selected_lane="home-4b",
                                  model_identity_sha256=MODEL, text="bounded fix")
        value = inspect_response(response, expected_request_wire=wire)
        self.assertEqual(value["output"]["sha256"], sha256(b"bounded fix"))
        self.assertEqual(value["evidence"], {
            "hce_sha256": HCE, "source_sha256": [SOURCE],
        })
        self.assertEqual(value["policy"], {"tool_authority": "none", "vpn_control": False})
        with self.assertRaises(MobileProtocolError):
            build_response(request, request_sha256=sha256(wire), selected_lane="home-14b",
                           model_identity_sha256=MODEL, text="wrong rung")

    def test_duplicate_nonfinite_float_noncanonical_and_hash_mutation_are_refused(self):
        wire = request_bytes()
        duplicate = wire[:-1] + b',"sequence":1}'
        for malformed in (duplicate, b'{"x":NaN}', b'{"x":1.5}', b'{"x":1e999}',
                          b'{"x":' + b"9" * 100 + b"}"):
            with self.subTest(malformed=malformed[-20:]), self.assertRaises(MobileProtocolError):
                load_bounded_json(malformed, maximum_bytes=1024)
        with self.assertRaises(MobileProtocolError):
            inspect_request(b" " + wire)
        value = json.loads(wire)
        value["input"]["prompt_sha256"] = "0" * 64
        with self.assertRaises(MobileProtocolError):
            inspect_request(canonical(value))
        value = json.loads(wire)
        value["route"]["requested_lane"] = []
        with self.assertRaises(MobileProtocolError):
            inspect_request(canonical(value))

    def test_request_bounds_and_exact_types_are_enforced(self):
        with self.assertRaises(MobileProtocolError):
            request_bytes(prompt="x" * (MAX_PROMPT_BYTES + 1))
        with self.assertRaises(MobileProtocolError):
            request_bytes(sequence=True)
        with self.assertRaises(MobileProtocolError):
            request_bytes(source_sha256=[SOURCE, SOURCE])
        with self.assertRaises(MobileProtocolError):
            request_bytes(hce_sha256="A" * 64)
        with self.assertRaises(MobileProtocolError):
            request_bytes(prior_outcome_sha256="missing")
        with self.assertRaises(MobileProtocolError):
            request_bytes(prompt="portable\u2028separator")
        with self.assertRaises(MobileProtocolError):
            build_pair_request(code="A" * 32, device_id="iphone-1",
                               device_name="spoofed\nname")

    def test_only_numeric_private_mesh_addresses_are_accepted(self):
        for accepted in ("100.64.10.20", "10.4.5.6", "172.16.0.2", "192.168.7.8", "fd00::2"):
            with self.subTest(accepted=accepted):
                self.assertEqual(validate_private_mesh_address(accepted), accepted)
        for refused in ("127.0.0.1", "::1", "0.0.0.0", "8.8.8.8", "169.254.1.2",
                        "phone.example", "https://100.64.10.20", "192.168.007.8", "fe80::1"):
            with self.subTest(refused=refused), self.assertRaises(MobileProtocolError):
                validate_private_mesh_address(refused)


if __name__ == "__main__":
    unittest.main()
