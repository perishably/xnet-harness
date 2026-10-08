"""Pure policy boundary controls; synthetic pins, no model capability claim."""
from dataclasses import replace
import unittest

from xnet.halo_context_v1 import (ContextPinProposal, EngineProfile,
                                  HaloContextError, HaloPinRegistry)


def profile():
    return EngineProfile("qwen-fixture", "a"*64, "b"*64, "c"*64,
                         "d"*64, "e"*64, 8192, 650)


def proposal(p):
    return ContextPinProposal(p.sha256, 6500, 7000, ("f"*64,))


class HaloContextTests(unittest.TestCase):
    def advise(self, registry, p, tokens):
        return registry.advise(profile_sha256=p.sha256,
            observed_profile_sha256=p.sha256, rendered_prompt_sha256="0"*64,
            measured_prompt_tokens=tokens)

    def test_boundary_margin_and_reserve(self):
        p = profile(); registry = HaloPinRegistry()
        registry.register(p, proposal(p))
        self.assertFalse(self.advise(registry, p, 6499)["review_due"])
        self.assertTrue(self.advise(registry, p, 6500)["review_due"])
        exact = self.advise(registry, p, 7542)
        self.assertEqual(exact["remaining_after_reserve"], 0)
        self.assertEqual(exact["authority"], "none")
        self.assertFalse(exact["rotation_performed"])
        with self.assertRaises(HaloContextError): self.advise(registry, p, 7543)

    def test_full_profile_identity_changes_for_every_configuration_field(self):
        p = profile()
        for field in ("model_sha256", "runner_bundle_sha256", "tokenizer_sha256",
                      "template_sha256", "configuration_sha256"):
            with self.subTest(field=field):
                changed = replace(p, **{field: "1"*64})
                self.assertNotEqual(p.sha256, changed.sha256)
                with self.assertRaises(HaloContextError): proposal(p).validate_for(changed)
        for fields in ({"capacity_tokens": 16384}, {"generation_reserve_tokens": 32}):
            with self.assertRaises(HaloContextError): proposal(p).validate_for(replace(p, **fields))

    def test_no_cross_engine_global_pin_or_missing_default(self):
        p = profile(); registry = HaloPinRegistry()
        with self.assertRaises(HaloContextError): self.advise(registry, p, 1)
        lite = replace(p, engine_id="lite-fixture", capacity_tokens=4096)
        with self.assertRaises(HaloContextError): registry.register(lite, proposal(p))
        with self.assertRaises(HaloContextError):
            registry.register(lite, ContextPinProposal(lite.sha256, 6500, 7000, ("f"*64,)))
        registry.register(p, proposal(p))
        with self.assertRaises(HaloContextError):
            registry.advise(profile_sha256=p.sha256, observed_profile_sha256=lite.sha256,
                           rendered_prompt_sha256="0"*64, measured_prompt_tokens=100)

    def test_frozen_evidence_and_policy_conflicts(self):
        p = profile(); registry = HaloPinRegistry(); pin = proposal(p)
        self.assertEqual(registry.register(p, pin), registry.register(p, pin))
        with self.assertRaises(HaloContextError): registry.register(p, replace(pin, review_tokens=6400))
        with self.assertRaises(HaloContextError): replace(pin, evidence_sha256s=["f"*64])
        with self.assertRaises(HaloContextError): replace(pin, evidence_sha256s=("f"*64, "f"*64))
        with self.assertRaises(HaloContextError): replace(pin, purpose="reasoning-proven")
        class EqualToAnything:
            def __eq__(self, other): return True
        with self.assertRaises(HaloContextError): replace(pin, purpose=EqualToAnything())
        with self.assertRaises(HaloContextError): replace(pin, evidence_sha256s=({},))

    def test_malformed_pins_bool_and_capacity_refused(self):
        p = profile()
        for value in (True, 0, -1, 8192.0):
            with self.assertRaises(HaloContextError): replace(p, capacity_tokens=value)
        for value in (True, -1, 8192):
            with self.assertRaises(HaloContextError): replace(p, generation_reserve_tokens=value)
        for value in (None, "a"*16, "A"*64, "../invalid"):
            with self.assertRaises(HaloContextError): replace(p, tokenizer_sha256=value)
        with self.assertRaises(HaloContextError): replace(proposal(p), review_tokens=True)
        with self.assertRaises(HaloContextError): replace(proposal(p), review_tokens=7000)
        registry = HaloPinRegistry(); registry.register(p, proposal(p))
        for value in (True, -1, 2.0):
            with self.assertRaises(HaloContextError): self.advise(registry, p, value)


if __name__ == "__main__":
    unittest.main()
