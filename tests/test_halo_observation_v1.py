"""Unbound labels remain observations and cannot enter active policy registry."""
from dataclasses import replace
import unittest

from xnet.halo_context_v1 import EngineProfile, HaloContextError, HaloPinRegistry
from xnet.halo_observation_v1 import HaloObservationError, UnboundContextCandidate


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.candidate = UnboundContextCandidate("lite-synthetic", "lite-4k-synthetic",
            4096, 3400, 3769, ("a" * 64,), ("missing exact loaded artifact identity",))

    def test_record_never_grants_activation_or_rotation(self):
        record = self.candidate.record()
        self.assertFalse(record["active"])
        self.assertFalse(record["rotation_performed"])
        self.assertEqual(record["status"], "inactive-unbound")
        self.assertEqual(record["authority"], "none")
        p = EngineProfile("synthetic", "b"*64, "c"*64, "d"*64, "e"*64, "f"*64, 4096, 48)
        with self.assertRaises(HaloContextError): HaloPinRegistry().register(p, self.candidate)

    def test_hash_binds_qualification_and_evidence(self):
        for changes in ({"blockers": ("contradictory native versus stretched configuration",)},
                        {"evidence_sha256s": ("b"*64,)}, {"review_tokens": 3399}):
            with self.subTest(changes=changes):
                self.assertNotEqual(replace(self.candidate, **changes).sha256, self.candidate.sha256)
        # Records are fresh views; external edits cannot mutate the candidate.
        record = self.candidate.record(); record["active"] = True; record["blockers"].clear()
        self.assertFalse(self.candidate.record()["active"])
        self.assertTrue(self.candidate.blockers)

    def test_bad_budgets_bool_labels_empty_blockers_and_short_pins_refused(self):
        for changes in ({"review_tokens": True}, {"review_tokens": 3769},
                        {"reported_good_tokens": 4097}, {"declared_capacity_tokens": 0},
                        {"reported_engine_label": "private/path"}, {"blockers": ()},
                        {"blockers": ["missing identity"]}, {"evidence_sha256s": ("a"*16,)},
                        {"evidence_sha256s": ("a"*64, "a"*64)}):
            with self.subTest(changes=changes), self.assertRaises(HaloObservationError):
                replace(self.candidate, **changes)


if __name__ == "__main__":
    unittest.main()
