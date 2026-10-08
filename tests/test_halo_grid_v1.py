"""Exact inert HALO arithmetic and bounded visit-count scheduling controls."""
from collections import Counter
import copy
import unittest
from unittest.mock import patch

from xnet.halo_grid_v1 import GRID, MAX_ROUNDS, plan, slot, slot_id, validate_grid


class HaloControls(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "subprocess.run", "socket.create_connection"):
            control = patch(name, side_effect=AssertionError("HALO is inert planning data"))
            control.start(); self.addCleanup(control.stop)

    def test_exact_rows_columns_diagonals_unique_labels_and_total(self):
        result = validate_grid()
        self.assertEqual(result["rows"], [111] * 6)
        self.assertEqual(result["columns"], [111] * 6)
        self.assertEqual(result["diagonals"], [111, 111])
        self.assertEqual(result["total"], 666)
        self.assertEqual(result["unique_cells"], 36)
        self.assertFalse(result["numeric_sums_are_costs"])

    def test_altered_missing_duplicate_boolean_and_other_layouts_refused(self):
        changed = [list(row) for row in GRID]; changed[0][0] = 40
        duplicate = [list(row) for row in GRID]; duplicate[0][0] = 32
        boolean = [list(row) for row in GRID]; boolean[0][-1] = True
        rotated = [list(reversed(row)) for row in reversed(GRID)]
        # Rotating the entire square preserves every magic sum, but changes
        # the requested spatial slot identity and is still refused.
        for grid in (changed, duplicate, boolean, list(GRID[:-1]), rotated):
            with self.subTest(grid=grid), self.assertRaises(ValueError): validate_grid(grid)

    def test_exact_slot_ids_and_detached_slot_values(self):
        result = plan()
        self.assertEqual(len({row["slot_id"] for row in result["slots"]}), 36)
        self.assertEqual(sorted(row["cell_label"] for row in result["slots"]), list(range(1, 37)))
        self.assertEqual(slot("halo-r01-c01")["cell_label"], 6)
        for identifier in ("halo-r1-c1", "halo-r00-c01", "halo-r07-c01", "HALO-r01-c01", None):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError): slot(identifier)
        for coordinates in ((0, 1), (7, 1), (True, 1), (1.0, 1)):
            with self.subTest(coordinates=coordinates), self.assertRaises(ValueError): slot_id(*coordinates)
        result["slots"][0]["cell_label"] = 99
        self.assertEqual(slot("halo-r01-c01")["cell_label"], 6)

    def test_six_deterministic_phases_have_balanced_rows_columns_and_complete_coverage(self):
        result = plan(rounds=2)
        self.assertEqual(result, plan(rounds=2))
        self.assertEqual(len(result["phases"]), 12)
        self.assertEqual(len({phase["phase_id"] for phase in result["phases"]}), 12)
        visits = Counter()
        for phase in result["phases"]:
            self.assertEqual(sorted(row["row"] for row in phase["visits"]), list(range(1, 7)))
            self.assertEqual(sorted(row["column"] for row in phase["visits"]), list(range(1, 7)))
            visits.update(row["slot_id"] for row in phase["visits"])
        self.assertEqual(visits, Counter({row["slot_id"]: 2 for row in result["slots"]}))

    def test_round_budget_and_explicit_inert_claims(self):
        for rounds in (0, MAX_ROUNDS + 1, True, 1.0, "1", 10**9):
            with self.subTest(rounds=rounds), self.assertRaises(ValueError): plan(rounds=rounds)
        result = plan(rounds=MAX_ROUNDS)
        self.assertEqual(len(result["phases"]), MAX_ROUNDS * 6)
        self.assertEqual(result["authority"], "none")
        for key in ("scheduler_activated", "physical_nodes_attested", "weights_updated", "performance_improvement_measured"):
            self.assertIs(result[key], False)
        for key in ("process_calls", "network_calls", "sensor_calls", "model_calls"):
            self.assertEqual(result[key], 0)
        self.assertTrue(all(row["physical_node"] is None for row in result["slots"]))


if __name__ == "__main__":
    unittest.main()
