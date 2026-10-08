"""Finite local repair fixture admission; no model source is executed."""
import copy
import unittest

from xnet.dojo_curriculum import (DojoCurriculumError, build_dojo_curriculum,
    make_selection, private_selection, verify_dojo_curriculum)
from xnet.learning_dataset import freeze_learning_dataset
from xnet.protocol import canonical, digest
from xnet.swe_repair_evaluator import declared_import_graph, evaluate_bundle, validate_baseline
from xnet.swe_repair_suite import public_task


class DojoCurriculumControls(unittest.TestCase):
    def setUp(self):
        self.catalog = build_dojo_curriculum()
        self.ids = [row["task_id"] for row in self.catalog["rows"]]

    def selection(self):
        return make_selection(self.catalog, {split: self.ids[index:index + 2]
            for split, index in (("practice", 0), ("validation", 2), ("unseen", 4))})

    def test_detached_source_pinned_public_catalog_and_private_epoch_inputs(self):
        self.assertEqual(len(self.catalog["rows"]), 24)
        self.assertEqual(len({row["family_id"] for row in self.catalog["rows"]}), 12)
        self.assertFalse(self.catalog["semantic_novelty_proven"])
        self.assertEqual(verify_dojo_curriculum(self.catalog, expected_sha256=self.catalog["curriculum_sha256"]), self.catalog)
        selection = self.selection()
        private = private_selection(selection)
        self.assertEqual(len(private["tasks"]), 6)
        self.assertEqual(private["full_tasks_sha256"], digest({task["task_id"]: task for task in private["tasks"]}))
        self.assertEqual(private["references_sha256"], digest(private["references"]))
        for row in self.catalog["rows"]:
            self.assertNotIn("hidden_cases", row["public_task"])
            self.assertNotIn("references", row)
            self.assertTrue(all(case["hidden"] is False for case in row["public_task"]["public_cases"]))
        first = private["tasks"][0]
        original = next(row["public_task"] for row in self.catalog["rows"] if row["task_id"] == first["task_id"])
        self.assertEqual(public_task(first), original)
        private["tasks"][0]["files"]["api.py"] = "mutated detached private copy"
        self.assertEqual(private_selection(selection)["tasks"][0]["files"]["api.py"], original["files"]["api.py"])
        self.catalog["rows"][0]["family_id"] = "fake-new-family"
        with self.assertRaises(DojoCurriculumError):
            verify_dojo_curriculum(self.catalog)

    def test_all_authored_faults_fail_and_references_pass_in_actual_ast_grader(self):
        # Select each family pair in exactly one split. Two selections cover
        # all24 fixtures while preserving family/near-duplicate separation.
        for offset in (0, 12):
            selected = make_selection(self.catalog, {split: self.ids[offset + index:offset + index + 4]
                for split, index in (("practice", 0), ("validation", 4), ("unseen", 8))})
            private = private_selection(selected)
            for task in private["tasks"]:
                with self.subTest(task=task["task_id"]):
                    self.assertTrue(validate_baseline(task)["valid"])
                    report = evaluate_bundle(private["references"][task["task_id"]], "api.py", "run",
                        task["public_cases"] + task["hidden_cases"], allowed_files=task["files"],
                        import_graph=declared_import_graph(task["files"]))
                    self.assertEqual(report["status"], "evaluated")
                    self.assertEqual(report["passed"], report["total"])

    def test_content_hashes_match_learning_dataset_and_ignore_fresh_labels(self):
        selection = self.selection()
        rows = {row["task_id"]: row for row in self.catalog["rows"]}
        splits = {("train" if split == "practice" else split): [rows[tid]["public_task"] for tid in ids]
                  for split, ids in selection["splits"].items()}
        source = {tid: {"kind": "synthetic-authored", "source_manifest_sha256": self.catalog["curriculum_sha256"]}
                  for values in selection["splits"].values() for tid in values}
        dataset = freeze_learning_dataset(splits, source)
        for values in dataset["splits"].values():
            for row in values:
                for key in ("content_sha256", "normalized_content_sha256"):
                    self.assertEqual(row[key], rows[row["task_id"]][key])
        bad = copy.deepcopy(selection)
        bad["splits"]["validation"][0] = "fresh-id-for-old-problem"
        with self.assertRaises(DojoCurriculumError):
            private_selection(bad)
        bad = copy.deepcopy(selection)
        bad["selection_sha256"] = "a" * 64
        with self.assertRaises(DojoCurriculumError):
            private_selection(bad)

    def test_conservative_near_duplicate_groups_cannot_span_splits(self):
        unique = [row["task_id"] for row in self.catalog["rows"] if row["family_id"] == "stable-unique"]
        intersection = [row["task_id"] for row in self.catalog["rows"] if row["family_id"] == "ordered-intersection"]
        with self.assertRaisesRegex(DojoCurriculumError, "near-duplicate"):
            make_selection(self.catalog, {"practice": unique, "validation": intersection, "unseen": self.ids[:2]})
        for value in ([], [True, False], [self.ids[0], self.ids[0]]):
            with self.subTest(value=value), self.assertRaises(DojoCurriculumError):
                make_selection(self.catalog, {"practice": value, "validation": self.ids[2:4], "unseen": self.ids[4:6]})


if __name__ == "__main__":
    unittest.main()
