"""Learning split/firewall controls; no source execution, model or network."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from xnet.learning_dataset import (LearningDatasetError, freeze_learning_dataset,
                                   verify_learning_dataset)
from xnet.protocol import digest


def public_task(task_id, n):
    return {"task_id": task_id, "category": "bounded-repair", "issue": "Repair case " + str(n),
        "files": {"api.py": "def run(value):\n    return value + " + str(n) + "\n"},
        "entry_file": "api.py", "entry_function": "run", "editable_files": ["api.py"],
        "api_contract": {"signature": "run(value)", "requirements": "Return value plus " + str(n),
            "dependencies": "Only builtins", "replacement_limit_bytes": 8192},
        "public_cases": [{"args": [n], "kwargs": {}, "case_type": "F2P",
            "case_id": task_id + "-1", "name": "run", "hidden": False, "expected": n * 2}]}


class LearningDatasetControls(unittest.TestCase):
    def setUp(self):
        self.splits = {split: [public_task(split + "-" + str(i), n + i)
                             for i in range(2)]
                       for split, n in (("train", 1), ("validation", 10), ("unseen", 20))}
        self.provenance = {task["task_id"]: {"kind": "synthetic-authored",
                          "source_manifest_sha256": "a" * 64}
                           for tasks in self.splits.values() for task in tasks}

    def freeze(self, **kwargs):
        return freeze_learning_dataset(self.splits, self.provenance, **kwargs)

    def test_roundtrip_and_exact_public_views(self):
        frozen = self.freeze(caller_source_sha256="b" * 64)
        self.assertEqual(verify_learning_dataset(frozen, expected_sha256=frozen["manifest_sha256"]), frozen)
        for split, tasks in self.splits.items():
            self.assertEqual([row["public_task"] for row in frozen["splits"][split]], tasks)
        self.assertTrue(frozen["public_only"])
        self.assertFalse(frozen["semantic_novelty_proven"])
        self.assertFalse(frozen["weights_updated"])

    def test_inputs_and_verified_copy_are_detached(self):
        frozen = self.freeze()
        verified = verify_learning_dataset(frozen)
        self.splits["train"][0]["files"]["api.py"] = "changed input"
        self.provenance["train-0"]["kind"] = "changed source"
        verified["splits"]["train"][0]["public_task"]["files"]["api.py"] = "changed copy"
        self.assertEqual(verify_learning_dataset(frozen), frozen)

    def test_manifest_edit_detected_and_external_pin_survives_resigning(self):
        frozen = self.freeze()
        bad = copy.deepcopy(frozen)
        bad["splits"]["train"][0]["public_task"]["issue"] = "edited"
        with self.assertRaises(LearningDatasetError):
            verify_learning_dataset(bad)
        fresh = self.freeze(caller_source_sha256="c" * 64)
        with self.assertRaises(LearningDatasetError):
            verify_learning_dataset(fresh, expected_sha256=frozen["manifest_sha256"])

    def test_rehashed_internal_task_pin_and_flags_cannot_launder_edit(self):
        for field, replacement in (("content_sha256", "b" * 64), ("derived", 0),
                                   ("raw_repo_benchmark", True), ("task_id", "other")):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.freeze())
                bad["splits"]["unseen"][0][field] = replacement
                body = {k: v for k, v in bad.items() if k != "manifest_sha256"}
                bad["manifest_sha256"] = digest(body)
                with self.assertRaises(LearningDatasetError):
                    verify_learning_dataset(bad)

    def test_hidden_and_reference_fields_refused_at_any_depth(self):
        for key, value in (("hidden_cases", []), ("reference", "source"),
                ("referenceAnswer", 7), ("reference_sha256", "a" * 64),
                ("ＧＯＬＤ_source", "source"), ("gold_patch", "source"), ("solution", "source"),
                ("api-key", "secret"), ("credentials", {}), ("hidden", False)):
            with self.subTest(key=key):
                splits = copy.deepcopy(self.splits)
                splits["train"][0]["public_cases"][0]["args"] = [{"nested": {key: value}}]
                with self.assertRaises(LearningDatasetError):
                    freeze_learning_dataset(splits, self.provenance)
        for key in ("hidden_cases", "reference_files"):
            splits = copy.deepcopy(self.splits)
            splits["unseen"][0][key] = {}
            with self.assertRaises(LearningDatasetError):
                freeze_learning_dataset(splits, self.provenance)

    def test_public_hidden_marker_requires_exact_false(self):
        for value in (0, True, "false", None):
            with self.subTest(value=value):
                self.splits["train"][0]["public_cases"][0]["hidden"] = value
                with self.assertRaises(LearningDatasetError):
                    self.freeze()

    def test_exact_duplicate_renamed_id_and_case_id_refused_cross_split(self):
        copied = copy.deepcopy(self.splits["train"][0])
        copied["task_id"] = "validation-0"
        copied["public_cases"][0]["case_id"] = "renamed-case"
        self.splits["validation"][0] = copied
        with self.assertRaisesRegex(LearningDatasetError, "duplicate public content"):
            self.freeze()

    def test_normalized_duplicate_case_whitespace_refused_cross_split(self):
        copied = copy.deepcopy(self.splits["train"][0])
        copied["task_id"] = "unseen-0"
        copied["public_cases"][0]["case_id"] = "renamed-case"
        copied["issue"] = "  REPAIR\n CASE   1  "
        copied["files"]["api.py"] = "DEF RUN(VALUE):\n RETURN VALUE + 1\n"
        self.splits["unseen"][0] = copied
        with self.assertRaisesRegex(LearningDatasetError, "duplicate public content"):
            self.freeze()

    def test_known_prior_holdout_exact_and_normalized_hash_refused(self):
        prior = self.freeze()["splits"]["validation"][0]
        for field in ("content_sha256", "normalized_content_sha256"):
            with self.subTest(field=field), self.assertRaisesRegex(LearningDatasetError, "prior evaluated"):
                self.freeze(denied_content_sha256=[prior[field]])

    def test_retired_known_content_is_allowed_in_train(self):
        prior = self.freeze()["splits"]["train"][0]
        frozen = self.freeze(denied_content_sha256=[prior["content_sha256"], prior["normalized_content_sha256"]])
        self.assertEqual(verify_learning_dataset(frozen), frozen)

    def test_cluster_requires_pinned_provenance_and_must_not_span_splits(self):
        assignments = {"train-0": "near-cluster", "train-1": "near-cluster"}
        evidence = {"method_id": "review-v1", "source_sha256": "b" * 64,
                    "assignment_sha256": digest(assignments)}
        with self.assertRaises(LearningDatasetError):
            self.freeze(clusters=assignments)
        frozen = self.freeze(clusters=assignments, cluster_provenance=evidence)
        self.assertEqual(verify_learning_dataset(frozen), frozen)
        self.assertFalse(frozen["semantic_novelty_proven"])
        evidence["assignment_sha256"] = "c" * 64
        with self.assertRaises(LearningDatasetError):
            self.freeze(clusters=assignments, cluster_provenance=evidence)
        assignments["unseen-0"] = "near-cluster"
        evidence["assignment_sha256"] = digest(assignments)
        with self.assertRaisesRegex(LearningDatasetError, "cluster crosses splits"):
            self.freeze(clusters=assignments, cluster_provenance=evidence)

    def test_known_prior_cluster_refused_for_new_holdout_ids(self):
        assignments = {"unseen-0": "retired-cluster"}
        evidence = {"method_id": "review-v1", "source_sha256": "b" * 64,
                    "assignment_sha256": digest(assignments)}
        with self.assertRaisesRegex(LearningDatasetError, "prior evaluated"):
            self.freeze(clusters=assignments, cluster_provenance=evidence,
                        denied_cluster_ids=["retired-cluster"])

    def test_derived_provenance_pins_and_label_remain_honest(self):
        self.provenance["train-0"] = {"kind": "pattern-derived", "source_manifest_sha256": "a" * 64,
            "original_change_sha256": "b" * 64, "transform_sha256": "c" * 64}
        row = self.freeze()["splits"]["train"][0]
        self.assertTrue(row["derived"])
        self.assertFalse(row["raw_repo_benchmark"])
        self.provenance["train-0"].pop("transform_sha256")
        with self.assertRaises(LearningDatasetError):
            self.freeze()
        self.provenance["train-0"]["kind"] = "raw-repo-benchmark"
        with self.assertRaises(LearningDatasetError):
            self.freeze()

    def test_strict_bounds_ids_and_types(self):
        changes = (lambda s: s["train"].pop(),
                   lambda s: s.update(extra=[]),
                   lambda s: s["train"][0].update(task_id="../escape"),
                   lambda s: s["train"][0].update(task_id=True),
                   lambda s: s["train"][0]["api_contract"].update(replacement_limit_bytes=True),
                   lambda s: s["train"][0]["files"].update({"../outside.py": "pass"}))
        for change in changes:
            with self.subTest(change=change):
                splits = copy.deepcopy(self.splits)
                change(splits)
                with self.assertRaises(LearningDatasetError):
                    freeze_learning_dataset(splits, self.provenance)
        splits = copy.deepcopy(self.splits)
        splits["train"] = [public_task("many-" + str(i), 100 + i) for i in range(51)]
        with self.assertRaises(LearningDatasetError):
            freeze_learning_dataset(splits, self.provenance)

    def test_exact_string_subclasses_and_nonfinite_values_refused(self):
        class Text(str):
            pass
        for value in (Text("train-0"), None, 1):
            with self.subTest(value=value):
                splits = copy.deepcopy(self.splits)
                splits["train"][0]["task_id"] = value
                with self.assertRaises(LearningDatasetError):
                    freeze_learning_dataset(splits, self.provenance)
        self.splits["train"][0]["public_cases"][0]["expected"] = float("nan")
        with self.assertRaises(LearningDatasetError):
            self.freeze()

    def test_source_helper_change_refused(self):
        frozen = self.freeze()
        with patch("xnet.learning_dataset._source_pins", return_value={"learning_dataset.py": "a" * 64}):
            with self.assertRaisesRegex(LearningDatasetError, "source/helper identity"):
                verify_learning_dataset(frozen)

    def test_denylist_and_provenance_exact_types(self):
        for kwargs in ({"caller_source_sha256": True}, {"denied_content_sha256": "a" * 64},
                {"denied_content_sha256": [True]}, {"denied_cluster_ids": [True]},
                {"clusters": {"unknown": "cluster"}}, {"cluster_provenance": {}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(LearningDatasetError):
                self.freeze(**kwargs)
        for value in (True, "true", 12):
            with self.subTest(value=value):
                provenance = copy.deepcopy(self.provenance)
                provenance["train-0"]["source_manifest_sha256"] = value
                with self.assertRaises(LearningDatasetError):
                    freeze_learning_dataset(self.splits, provenance)


if __name__ == "__main__":
    unittest.main()
