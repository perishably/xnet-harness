"""Freeze fixture diversity, visibility boundaries, and baseline classifications."""
from __future__ import annotations

import ast
import collections
import json
import unittest

from xnet.repair_suite import make_suite as previous_suite
from xnet.swe_repair_evaluator import declared_import_graph, validate_baseline
from xnet.swe_repair_suite import DEFAULT_SEED, PUBLIC_FIELDS, build_swe_repair_suite, public_task


def normalized_bundle(files):
    """Reject copies that differ only in function names or local identifiers."""
    functions = {}
    for path in sorted(files):
        for node in ast.parse(files[path]).body:
            if isinstance(node, ast.FunctionDef):
                functions.setdefault(node.name, "function" + str(len(functions)))

    class Normalize(ast.NodeTransformer):
        def __init__(self):
            self.locals = {}

        def local(self, name):
            if name in functions:
                return functions[name]
            self.locals.setdefault(name, "variable" + str(len(self.locals)))
            return self.locals[name]

        def visit_FunctionDef(self, node):
            node.name = functions[node.name]
            self.locals = {}
            return self.generic_visit(node)

        def visit_arg(self, node):
            node.arg = self.local(node.arg)
            return node

        def visit_Name(self, node):
            # Builtins keep their semantics; locals and function names are scrubbed.
            if node.id not in {"sum", "max", "min", "sorted", "set", "range", "len", "int",
                               "abs", "zip", "reversed", "any", "all", "isinstance",
                               "dict", "ValueError", "str", "enumerate"}:
                node.id = self.local(node.id)
            return node

    shapes = []
    for path in sorted(files):
        tree = ast.parse(files[path])
        tree.body = [node for node in tree.body if not isinstance(node, ast.ImportFrom)]
        shapes.append(ast.dump(Normalize().visit(tree), include_attributes=False))
    return "\n".join(shapes)


class SWERepairSuiteTests(unittest.TestCase):
    def test_fifty_fresh_unique_tasks_with_ten_real_families(self):
        tasks = build_swe_repair_suite()
        self.assertEqual(len(tasks), 50)
        for field in ("task_id", "issue"):
            self.assertEqual(len({task[field] for task in tasks}), 50)
        counts = collections.Counter(task["category"] for task in tasks)
        self.assertEqual(len(counts), 10)
        self.assertEqual(set(counts.values()), {5})
        self.assertEqual(len({normalized_bundle(task["files"]) for task in tasks}), 50)
        prior = previous_suite()
        self.assertTrue({task["task_id"] for task in tasks}.isdisjoint(task["task_id"] for task in prior))
        prior_sources = {task["buggy_source"] for task in prior}
        self.assertFalse(any(source in prior_sources for task in tasks for source in task["files"].values()))

    def test_every_bundle_is_small_and_has_a_reachable_local_module_graph(self):
        three_file_count = 0
        for task in build_swe_repair_suite():
            with self.subTest(task=task["task_id"]):
                files = task["files"]
                self.assertTrue(2 <= len(files) <= 4)
                three_file_count += len(files) >= 3
                self.assertLessEqual(sum(len(source) for source in files.values()), 3000)
                self.assertLessEqual(len(json.dumps(public_task(task))), 5000)
                self.assertEqual(set(task["editable_files"]), set(files))
                self.assertIn(task["entry_file"], files)
                self.assertTrue(task["api_contract"]["signature"].startswith(task["entry_function"] + "("))
                graph = declared_import_graph(files)
                reached = set()

                def walk(path):
                    if path in reached:
                        return
                    reached.add(path)
                    for dependency in graph[path]:
                        walk(dependency["module"] + ".py")

                walk(task["entry_file"])
                self.assertEqual(reached, set(files))
                self.assertTrue(graph[task["entry_file"]])
        self.assertGreaterEqual(three_file_count, 3)

    def test_exactly_300_portable_cases_with_balanced_visible_and_held_out_groups(self):
        identifiers = set()
        totals = collections.Counter()
        for task in build_swe_repair_suite():
            for key, size, hidden in (("public_cases", 2, False), ("hidden_cases", 4, True)):
                cases = task[key]
                self.assertEqual(len(cases), size)
                self.assertEqual(collections.Counter(case["case_type"] for case in cases),
                                 {"F2P": size // 2, "P2P": size // 2})
                for case in cases:
                    self.assertIs(case["hidden"], hidden)
                    self.assertEqual(case["name"], task["entry_function"])
                    self.assertIsInstance(case["args"], list)
                    self.assertIsInstance(case["kwargs"], dict)
                    self.assertEqual(sum(name in case for name in ("expected", "raises")), 1)
                    self.assertNotIn(case["case_id"], identifiers)
                    identifiers.add(case["case_id"])
                    totals[key] += 1
            self.assertEqual(json.loads(json.dumps(task, allow_nan=False)), task)
        self.assertEqual(totals, {"public_cases": 100, "hidden_cases": 200})
        self.assertEqual(len(identifiers), 300)

    def test_every_baseline_fails_all_f2p_and_preserves_all_p2p(self):
        for task in build_swe_repair_suite():
            with self.subTest(task=task["task_id"]):
                report = validate_baseline(task)
                self.assertTrue(report["valid"], report)

    def test_model_projection_excludes_grader_data_and_is_an_independent_copy(self):
        for task in build_swe_repair_suite():
            projected = public_task(task)
            self.assertEqual(set(projected), set(PUBLIC_FIELDS))
            self.assertNotIn("hidden_cases", projected)
            self.assertNotIn("case_rationale", projected)
            self.assertNotIn("fixture_version", projected)
            for forbidden in ("gold_patch", "gold_source", "repaired_source"):
                self.assertNotIn(forbidden, task)
            self.assertTrue(all(case["hidden"] is False for case in projected["public_cases"]))
            projected["files"]["api.py"] = "mutated"
            projected["public_cases"][0]["args"].append("mutated")
            self.assertNotEqual(projected, public_task(task))

    def test_seed_changes_order_only_and_builds_fresh_data(self):
        tasks = build_swe_repair_suite(DEFAULT_SEED)
        self.assertEqual(tasks, build_swe_repair_suite(DEFAULT_SEED))
        other = build_swe_repair_suite(DEFAULT_SEED + 1)
        self.assertNotEqual([task["task_id"] for task in tasks], [task["task_id"] for task in other])
        self.assertEqual({task["task_id"]: task for task in tasks}, {task["task_id"]: task for task in other})
        tasks[0]["hidden_cases"][0]["args"].append("mutation")
        self.assertNotEqual(tasks, build_swe_repair_suite(DEFAULT_SEED))
        for seed in (True, -1, 2 ** 63, "20261005", None):
            with self.assertRaises(ValueError):
                build_swe_repair_suite(seed)


if __name__ == "__main__":
    unittest.main()
