"""Restricted evaluator checks; candidate source never reaches Python exec."""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from xnet.repair_evaluator import _evaluate, evaluate_source
from xnet.repair_suite import make_suite


def case(args, expected=None, *, name="solve", kind="F2P", raises=None, kwargs=None):
    result = {"case_id": "test-" + kind, "name": name, "args": args,
              "kwargs": kwargs or {}, "case_type": kind, "hidden": True}
    result["raises" if raises else "expected"] = raises if raises else expected
    return result


class RepairEvaluatorTests(unittest.TestCase):
    def test_subprocess_legitimate_repair_and_exact_case_ids(self):
        source = "def solve(text):\n    return [field.strip() for field in text.split(',')]\n"
        cases = [case(["a, b ,c"], ["a", "b", "c"]), case(["a,,b"], ["a", "", "b"], kind="P2P")]
        result = evaluate_source(source, cases)
        self.assertEqual(result["status"], "evaluated")
        self.assertTrue(result["resolved"])
        self.assertEqual(result["passed"], 2)
        self.assertEqual([row["case_id"] for row in result["cases"]], [item["case_id"] for item in cases])
        self.assertEqual(result["fail_to_pass"], {"passed": 1, "total": 1})
        self.assertEqual(result["pass_to_pass"], {"passed": 1, "total": 1})
        self.assertNotIn("expected", result["cases"][0])
        self.assertNotIn("args", result["cases"][0])
        self.assertFalse(result["os_sandbox"])

    def test_every_authored_baseline_preserves_known_classification(self):
        counts = {"F2P": 0, "P2P": 0}
        for task in make_suite():
            result = _evaluate(task["buggy_source"], task["cases"])
            with self.subTest(task=task["task_id"]):
                self.assertEqual(result["status"], "evaluated")
                self.assertFalse(result["resolved"])
                for row, original in zip(result["cases"], task["cases"]):
                    self.assertEqual(row["case_id"], original["case_id"])
                    self.assertIs(row["passed"], row["case_type"] == "P2P")
                    counts[row["case_type"]] += 1
        self.assertEqual(counts, {"F2P": 99, "P2P": 99})

    def test_helpers_defaults_keywords_loops_and_methods(self):
        source = '''
def normalized(text):
    return text.strip().lower()
def solve(values, prefix="x"):
    counts = {}
    seen = set()
    result = []
    for value in values:
        value = normalized(value)
        counts[value] = counts.get(value, 0) + 1
        if value in seen:
            continue
        seen.add(value)
        result.append(prefix + value)
    result.sort()
    return {"items": result, "counts": counts}
'''
        expected = {"items": ["!a", "!b"], "counts": {"a": 2, "b": 1}}
        self.assertTrue(_evaluate(source, [case([[" A", "b ", "a"]], expected, kwargs={"prefix": "!"})])["resolved"])

    def test_slicing_starred_zip_and_nested_comprehensions(self):
        source = "def solve(rows):\n    return [list(row)[::-1] for row in zip(*rows)]\n"
        self.assertTrue(_evaluate(source, [case([[[1, 2], [3, 4]]], [[3, 1], [4, 2]])])["resolved"])

    def test_pure_lambda_sort_key_and_builtin_type_checks(self):
        source = '''
def solve(values):
    if not isinstance(values, (list, tuple)):
        raise TypeError("list required")
    return sorted(values, key=lambda item: item[1], reverse=True)
'''
        result = _evaluate(source, [case([[["a", 1], ["b", 3]]], [["b", 3], ["a", 1]]),
                                    case([4], raises="TypeError", kind="P2P")])
        self.assertTrue(result["resolved"])

    def test_exception_names_must_match_exactly(self):
        result = _evaluate("def solve(x):\n    return 1 // x\n", [case([0], raises="ValueError"), case([0], raises="ZeroDivisionError", kind="P2P")])
        self.assertEqual([row["passed"] for row in result["cases"]], [False, True])
        self.assertFalse(result["resolved"])

    def test_tuple_return_does_not_satisfy_list_contract(self):
        for source in ("def solve():\n    return (1, 2)\n",
                       "def solve():\n    return {'items': (1, 2)}\n"):
            expected = {"items": [1, 2]} if "items" in source else [1, 2]
            result = _evaluate(source, [case([], expected)])
            self.assertFalse(result["resolved"])
            self.assertEqual(result["cases"][0]["status"], "wrong-answer")

    def test_case_mutation_cannot_change_expected_or_later_cases(self):
        source = "def solve(values):\n    values.append(2)\n    return values\n"
        cases = [case([[1]], [1, 2]), case([[1]], [1, 2], kind="P2P")]
        self.assertTrue(_evaluate(source, cases)["resolved"])
        self.assertEqual(cases[0]["args"], [[1]])
        self.assertEqual(cases[1]["args"], [[1]])

    def test_imports_dynamic_capabilities_and_attribute_reads_are_rejected(self):
        sources = [
            "import os\ndef solve():\n    return 1\n",
            "def solve():\n    return open('sentinel')\n",
            "def solve():\n    return __import__('os')\n",
            "def solve():\n    return (1).__class__\n",
            "def solve():\n    return str.lower\n",
            "def solve():\n    return getattr('x', 'lower')()\n",
            "def solve():\n    return eval('1')\n",
            "def solve():\n    return globals()\n",
            "def solve():\n    return '{}'.format(1)\n",
            "def solve():\n    return 'abc'.encode()\n",
            "class X:\n    pass\ndef solve():\n    return 1\n",
            "@str\ndef solve():\n    return 1\n",
            "def solve():\n    yield 1\n",
        ]
        for source in sources:
            with self.subTest(source=source):
                result = _evaluate(source, [case([], 1)])
                self.assertEqual(result["status"], "rejected")
                self.assertFalse(result["resolved"])

    def test_allowed_method_name_does_not_expose_other_object_attributes(self):
        result = _evaluate("def solve():\n    return (1).get('x')\n", [case([], None)])
        self.assertFalse(result["resolved"])
        self.assertEqual(result["cases"][0]["error_type"], "CandidateRejected")

    def test_loop_recursion_and_expansion_have_finite_budgets(self):
        sources = [
            "def solve():\n    while True:\n        pass\n",
            "def solve():\n    return solve()\n",
            "def solve():\n    return 'x' * 1000000000\n",
            "def solve():\n    return list(range(1000000000))\n",
            "def solve():\n    return 2 ** 1000000000\n",
            "def solve():\n    return 'a' * 65536 + 'b'\n",
            "def solve():\n    return ('a' * 65536).replace('a', 'x' * 65536, -1)\n",
            "def solve():\n    return str(['x' * 65536] * 10000)\n",
            "def solve():\n    x = []\n    x.append(x)\n    return x\n",
        ]
        for source in sources:
            with self.subTest(source=source):
                result = _evaluate(source, [case([], None)])
                self.assertFalse(result["resolved"])
                self.assertEqual(result["cases"][0]["error_type"], "EvaluationLimit")

    def test_validation_rejects_nonhidden_or_unbounded_cases(self):
        malformed = [[], [dict(case([], 1), hidden=False)], [dict(case([], 1), case_type="other")],
                     [dict(case([], 1), raises="ValueError")], [dict(case([], 1), case_id="")],
                     [case([], raises="BaseException")]]
        for cases in malformed:
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                evaluate_source("def solve():\n    return 1\n", cases)

    def test_worker_timeout_is_recorded_failure(self):
        with mock.patch("xnet.repair_evaluator.subprocess.run", side_effect=subprocess.TimeoutExpired("fixed", 3)):
            result = evaluate_source("def solve():\n    return 1\n", [case([], 1)])
        self.assertEqual(result["status"], "timed-out")
        self.assertFalse(result["resolved"])
        self.assertEqual(result["total"], 1)

    def test_fixed_worker_uses_isolated_python_and_stdin_not_candidate_command(self):
        source = "def solve():\n    return 1\n"
        with mock.patch("xnet.repair_evaluator.subprocess.run", wraps=subprocess.run) as run:
            self.assertTrue(evaluate_source(source, [case([], 1)])["resolved"])
        args, kwargs = run.call_args
        self.assertEqual(args[0][1:4], ["-I", "-S", "-B"])
        self.assertEqual(args[0][-1], "--worker")
        self.assertNotIn(source, args[0])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["timeout"], 3)


if __name__ == "__main__":
    unittest.main()
