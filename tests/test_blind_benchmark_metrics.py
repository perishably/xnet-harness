"""Metric coverage for the frozen Blind Repair benchmark."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xnet.blind_repair_benchmark import freeze, grade, prepare, run, summarize
from xnet.protocol import canonical


def _case(case_id, value, expected, *, kind="F2P", hidden=False):
    return {"case_id": case_id, "name": "solve", "args": [value], "kwargs": {},
            "case_type": kind, "hidden": hidden, "expected": expected}


def _task():
    return {
        "task_id": "blind-metrics-001", "category": "boundary",
        "issue": "Positive values are incremented even though only negative values should clamp to zero.",
        "files": {
            "api.py": "from helper import clamp\n\ndef solve(value):\n    return clamp(value)\n",
            "helper.py": "def clamp(value):\n    if value < 0:\n        return 0\n    return value + 1\n",
        },
        "entry_file": "api.py", "entry_function": "solve",
        "editable_files": ["api.py", "helper.py"],
        "api_contract": {
            "signature": "solve(value)",
            "requirements": ["negative values clamp to zero", "nonnegative values remain unchanged"],
            "dependencies": "Python builtins and declared local imports only",
            "replacement_limit_bytes": 8192,
        },
        "public_cases": [_case("public-f2p", 2, 2),
                         _case("public-p2p", -1, 0, kind="P2P")],
    }


def _hidden():
    return {"schema": "xnet.blind-repair50.hidden.v1", "tasks": [{
        "task_id": "blind-metrics-001",
        "hidden_cases": [
            _case("hidden-f2p-1", 1, 1, hidden=True),
            _case("hidden-f2p-2", 100, 100, hidden=True),
            _case("hidden-p2p-1", -2, 0, kind="P2P", hidden=True),
            _case("hidden-p2p-2", -100, 0, kind="P2P", hidden=True),
        ],
    }]}


def _protocol():
    return {
        "schema": "xnet.blind-repair50.protocol.v1",
        "benchmark_name": "metric fixture",
        "benchmark_kind": "custom frozen SWE-style multi-file repair benchmark",
        "official_swe_bench": False, "base_commit": "0" * 40, "task_count": 1,
        "lanes": ["raw", "retrieval", "full-xnet"],
        "inference": {"temperature": 0, "seed": 0, "max_output_tokens": 650,
                      "max_attempts": 2, "stateless_calls": True,
                      "cross_task_kv_reuse": False, "hidden_feedback": False},
        "success_gate": {"full_minus_raw_minimum_solves": 0,
                         "full_minus_retrieval_minimum_solves": 0,
                         "p2p_preservation_minimum_tasks": 1,
                         "maximum_hidden_or_retrieval_leaks": 0,
                         "maximum_candidate_host_executions": 0,
                         "full_lane_median_task_seconds_maximum": 1,
                         "full_to_raw_total_token_ratio_maximum": 1,
                         "confirmatory_full_minus_raw_minimum_solves": 0},
    }


def _corpus():
    return {"schema": "xnet.repair-card-corpus.v1", "cards": [
        {"id": "boundary-contract", "tags": ["boundary", "comparison"],
         "text": "Translate each boundary word into an explicit comparison and test equality."},
        {"id": "preserve-passing", "tags": ["preserve", "passing"],
         "text": "Keep behavior already established by passing public cases."},
        {"id": "narrow-change", "tags": ["repair", "source"],
         "text": "Change the narrowest helper that owns the broken rule."},
    ]}


class _Fixture:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.public = self._write(
            "public.json", {"schema": "xnet.blind-repair50.public.v1", "tasks": [_task()]})
        self.hidden = self._write("hidden.json", _hidden())
        self.protocol = self._write("protocol.json", _protocol())
        self.corpus = self._write("corpus.json", _corpus())
        self.profile = self._write("provider.json", {
            "schema": "xnet.local-provider-profile.v1", "base_url": "http://127.0.0.1:18096/v1",
            "model": "unit-4b", "model_sha256": "1" * 64, "runtime_sha256": "2" * 64,
            "context_tokens": 8192, "max_output_tokens": 650, "temperature": 0, "seed": 0,
        })
        self.run_root = self.directory / "run"

    def _write(self, name, value):
        path = self.directory / name
        path.write_bytes(canonical(value) + b"\n")
        return path

    def prepare(self):
        return prepare(self.run_root, public_suite=self.public,
                       hidden_suite_sha256=hashlib.sha256(self.hidden.read_bytes()).hexdigest(),
                       protocol=self.protocol, corpus=self.corpus, provider_profile=self.profile)


class _Generator:
    fixed_source = "def clamp(value):\n    if value < 0:\n        return 0\n    return value\n"
    original_source = "def clamp(value):\n    if value < 0:\n        return 0\n    return value + 1\n"

    def __init__(self, *, optional_metrics=True, modes=None):
        self.optional_metrics = optional_metrics
        self.modes = modes or {}

    def __call__(self, messages, **options):
        mode = self.modes.get(options["lane"], "fixed")
        if mode == "schema-error":
            text = "{"
        else:
            source = self.original_source if mode == "no-op" else self.fixed_source
            text = json.dumps({"files": {"helper.py": source}}, separators=(",", ":"))
        provider_request = {"model": "unit-4b", "messages": messages, "max_tokens": 650,
                            "temperature": 0, "seed": 0, "stream": False}
        usage = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
        timing = {"prompt_seconds": 0.01, "decode_seconds": 0.02,
                  "ttft_seconds": 0.005, "total_seconds": 0.03}
        speculative = {"drafted_tokens": 2, "accepted_tokens": 1}
        result = {
            "text": text, "usage": usage, "timing": timing,
            "transport": {"request_sha256": hashlib.sha256(canonical(provider_request)).hexdigest(),
                          "response_sha256": hashlib.sha256(text.encode()).hexdigest(), "status": 200},
            "speculative": speculative,
        }
        if self.optional_metrics:
            usage["cached_input_tokens"] = 4
            result["throughput"] = {"prompt_tokens_per_second": 100.0,
                                    "decode_tokens_per_second": 50.0}
        else:
            timing.update(prompt_seconds=None, decode_seconds=None,
                          ttft_seconds=None, total_seconds=None)
            speculative.update(drafted_tokens=None, accepted_tokens=None)
        return result


class BlindBenchmarkMetricTests(unittest.TestCase):
    def _complete(self, fixture, generator):
        fixture.prepare()
        attempts = run(fixture.run_root, generator)
        freeze(fixture.run_root)
        graded = grade(fixture.run_root, fixture.hidden)
        return attempts, graded, summarize(fixture.run_root)

    def test_grade_and_summary_cover_cases_costs_retrieval_and_provider_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            attempts, graded, summary = self._complete(_Fixture(directory), _Generator())

        self.assertEqual(len(attempts), 3)
        for row in graded["scores"]:
            for phase in ("first", "final"):
                counts = row[phase]["case_counts"]
                self.assertEqual(counts["public"]["F2P"], {"passed": 1, "failed": 0, "total": 1})
                self.assertEqual(counts["public"]["P2P"], {"passed": 1, "failed": 0, "total": 1})
                self.assertEqual(counts["hidden"]["F2P"], {"passed": 2, "failed": 0, "total": 2})
                self.assertEqual(counts["hidden"]["P2P"], {"passed": 2, "failed": 0, "total": 2})

        raw = summary["lanes"]["raw"]
        self.assertEqual(raw["case_counts"]["final"]["hidden"]["F2P"]["passed"], 2)
        self.assertEqual(raw["observed_tokens"], {"input_tokens": 10, "output_tokens": 5,
                                                  "total_tokens": 15, "cached_input_tokens": 4})
        self.assertEqual(raw["known_token_counts"], {key: 1 for key in raw["observed_tokens"]})
        self.assertEqual(raw["unknown_token_counts"], {key: 0 for key in raw["observed_tokens"]})
        self.assertEqual(raw["throughput"]["prompt_tokens_per_second"]["mean"], 100.0)
        self.assertEqual(raw["speculative"]["observed_tokens"],
                         {"drafted_tokens": 2, "accepted_tokens": 1})
        self.assertEqual(raw["speculative"]["acceptance_rate"], 0.5)
        for metric in ("provider_generation_seconds", "callback_seconds",
                       "admission_seconds", "e2e_seconds"):
            self.assertEqual(raw["timing"][metric]["known_calls"], 1)
            self.assertIsNotNone(raw["timing"][metric]["total"])
        self.assertEqual(raw["seconds_per_joint_solve"], raw["total_e2e_seconds"])
        self.assertEqual(raw["retrieval"]["card_count"], 0)
        self.assertEqual(summary["lanes"]["retrieval"]["retrieved_cards"], 2)
        self.assertEqual(summary["lanes"]["full-xnet"]["retrieved_cards"], 1)
        self.assertGreater(summary["lanes"]["retrieval"]["retrieved_bytes"], 0)
        self.assertGreater(summary["lanes"]["retrieval"]["retrieval"]["capsule_bytes"], 0)

    def test_absent_optional_provider_metrics_remain_explicit_unknowns(self):
        with tempfile.TemporaryDirectory() as directory:
            attempts, _, summary = self._complete(
                _Fixture(directory), _Generator(optional_metrics=False))

        generation = attempts[0]["generation"]
        self.assertIsNone(generation["usage"]["cached_input_tokens"])
        self.assertEqual(generation["throughput"],
                         {"decode_tokens_per_second": None, "prompt_tokens_per_second": None})
        raw = summary["lanes"]["raw"]
        self.assertIsNone(raw["observed_tokens"]["cached_input_tokens"])
        self.assertEqual(raw["known_token_counts"]["cached_input_tokens"], 0)
        self.assertEqual(raw["unknown_token_counts"]["cached_input_tokens"], 1)
        self.assertIsNone(raw["timing"]["provider_generation_seconds"]["total"])
        self.assertEqual(raw["timing"]["provider_generation_seconds"]["unknown_calls"], 1)
        self.assertIsNone(raw["throughput"]["decode_tokens_per_second"]["mean"])
        self.assertEqual(raw["throughput"]["decode_tokens_per_second"]["unknown_calls"], 1)
        self.assertEqual(raw["speculative"]["observed_tokens"],
                         {"drafted_tokens": None, "accepted_tokens": None})
        self.assertIsNone(raw["speculative"]["acceptance_rate"])
        self.assertIsNotNone(raw["total_callback_seconds"])
        self.assertIsNotNone(raw["total_admission_seconds"])
        self.assertIsNotNone(raw["total_e2e_seconds"])

    def test_attempt_outcomes_distinguish_supported_counts_and_unknown_abstentions(self):
        timeout_report = {"schema_version": "xnet.swe-repair-evaluation.v1",
                          "visibility": "public", "status": "timed-out", "resolved": False,
                          "passed": 0, "total": 2, "cases": [],
                          "error": "fixed evaluator subprocess exceeded timeout"}
        generator = _Generator(modes={"raw": "schema-error", "retrieval": "no-op"})
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            with patch("xnet.blind_repair_benchmark.evaluate_bundle", return_value=timeout_report):
                run(fixture.run_root, generator)
            freeze(fixture.run_root)
            grade(fixture.run_root, fixture.hidden)
            summary = summarize(fixture.run_root)

        raw = summary["lanes"]["raw"]["outcome_counts"]
        retrieval = summary["lanes"]["retrieval"]["outcome_counts"]
        full = summary["lanes"]["full-xnet"]["outcome_counts"]
        self.assertEqual(raw["schema_errors"], 2)
        self.assertEqual(retrieval["no_ops"], 2)
        self.assertEqual(full["timeouts"], 2)
        self.assertEqual(full["errors"], 0)
        self.assertIsNone(full["abstentions"])
        self.assertIn("abstentions", full["unknown_metrics"])
        self.assertEqual(summary["lanes"]["full-xnet"]["case_counts"]["final"]
                         ["hidden"]["P2P"], {"passed": 0, "failed": 2, "total": 2})


if __name__ == "__main__":
    unittest.main()
