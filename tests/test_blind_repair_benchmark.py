"""Lifecycle, lane-boundary and tamper tests for Blind Repair 50."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from xnet.blind_repair_benchmark import (
    BenchmarkError,
    PendingGeneration,
    _parse_candidate,
    build_messages,
    freeze,
    grade,
    prepare,
    run,
    summarize,
)
from xnet.protocol import canonical


def _case(case_id, value, expected, *, kind="F2P", hidden=False):
    return {
        "case_id": case_id,
        "name": "solve",
        "args": [value],
        "kwargs": {},
        "case_type": kind,
        "hidden": hidden,
        "expected": expected,
    }


def _task():
    return {
        "task_id": "blind-unit-001",
        "category": "boundary",
        "issue": "Positive values are incremented even though only negative values should clamp to zero.",
        "files": {
            "api.py": "from helper import clamp\n\ndef solve(value):\n    return clamp(value)\n",
            "helper.py": "def clamp(value):\n    if value < 0:\n        return 0\n    return value + 1\n",
        },
        "entry_file": "api.py",
        "entry_function": "solve",
        "editable_files": ["api.py", "helper.py"],
        "api_contract": {
            "signature": "solve(value)",
            "requirements": ["negative values clamp to zero", "nonnegative values remain unchanged"],
            "dependencies": "Python builtins and declared local imports only",
            "replacement_limit_bytes": 8192,
        },
        "public_cases": [
            _case("public-f2p", 2, 2),
            _case("public-p2p", -1, 0, kind="P2P"),
        ],
    }


def _hidden():
    return {
        "schema": "xnet.blind-repair50.hidden.v1",
        "tasks": [{
            "task_id": "blind-unit-001",
            "hidden_cases": [
                _case("hidden-f2p-1", 1, 1, hidden=True),
                _case("hidden-f2p-2", 100, 100, hidden=True),
                _case("hidden-p2p-1", -2, 0, kind="P2P", hidden=True),
                _case("hidden-p2p-2", -100, 0, kind="P2P", hidden=True),
            ],
        }],
    }


def _protocol():
    return {
        "schema": "xnet.blind-repair50.protocol.v1",
        "benchmark_name": "one-task lifecycle fixture",
        "benchmark_kind": "custom frozen SWE-style multi-file repair benchmark",
        "official_swe_bench": False,
        "base_commit": "0" * 40,
        "task_count": 1,
        "lanes": ["raw", "retrieval", "full-xnet"],
        "inference": {
            "temperature": 0,
            "seed": 0,
            "max_output_tokens": 650,
            "max_attempts": 2,
            "stateless_calls": True,
            "cross_task_kv_reuse": False,
            "hidden_feedback": False,
        },
        "success_gate": {
            "full_minus_raw_minimum_solves": 0,
            "full_minus_retrieval_minimum_solves": 0,
            "p2p_preservation_minimum_tasks": 1,
            "maximum_hidden_or_retrieval_leaks": 0,
            "maximum_candidate_host_executions": 0,
            "full_lane_median_task_seconds_maximum": 1,
            "full_to_raw_total_token_ratio_maximum": 1,
            "confirmatory_full_minus_raw_minimum_solves": 0,
        },
    }


def _corpus():
    return {
        "schema": "xnet.repair-card-corpus.v1",
        "cards": [
            {
                "id": "boundary-contract",
                "tags": ["boundary", "comparison"],
                "text": "Translate each boundary word into an explicit comparison and test equality.",
            },
            {
                "id": "preserve-passing",
                "tags": ["preserve", "passing"],
                "text": "Keep behavior already established by passing public cases.",
            },
            {
                "id": "narrow-change",
                "tags": ["repair", "source"],
                "text": "Change the narrowest helper that owns the broken rule.",
            },
        ],
    }


class _Fixture:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.public = self._write("public.json", {"schema": "xnet.blind-repair50.public.v1", "tasks": [_task()]})
        self.hidden = self._write("hidden.json", _hidden())
        self.protocol = self._write("protocol.json", _protocol())
        self.corpus = self._write("corpus.json", _corpus())
        self.profile = self._write("provider.json", {
            "schema": "xnet.local-provider-profile.v1",
            "base_url": "http://127.0.0.1:18096/v1",
            "model": "unit-4b",
            "model_sha256": "1" * 64,
            "runtime_sha256": "2" * 64,
            "context_tokens": 8192,
            "max_output_tokens": 650,
            "temperature": 0,
            "seed": 0,
        })
        self.run_root = self.directory / "run"

    def _write(self, name, value):
        path = self.directory / name
        path.write_bytes(canonical(value) + b"\n")
        return path

    @property
    def hidden_sha256(self):
        return hashlib.sha256(self.hidden.read_bytes()).hexdigest()

    def prepare(self, *, hidden_sha256=None):
        return prepare(
            self.run_root,
            public_suite=self.public,
            hidden_suite_sha256=hidden_sha256 or self.hidden_sha256,
            protocol=self.protocol,
            corpus=self.corpus,
            provider_profile=self.profile,
        )


class _Generator:
    def __init__(self, source=None):
        self.calls = []
        self.source = source or "def clamp(value):\n    if value < 0:\n        return 0\n    return value\n"

    def __call__(self, messages, **options):
        self.calls.append({"messages": copy.deepcopy(messages), "options": copy.deepcopy(options)})
        text = json.dumps({"files": {"helper.py": self.source}}, separators=(",", ":"))
        provider_request = {
            "model": "unit-4b",
            "messages": messages,
            "max_tokens": options["max_output_tokens"],
            "temperature": options["temperature"],
            "seed": options["seed"],
            "stream": False,
        }
        return {
            "text": text,
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            "timing": {"prompt_seconds": 0.01, "decode_seconds": 0.02,
                       "ttft_seconds": 0.01, "total_seconds": 0.03},
            "transport": {"request_sha256": hashlib.sha256(canonical(provider_request)).hexdigest(),
                          "response_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                          "status": 200},
            "speculative": {"drafted_tokens": 2, "accepted_tokens": 1},
        }


class BlindRepairBenchmarkTests(unittest.TestCase):
    def test_candidate_envelope_recovery_is_bounded_payload_preserving_and_recorded(self):
        task = _task()
        source = "def clamp(value):\n    return max(0, value)\n"
        exact = json.dumps({"files": {"helper.py": source}}, separators=(",", ":"))

        files, steps = _parse_candidate(exact, task, task["files"])
        self.assertEqual(files["helper.py"], source)
        self.assertEqual(steps, [])

        fenced = "```json\n" + exact + "\n```"
        files, steps = _parse_candidate(fenced, task, task["files"])
        self.assertEqual(files["helper.py"], source)
        self.assertEqual(steps, ["unwrap-single-json-fence"])

        missing_outer = exact[:-1]
        files, steps = _parse_candidate(missing_outer, task, task["files"])
        self.assertEqual(files["helper.py"], source)
        self.assertEqual(steps, ["append-missing-terminal-closers:}"])

        files, steps = _parse_candidate(
            "```json\n" + missing_outer + "\n```", task, task["files"])
        self.assertEqual(files["helper.py"], source)
        self.assertEqual(steps, ["unwrap-single-json-fence",
                                 "append-missing-terminal-closers:}"])

        rejected = [
            "explanation\n" + exact,
            fenced + "\ntrailing",
            exact[:-3],
            '{"files":{"helper.py":"unterminated}',
            '{"files":{"helper.py":"x"],',
            '{"files":{"helper.py":"x"},"files":{"helper.py":"y"}}',
        ]
        for candidate in rejected:
            with self.subTest(candidate=candidate):
                with self.assertRaises(BenchmarkError):
                    _parse_candidate(candidate, task, task["files"])

    def test_prepare_run_resume_freeze_grade_and_summarize_one_task(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            manifest = fixture.prepare()
            self.assertEqual(manifest["task_count"], 1)
            self.assertEqual(manifest["model_calls_during_prepare"], 0)
            self.assertFalse(manifest["hidden_suite_opened"])

            generator = _Generator()
            rows = run(fixture.run_root, generator)
            self.assertEqual(len(rows), 3)
            self.assertEqual(len(generator.calls), 3)
            self.assertTrue(all(row["public_evaluation"]["resolved"] for row in rows))

            def unexpected_generation(*_args, **_kwargs):
                self.fail("resume redispatched an already sealed generation")

            resumed = run(fixture.run_root, unexpected_generation)
            self.assertEqual([row["receipt_sha256"] for row in resumed],
                             [row["receipt_sha256"] for row in rows])

            choices = freeze(fixture.run_root)
            self.assertEqual(choices["choice_count"], 3)
            with self.assertRaisesRegex(BenchmarkError, "already frozen"):
                run(fixture.run_root, unexpected_generation)

            graded = grade(fixture.run_root, fixture.hidden)
            self.assertEqual(graded["model_calls"], 0)
            self.assertTrue(all(row["final"]["resolved"] for row in graded["scores"]))
            summary = summarize(fixture.run_root)
            self.assertEqual({lane: summary["lanes"][lane]["final_joint_solves"]
                              for lane in ("raw", "retrieval", "full-xnet")},
                             {"raw": 1, "retrieval": 1, "full-xnet": 1})
            self.assertTrue(summary["initial_gate_passed"])
            self.assertFalse(manifest["candidate_execution"])
            self.assertFalse(graded["candidate_execution"])

    def test_raw_retrieval_and_full_prompts_have_distinct_bounded_context(self):
        task, corpus = _task(), _corpus()
        raw, raw_evidence = build_messages(task, "raw", 1, task["files"], None, corpus)
        retrieval, retrieval_evidence = build_messages(
            task, "retrieval", 1, task["files"], None, corpus)
        full, full_evidence = build_messages(task, "full-xnet", 1, task["files"], None, corpus)
        full_retry, retry_evidence = build_messages(
            task, "full-xnet", 2, task["files"], {"passed": 1}, corpus)

        raw_body = json.loads(raw[1]["content"])
        retrieval_body = json.loads(retrieval[1]["content"])
        full_body = json.loads(full[1]["content"])
        self.assertNotIn("repair_cards", raw_body)
        self.assertEqual(raw_evidence["cards"], [])
        self.assertIn("repair_cards", retrieval_body)
        self.assertEqual(len(retrieval_evidence["cards"]), 2)
        self.assertIn("repair_cards", full_body)
        self.assertEqual(len(full_evidence["cards"]), 1)
        self.assertEqual(raw[0]["content"], retrieval[0]["content"])
        self.assertNotIn("XNET route", raw[0]["content"])
        self.assertNotIn("XNET route", retrieval[0]["content"])
        self.assertIn("XNET route", full[0]["content"])
        self.assertNotIn("Accordion retry", full[0]["content"])
        self.assertIn("Accordion retry", full_retry[0]["content"])
        self.assertEqual(len(retry_evidence["cards"]), 3)
        for evidence in (raw_evidence, retrieval_evidence, full_evidence, retry_evidence):
            self.assertFalse(evidence["hidden_data_used"])
            self.assertEqual(evidence["authority"], "none")

    def test_pending_reservation_is_not_redispatched_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            calls = []

            def interrupted(_messages, **_options):
                calls.append(True)
                raise RuntimeError("transport was lost after durable reservation")

            with self.assertRaisesRegex(RuntimeError, "transport was lost"):
                run(fixture.run_root, interrupted)
            self.assertEqual(len(calls), 1)
            with self.assertRaises(PendingGeneration):
                run(fixture.run_root, interrupted)
            self.assertEqual(len(calls), 1)

    def test_hidden_commitment_mismatch_is_rejected_even_after_grading(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            run(fixture.run_root, _Generator())
            freeze(fixture.run_root)
            grade(fixture.run_root, fixture.hidden)
            changed = _hidden()
            changed["tasks"][0]["hidden_cases"][0]["expected"] = 999
            mismatched = fixture._write("hidden-mismatch.json", changed)
            with self.assertRaisesRegex(BenchmarkError, "held-out suite differs"):
                grade(fixture.run_root, mismatched)

    def test_frozen_input_and_attempt_receipt_tampering_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            copied_public = fixture.run_root / "public-suite.json"
            value = json.loads(copied_public.read_text(encoding="utf-8"))
            value["tasks"][0]["issue"] += " tampered"
            copied_public.write_bytes(canonical(value) + b"\n")
            with self.assertRaisesRegex(BenchmarkError, "frozen input changed"):
                run(fixture.run_root, _Generator())

        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            run(fixture.run_root, _Generator())
            result_path = fixture.run_root / "cases" / "raw" / "blind-unit-001" / "attempt-1" / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["candidate_execution"] = True
            result_path.write_bytes(canonical(result) + b"\n")
            with self.assertRaisesRegex(BenchmarkError, "receipt hash mismatch"):
                freeze(fixture.run_root)

    def test_candidate_source_is_never_imported_or_executed_by_host(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            marker = Path(directory) / "candidate-executed.txt"
            malicious = (
                "__import__('pathlib').Path(" + repr(str(marker)) + ").write_text('owned')\n"
                "def clamp(value):\n    return value\n"
            )
            rows = run(fixture.run_root, _Generator(malicious))
            self.assertEqual(len(rows), 6)
            self.assertTrue(all(not row["candidate_valid"] for row in rows))
            self.assertTrue(all(row["candidate_execution"] is False for row in rows))
            self.assertFalse(marker.exists())
            freeze(fixture.run_root)
            graded = grade(fixture.run_root, fixture.hidden)
            self.assertTrue(all(not row["final"]["resolved"] for row in graded["scores"]))
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
