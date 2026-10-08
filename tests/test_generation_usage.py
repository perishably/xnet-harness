"""Counter compatibility controls; no model, host-code evaluation or network."""
from __future__ import annotations

import copy
import unittest

from xnet.generation_usage import (GenerationUsageError,
    generation_usage_callback, generation_usage_projection,
    normalize_generation_usage)


class GenerationUsageControls(unittest.TestCase):
    def test_native_and_openai_aliases_match(self):
        native = normalize_generation_usage({"input_tokens": 17, "output_tokens": 5})
        alias = normalize_generation_usage({"prompt_tokens": 17, "completion_tokens": 5,
                                            "total_tokens": 22})
        self.assertEqual((native["input_tokens"], native["output_tokens"]),
                         (alias["input_tokens"], alias["output_tokens"]))

    def test_equal_aliases_and_zero_are_valid(self):
        self.assertEqual(normalize_generation_usage({"input_tokens": 0, "prompt_tokens": 0,
            "output_tokens": 0, "completion_tokens": 0, "total_tokens": 0})["output_tokens"], 0)

    def test_conflicting_input_aliases_refused(self):
        with self.assertRaises(GenerationUsageError):
            normalize_generation_usage({"input_tokens": 8, "prompt_tokens": 9, "output_tokens": 2})

    def test_conflicting_output_aliases_refused(self):
        with self.assertRaises(GenerationUsageError):
            normalize_generation_usage({"prompt_tokens": 8, "output_tokens": 2, "completion_tokens": 3})

    def test_bad_counter_types_refused(self):
        for value in (True, False, -1, 2.0, "2", None, 2**63):
            for field in ("prompt_tokens", "completion_tokens"):
                with self.subTest(value=value, field=field):
                    usage = {"prompt_tokens": 8, "completion_tokens": 2}
                    usage[field] = value
                    with self.assertRaises(GenerationUsageError):
                        normalize_generation_usage(usage)

    def test_missing_counter_is_not_zero(self):
        for usage in ({}, {"input_tokens": 2}, {"output_tokens": 2},
                      {"total_tokens": 4, "prompt_tokens": 2}):
            with self.subTest(usage=usage), self.assertRaises(GenerationUsageError):
                normalize_generation_usage(usage)

    def test_conflicting_or_bad_total_refused(self):
        for total in (99, True, 2.0, None):
            with self.subTest(total=total), self.assertRaises(GenerationUsageError):
                normalize_generation_usage({"prompt_tokens": 8, "completion_tokens": 2,
                                             "total_tokens": total})

    def test_total_overflow_refused(self):
        with self.assertRaises(GenerationUsageError):
            normalize_generation_usage({"input_tokens": 2**63 - 1, "output_tokens": 1})

    def test_metadata_and_provider_evidence_unchanged(self):
        raw = {"prompt_tokens": 8, "completion_tokens": 2,
               "timings": {"predicted_ms": 31.2}, "prompt_tokens_details": {"cached_tokens": 0}}
        before = copy.deepcopy(raw)
        projected = generation_usage_projection(raw)
        self.assertEqual(raw, before)
        self.assertFalse(projected["estimated_counters"])
        projected["normalized_usage"]["timings"]["predicted_ms"] = 5
        self.assertEqual(raw, before)
        self.assertEqual(projected["alias_sources"]["output_tokens"], ["completion_tokens"])

    def test_callback_preserves_text_and_one_call(self):
        calls = []
        raw = {"model_id": "lite", "model_sha256": "a" * 64, "text": "unchanged",
               "usage": {"prompt_tokens": 8, "completion_tokens": 2}}
        def generate(request):
            calls.append(request)
            return raw
        result = generation_usage_callback(generate)({"nonce": "fixed"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["text"], raw["text"])
        self.assertEqual(result["usage"]["output_tokens"], 2)
        self.assertNotIn("output_tokens", raw["usage"])

    def test_failed_usage_does_not_retry_generation(self):
        calls = []
        def generate(request):
            calls.append(request)
            return {"usage": {"prompt_tokens": 8}}
        with self.assertRaises(GenerationUsageError):
            generation_usage_callback(generate)({"nonce": "fixed"})
        self.assertEqual(len(calls), 1)

    def test_bad_container_or_result_refused(self):
        for usage in (None, [], "bad"):
            with self.subTest(usage=usage), self.assertRaises(GenerationUsageError):
                normalize_generation_usage(usage)
        for result in (None, [], {}):
            with self.subTest(result=result), self.assertRaises(GenerationUsageError):
                generation_usage_callback(lambda request: result)({})


if __name__ == "__main__":
    unittest.main()
