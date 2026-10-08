"""Receipt schema, linkage, completeness, and release identity tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_blind_repair_benchmark import _Fixture, _Generator
from xnet.blind_repair_benchmark import (
    BenchmarkError,
    freeze,
    grade,
    release_note,
    run,
    summarize,
)
from xnet.protocol import canonical, digest


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _reseal(path, value):
    body = {key: item for key, item in value.items() if key != "receipt_sha256"}
    sealed = {**body, "receipt_sha256": digest(body)}
    Path(path).write_bytes(canonical(sealed) + b"\n")
    return sealed


def _complete(fixture):
    run(fixture.run_root, _Generator())
    freeze(fixture.run_root)
    grade(fixture.run_root, fixture.hidden)
    return summarize(fixture.run_root)


class BlindBenchmarkReceiptTests(unittest.TestCase):
    def test_manifest_has_complete_source_pins_and_rejects_resealed_schema_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            manifest = fixture.prepare()
            self.assertIn("brains.py", manifest["source_sha256"])
            self.assertEqual(set(manifest["source_sha256"]), {
                "benchmark_environment.py", "blind_repair_benchmark.py", "brains.py", "hce_capsule_v1.py",
                "local_provider.py", "protocol.py", "repair_evaluator.py",
                "repair_loop.py", "swe_repair_evaluator.py"})

            path = fixture.run_root / "manifest.json"
            changed = _read(path)
            changed["source_sha256"].pop("brains.py")
            _reseal(path, changed)
            with self.assertRaisesRegex(BenchmarkError, "source pin fields differ"):
                freeze(fixture.run_root)

    def test_resealed_response_cannot_change_its_request_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            run(fixture.run_root, _Generator())
            path = (fixture.run_root / "cases" / "raw" / "blind-unit-001" /
                    "attempt-1" / "response.json")
            changed = _read(path)
            changed["reservation_sha256"] = "0" * 64
            _reseal(path, changed)
            with self.assertRaisesRegex(BenchmarkError, "does not link to its request"):
                freeze(fixture.run_root)

    def test_resealed_choices_and_grade_must_remain_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            run(fixture.run_root, _Generator())
            freeze(fixture.run_root)
            path = fixture.run_root / "frozen" / "choices.json"
            changed = _read(path)
            changed["choices"].pop()
            changed["choice_count"] = len(changed["choices"])
            _reseal(path, changed)
            with self.assertRaisesRegex(BenchmarkError, "choices are incomplete"):
                grade(fixture.run_root, fixture.hidden)

        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            run(fixture.run_root, _Generator())
            freeze(fixture.run_root)
            grade(fixture.run_root, fixture.hidden)
            path = fixture.run_root / "frozen" / "grade.json"
            changed = _read(path)
            changed["scores"].pop()
            _reseal(path, changed)
            with self.assertRaisesRegex(BenchmarkError, "grade record is incomplete"):
                summarize(fixture.run_root)

    def test_release_note_requires_sealed_summary_and_exact_frozen_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(directory)
            fixture.prepare()
            summary = _complete(fixture)
            options = {"model_label": "unit-4b", "source_commit": "a" * 40,
                       "model_sha256": "1" * 64, "runtime_sha256": "2" * 64}
            note = release_note(summary, **options)
            self.assertIn("**1/1**", note)
            self.assertIn("Source-pin manifest SHA-256", note)
            self.assertIn(summary["receipt_sha256"], note)

            unsealed = copy.deepcopy(summary)
            unsealed["lanes"]["raw"]["final_joint_solves"] = 0
            with self.assertRaisesRegex(BenchmarkError, "receipt hash mismatch"):
                release_note(unsealed, **options)

            changes = (("model_label", "another-model"),
                       ("model_sha256", "3" * 64),
                       ("runtime_sha256", "4" * 64))
            for field, replacement in changes:
                with self.subTest(field=field), self.assertRaisesRegex(
                        BenchmarkError, "release identity differs"):
                    release_note(summary, **{**options, field: replacement})
            with self.assertRaisesRegex(BenchmarkError, "source_commit"):
                release_note(summary, **{**options, "source_commit": "not-a-commit"})

            missing_source = copy.deepcopy(summary)
            missing_source["release_pins"]["source_sha256"].pop("brains.py")
            missing_source = {key: item for key, item in missing_source.items()
                              if key != "receipt_sha256"}
            missing_source["receipt_sha256"] = digest(missing_source)
            with self.assertRaisesRegex(BenchmarkError, "release source pin fields differ"):
                release_note(missing_source, **options)


if __name__ == "__main__":
    unittest.main()
