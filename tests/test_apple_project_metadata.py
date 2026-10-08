"""Metadata-only check for the authored iPhone source project.

This test never invokes Swift, Xcode, a model, a device, or a network.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "examples" / "native" / "apple" / "validate_project.py"


class AppleProjectMetadataTests(unittest.TestCase):
    def test_authored_project_is_closed_and_unmeasured_claims_remain_false(self):
        spec = importlib.util.spec_from_file_location("xnet_apple_project_validator", VALIDATOR)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output = io.StringIO()
        with redirect_stdout(output):
            module.main()
        receipt = json.loads(output.getvalue())
        self.assertTrue(receipt["project_metadata_valid"])
        self.assertEqual(receipt["app_source_files"], 9)
        self.assertEqual(receipt["authored_core_test_cases"], 17)
        self.assertFalse(receipt["swift_compiled"])
        self.assertFalse(receipt["xctest_executed"])
        self.assertFalse(receipt["physical_device_validated"])


if __name__ == "__main__":
    unittest.main()
