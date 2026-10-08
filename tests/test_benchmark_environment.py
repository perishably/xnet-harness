import copy
import json
from pathlib import Path
import tempfile
import unittest

from xnet.benchmark_environment import (BenchmarkEnvironmentError,
                                        MAX_SERVER_CONTROL_BYTES,
                                        capture_llama_environment,
                                        save_environment, validate_environment)
from xnet.local_provider import LocalProviderProfile
from xnet.protocol import digest


class BenchmarkEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.profile = LocalProviderProfile(
            base_url="http://127.0.0.1:18106/v1", model="qwen-4b",
            model_sha256="1" * 64, runtime_sha256="2" * 64,
            context_tokens=8192, max_output_tokens=650, temperature=0, seed=0)
        self.hardware = {"system": "test laptop", "cpu": "test cpu", "logical_processors": 16,
                         "memory_bytes": 32 * 1024**3, "gpu": "test gpu",
                         "backend": "Vulkan", "os": "Windows test"}

    def state(self):
        return {"schema": "adaptive-dojo.provider-process.v1", "status": "healthy",
                "model_id": "qwen-4b", "model_sha256": "1" * 64,
                "runtime_sha256": "2" * 64,
                "endpoint": "http://127.0.0.1:18106/v1/chat/completions",
                "inference_controls": {"context_tokens": 8192, "parallel_slots": 1,
                    "reasoning_budget": 0, "prompt_cache": "disabled", "cache_ram_mib": 0,
                    "cache_idle_slots": False, "slot_prompt_similarity": 0.0,
                    "cross_task_kv_reuse": False},
                "full_offload_confirmed": True, "launch_config_sha256": "3" * 64,
                "command_sha256": "4" * 64, "profile": "vulkan-test", "ngram_simple": True,
                "performance_controls": {
                    "threads": 14, "threads_batch": 14, "batch_size": 2048,
                    "ubatch_size": 512, "cache_type_k": "q8_0", "cache_type_v": "q8_0",
                    "flash_attention": "on", "gpu_layers": 99, "device": "Vulkan0",
                    "speculative_decoding": "ngram-simple"},
                "executable_path": "C:/private/runtime.exe", "stdout_path": "C:/private/out.log"}

    def test_capture_is_sanitized_sealed_and_exclusive(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state.json"
            state.write_text(json.dumps(self.state()), encoding="utf-8")
            control = root / "control.ps1"
            control.write_text("# pinned", encoding="utf-8")
            receipt = capture_llama_environment(state_path=state, profile=self.profile,
                server_control_path=control, hardware=self.hardware)
            self.assertEqual(receipt["schema"], "xnet.blind-repair50.environment.v2")
            self.assertEqual(receipt["performance_controls"],
                             self.state()["performance_controls"])
            self.assertFalse(receipt["paths_disclosed"])
            self.assertNotIn("executable_path", receipt)
            self.assertEqual(validate_environment(receipt, self.profile), receipt)
            target = root / "environment.json"
            save_environment(target, receipt, self.profile)
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "already exists"):
                save_environment(target, receipt, self.profile)

    def test_cache_drift_and_receipt_tamper_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state_value = self.state()
            state_value["inference_controls"]["prompt_cache"] = "enabled"
            state = root / "state.json"
            state.write_text(json.dumps(state_value), encoding="utf-8")
            control = root / "control.ps1"
            control.write_text("# pinned", encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "controls differ"):
                capture_llama_environment(state_path=state, profile=self.profile,
                    server_control_path=control, hardware=self.hardware)

            state_value = self.state()
            state.write_text(json.dumps(state_value), encoding="utf-8")
            receipt = capture_llama_environment(state_path=state, profile=self.profile,
                server_control_path=control, hardware=self.hardware)
            receipt["performance_controls"]["threads"] = 12
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "hash mismatch"):
                validate_environment(receipt, self.profile)

    def test_performance_controls_are_exact_typed_and_match_speculation(self):
        changes = (
            ("missing", lambda value: value["performance_controls"].pop("device")),
            ("extra", lambda value: value["performance_controls"].update({"tensor_split": "none"})),
            ("bool-as-int", lambda value: value["performance_controls"].update({"threads": True})),
            ("ubatch-above-batch", lambda value: value["performance_controls"].update(
                {"ubatch_size": 4096})),
            ("speculation-mismatch", lambda value: value["performance_controls"].update(
                {"speculative_decoding": "disabled"})),
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state.json"
            control = root / "control.ps1"
            control.write_text("# pinned", encoding="utf-8")
            for label, change in changes:
                with self.subTest(label=label):
                    value = self.state()
                    change(value)
                    state.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(BenchmarkEnvironmentError,
                                                 "performance control"):
                        capture_llama_environment(state_path=state, profile=self.profile,
                            server_control_path=control, hardware=self.hardware)

    def test_numeric_control_booleans_cannot_impersonate_zero_or_one(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state.json"
            control = root / "control.ps1"
            control.write_text("# pinned", encoding="utf-8")

            powershell_state = self.state()
            powershell_state["inference_controls"]["slot_prompt_similarity"] = 0
            state.write_text(json.dumps(powershell_state), encoding="utf-8")
            normalized = capture_llama_environment(state_path=state, profile=self.profile,
                server_control_path=control, hardware=self.hardware)
            self.assertIs(type(normalized["inference_controls"]["slot_prompt_similarity"]), float)

            state_value = self.state()
            state_value["inference_controls"]["parallel_slots"] = True
            state.write_text(json.dumps(state_value), encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "controls differ"):
                capture_llama_environment(state_path=state, profile=self.profile,
                    server_control_path=control, hardware=self.hardware)

            state.write_text(json.dumps(self.state()), encoding="utf-8")
            receipt = capture_llama_environment(state_path=state, profile=self.profile,
                server_control_path=control, hardware=self.hardware)
            forged = copy.deepcopy(receipt)
            forged["inference_controls"]["reasoning_budget"] = False
            forged_body = dict(forged)
            forged_body.pop("environment_sha256")
            forged["environment_sha256"] = digest(forged_body)
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "controls differ"):
                validate_environment(forged, self.profile)

    def test_state_rejects_duplicate_keys_and_unsafe_runtime_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state.json"
            encoded = json.dumps(self.state())
            state.write_text(encoded.replace('"status": "healthy"',
                '"status": "healthy", "status": "healthy"', 1), encoding="utf-8")
            control = root / "control.ps1"
            control.write_text("# pinned", encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "duplicate key"):
                capture_llama_environment(state_path=state, profile=self.profile,
                    server_control_path=control, hardware=self.hardware)

            unsafe = self.state()
            unsafe["profile"] = "C:/Users/private/runtime.json"
            state.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "bounded identifier"):
                capture_llama_environment(state_path=state, profile=self.profile,
                    server_control_path=control, hardware=self.hardware)

            invalid_bool = self.state()
            invalid_bool["ngram_simple"] = 1
            state.write_text(json.dumps(invalid_bool), encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "must be boolean"):
                capture_llama_environment(state_path=state, profile=self.profile,
                    server_control_path=control, hardware=self.hardware)

    def test_server_control_read_is_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state.json"
            state.write_text(json.dumps(self.state()), encoding="utf-8")
            control = root / "control.ps1"
            control.write_bytes(b"x" * (MAX_SERVER_CONTROL_BYTES + 1))
            with self.assertRaisesRegex(BenchmarkEnvironmentError, "control input exceeds"):
                capture_llama_environment(state_path=state, profile=self.profile,
                    server_control_path=control, hardware=self.hardware)


if __name__ == "__main__":
    unittest.main()
