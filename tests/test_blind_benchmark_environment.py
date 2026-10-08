"""Cold-prompt environment binding for the release benchmark."""
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_blind_repair_benchmark import _Fixture, _Generator
from xnet.benchmark_environment import capture_llama_environment, save_environment
from xnet.blind_repair_benchmark import BenchmarkError, prepare, run
from xnet.local_provider import load_profile
from xnet.protocol import canonical


class BlindBenchmarkEnvironmentTests(unittest.TestCase):
    def test_cold_protocol_requires_and_pins_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = _Fixture(folder)
            protocol = json.loads(fixture.protocol.read_text(encoding="utf-8"))
            protocol["inference"].update({
                "prompt_cache_policy": "disabled at server startup and bound by the run environment receipt",
                "required_llama_server_flags": ["--no-cache-prompt", "--cache-ram 0",
                    "--no-cache-idle-slots", "--slot-prompt-similarity 0.0"],
            })
            fixture.protocol.write_bytes(canonical(protocol) + b"\n")
            with self.assertRaisesRegex(BenchmarkError, "requires a benchmark environment"):
                fixture.prepare()
            self.assertFalse(fixture.run_root.exists())

            state = Path(folder) / "state.json"
            state.write_text(json.dumps({
                "schema": "adaptive-dojo.provider-process.v1", "status": "healthy",
                "model_id": "unit-4b", "model_sha256": "1" * 64,
                "runtime_sha256": "2" * 64,
                "endpoint": "http://127.0.0.1:18096/v1/chat/completions",
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
            }), encoding="utf-8")
            control = Path(folder) / "control.ps1"
            control.write_text("# test control", encoding="utf-8")
            profile = load_profile(fixture.profile)
            receipt = capture_llama_environment(state_path=state, profile=profile,
                server_control_path=control,
                hardware={"system": "test laptop", "cpu": "test cpu",
                    "logical_processors": 16, "memory_bytes": 32 * 1024**3,
                    "gpu": "test gpu", "backend": "Vulkan", "os": "Windows test"})
            environment = Path(folder) / "environment.json"
            save_environment(environment, receipt, profile)
            manifest = prepare(fixture.run_root, public_suite=fixture.public,
                hidden_suite_sha256=fixture.hidden_sha256, protocol=fixture.protocol,
                corpus=fixture.corpus, provider_profile=fixture.profile,
                environment_receipt=environment)
            self.assertTrue(manifest["cold_prompt_attested"])
            self.assertEqual(manifest["environment_identity_sha256"],
                             receipt["environment_sha256"])

            copied = fixture.run_root / "environment.json"
            value = json.loads(copied.read_text(encoding="utf-8"))
            value["ngram_simple"] = False
            copied.write_bytes(canonical(value) + b"\n")
            with self.assertRaisesRegex(BenchmarkError, "frozen input changed"):
                run(fixture.run_root, _Generator())


if __name__ == "__main__":
    unittest.main()
