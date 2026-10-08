"""Tests for the numeric-loopback OpenAI-compatible provider boundary."""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from xnet.local_provider import (
    LocalProviderError,
    LocalProviderProfile,
    chat_completion,
    doctor_profile,
    load_profile,
    normalize_response_metrics,
    save_profile,
)


class _Handler(BaseHTTPRequestHandler):
    calls: list[dict] = []

    def log_message(self, format, *args):  # noqa: A002
        return

    def _reply(self, value):
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path,
                                 "authorization": self.headers.get("Authorization"), "body": b""})
        if self.path == "/health":
            self._reply({"status": "ok"})
        elif self.path == "/v1/models":
            self._reply({"object": "list", "data": [{"id": "qwen-4b", "object": "model"}]})
        else:
            self.send_error(404)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).calls.append({"method": "POST", "path": self.path,
                                 "authorization": self.headers.get("Authorization"), "body": body})
        request = json.loads(body)
        self._reply({
            "id": "local-1",
            "unknown_provider_extension": {"kept": True},
            "choices": [{"index": 0, "message": {"role": "assistant",
                                                    "content": "print('candidate only')"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 41, "completion_tokens": 7, "total_tokens": 48,
                      "prompt_tokens_details": {"cached_tokens": 11}},
            "timings": {"prompt_n": 41, "predicted_n": 7, "prompt_ms": 20.5,
                        "predicted_ms": 100.0, "prompt_per_second": 2000.0,
                        "predicted_per_second": 70.0, "draft_n": 9,
                        "draft_n_accepted": 4},
            "echo_seed": request["seed"],
        })


class LocalProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _Handler.calls = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        _Handler.calls.clear()
        self.profile = LocalProviderProfile(
            base_url="http://127.0.0.1:" + str(self.server.server_port) + "/v1/",
            model="qwen-4b",
            model_sha256="a" * 64,
            runtime_sha256="b" * 64,
            context_tokens=8192,
            max_output_tokens=512,
            temperature=0,
            seed=17,
        )

    def test_only_numeric_loopback_http_is_accepted(self):
        bad = (
            "https://127.0.0.1:18096/v1",
            "http://localhost:18096/v1",
            "http://192.168.1.3:18096/v1",
            "http://user@127.0.0.1:18096/v1",
            "http://127.0.0.1:18096/v1?token=secret",
            "http://127.0.0.1/v1",
            "http://127.0.0.1:18096/other",
        )
        for base_url in bad:
            with self.subTest(base_url=base_url), self.assertRaises(LocalProviderError):
                LocalProviderProfile(base_url=base_url, model="m", model_sha256="a" * 64,
                                     runtime_sha256="b" * 64, context_tokens=4096,
                                     max_output_tokens=64, temperature=0, seed=0)

    def test_profile_round_trip_is_exclusive_and_pinned(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "nested" / "provider.json"
            receipt = save_profile(path, self.profile)
            self.assertEqual(load_profile(path), self.profile)
            self.assertEqual(receipt["canonical_profile_sha256"], self.profile.profile_sha256)
            self.assertEqual(receipt["raw_profile_sha256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(LocalProviderError):
                save_profile(path, self.profile)

    def test_profile_refuses_unknown_fields_and_duplicate_keys(self):
        value = self.profile.as_dict()
        value["api_key"] = "must-not-fit"
        with self.assertRaises(LocalProviderError):
            LocalProviderProfile.from_mapping(value)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "duplicate.json"
            path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaises(LocalProviderError):
                load_profile(path)

    def test_doctor_is_two_read_only_gets_without_credentials(self):
        result = doctor_profile(self.profile)
        self.assertTrue(result["ok"])
        self.assertTrue(result["configured_model_present"])
        self.assertEqual([(call["method"], call["path"]) for call in _Handler.calls],
                         [("GET", "/health"), ("GET", "/v1/models")])
        self.assertTrue(all(call["authorization"] is None for call in _Handler.calls))
        for key in ("health", "models"):
            raw_hash = result[key]["http_receipt"]["raw_response_body_sha256"]
            self.assertRegex(raw_hash, r"^[0-9a-f]{64}$")

    def test_chat_retains_exact_body_hashes_and_candidate_is_data(self):
        result = chat_completion(self.profile, [{"role": "user", "content": "repair it"}])
        call = _Handler.calls[-1]
        receipt = result["http_receipt"]
        self.assertEqual(call["path"], "/v1/chat/completions")
        self.assertIsNone(call["authorization"])
        self.assertEqual(receipt["raw_request_body_sha256"],
                         hashlib.sha256(call["body"]).hexdigest())
        self.assertGreaterEqual(receipt["client_elapsed_ms"], 0)
        self.assertEqual(result["provider_request"], json.loads(call["body"]))
        self.assertEqual(result["candidate_text"], "print('candidate only')")
        self.assertEqual(result["candidate_authority"], "data-only")
        self.assertTrue(result["provider_response"]["unknown_provider_extension"]["kept"])
        values = result["metrics"]["values"]
        self.assertEqual((values["input_tokens"], values["output_tokens"]), (41, 7))
        self.assertEqual(values["cached_input_tokens"], 11)
        self.assertEqual(values["speculative_accepted_tokens"], 4)
        self.assertIsNone(values["time_to_first_token_ms"])
        self.assertIn("time_to_first_token_ms", result["metrics"]["unknown"])

    def test_missing_metrics_are_explicit_unknown_and_conflicts_refuse(self):
        normalized = normalize_response_metrics({"choices": []})
        self.assertTrue(all(value is None for value in normalized["values"].values()))
        self.assertTrue(all(source == "unknown" for source in normalized["sources"].values()))
        with self.assertRaises(LocalProviderError):
            normalize_response_metrics({"usage": {"prompt_tokens": 3},
                                        "timings": {"prompt_n": 4}})
        with self.assertRaises(LocalProviderError):
            normalize_response_metrics({"usage": {"prompt_tokens": 3,
                                                   "completion_tokens": 2,
                                                   "total_tokens": 99}})

    def test_message_contract_is_strict_and_does_not_call_provider(self):
        bad_messages = (
            [],
            [{"role": "tool", "content": "x"}],
            [{"role": "user", "content": "x", "command": "calc.exe"}],
            [{"role": "user", "content": 7}],
        )
        for messages in bad_messages:
            before = len(_Handler.calls)
            with self.subTest(messages=messages), self.assertRaises(LocalProviderError):
                chat_completion(self.profile, messages)
            self.assertEqual(len(_Handler.calls), before)


if __name__ == "__main__":
    unittest.main()
