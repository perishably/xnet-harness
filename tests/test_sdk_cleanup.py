"""Controlled foreground-process/pipe failures; no model or untrusted code."""
import hashlib
import io
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from xnet_sdk.client import API, Client, XnetError, XnetStartupError


def frame(identity, *, result=None, error=None, wrong_hash=False):
    encoded = json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
    record = {"api": API, "id": identity, "ok": error is None, "result": result,
              "result_sha256": "0"*64 if wrong_hash else hashlib.sha256(encoded).hexdigest(),
              "error": error}
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class InputPipe:
    def __init__(self, *, fail_flush=False, fail_close=True):
        self.requests = []
        self.fail_flush, self.fail_close = fail_flush, fail_close
        self.closed = False
        self.on_write = None

    def write(self, request):
        self.requests.append(request)
        if self.on_write is not None:
            self.on_write(request)
        return len(request)

    def flush(self):
        if self.fail_flush:
            raise BrokenPipeError("owned child already exited")

    def close(self):
        self.closed = True
        if self.fail_close:
            raise BrokenPipeError("buffered close flush failed")


class FakeProcess:
    def __init__(self, wire=b"", *, fail_flush=False):
        self.stdin = InputPipe(fail_flush=fail_flush)
        self.stdout = io.BytesIO(wire)
        self.stderr = io.BytesIO()
        self.poll = Mock(return_value=0)
        self.kill = Mock()
        self.wait = Mock(return_value=0)


class SdkCleanupTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="xnet-sdk-cleanup-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.binary = self.root / "synthetic-binary-not-executed"
        self.binary.write_bytes(b"Synthetic pinned bytes; Popen is mocked before launch.")
        self.pin = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def manual_client(self, process, *, startup=False):
        client = object.__new__(Client)
        client.timeout = 0.1
        client._lock = threading.Lock()
        client._queue = queue.Queue(maxsize=2)
        client._closed = False
        client._startup = startup
        client._process = process
        client._reader = Mock()
        return client

    def test_initial_broken_pipe_preserves_validated_startup_rejection(self):
        process = FakeProcess(frame("startup", error="writer_lease_present"), fail_flush=True)
        observed = []
        class ObservedClient(Client):
            def _terminate(self):
                observed.append(self)
                super()._terminate()
        with patch("xnet_sdk.client.subprocess.Popen", return_value=process) as launch:
            with self.assertRaises(XnetStartupError) as refused:
                ObservedClient(self.binary, self.root / "designated-XNET", sha256=self.pin)
        self.assertEqual(refused.exception.code, "writer_lease_present")
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(len(process.stdin.requests), 1)
        self.assertEqual(json.loads(process.stdin.requests[0])["request"]["op"], "health")
        self.assertFalse((self.root / "designated-XNET").exists())
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertFalse(observed[-1]._reader.is_alive())
        # Repeated cleanup remains harmless; a closed client never redispatches.
        observed[-1]._terminate()
        with self.assertRaises(XnetError): observed[-1].call("health")
        self.assertEqual(len(process.stdin.requests), 1)

    def test_invalid_startup_frame_is_not_laundered_by_broken_pipe(self):
        wires = (frame("startup", error="writer_lease_present", wrong_hash=True),
                 frame("startup", result={"not": "null"}, error="writer_lease_present"),
                 b"[]\n", b"null\n", b'"not-a-response"\n')
        for wire in wires:
            process = FakeProcess(wire, fail_flush=True)
            with self.subTest(wire=wire), patch("xnet_sdk.client.subprocess.Popen", return_value=process):
                with self.assertRaisesRegex(XnetError, "runtime protocol failed") as refused:
                    Client(self.binary, self.root / "designated-XNET", sha256=self.pin)
            self.assertNotIsInstance(refused.exception, XnetStartupError)
            self.assertTrue(process.stdout.closed)
            self.assertEqual(len(process.stdin.requests), 1)

    def test_missing_rejection_never_retries_failed_startup_write(self):
        process = FakeProcess(fail_flush=True)
        client = self.manual_client(process, startup=True)
        with self.assertRaisesRegex(XnetError, "runtime protocol failed") as refused:
            client.call("health")
        self.assertIsInstance(refused.exception.__cause__, queue.Empty)
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(len(process.stdin.requests), 1)
        client._reader.join.assert_called_once_with(timeout=2)

    def test_nonstartup_transport_failure_keeps_primary_error_and_no_redispatch(self):
        process = FakeProcess(fail_flush=True)
        client = self.manual_client(process)
        with self.assertRaisesRegex(XnetError, "runtime protocol failed") as refused:
            client.call("seal", text="synthetic public bytes")
        self.assertIsInstance(refused.exception.__cause__, BrokenPipeError)
        self.assertEqual(str(refused.exception.__cause__), "owned child already exited")
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(len(process.stdin.requests), 1)
        with self.assertRaises(XnetError): client.call("seal", text="same bytes")
        self.assertEqual(len(process.stdin.requests), 1)

    def test_completed_verified_response_survives_shutdown_pipe_cleanup(self):
        process = FakeProcess()
        client = self.manual_client(process)
        sealed = {"digest": "a"*64, "bytes": 21, "receipt_seq": 1}
        def respond(raw):
            request = json.loads(raw)
            result = sealed if request["request"]["op"] == "seal" else {"stopped": True}
            client._queue.put(frame(request["id"], result=result))
        process.stdin.on_write = respond
        completed = client.seal("synthetic public bytes")
        self.assertEqual(completed, sealed)
        client.close()  # close() flush error must not hide or invalidate completion.
        self.assertEqual(completed, sealed)
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual([json.loads(r)["request"]["op"] for r in process.stdin.requests], ["seal", "shutdown"])
        client.close()
        self.assertEqual(len(process.stdin.requests), 2)

    def test_reap_retry_runs_even_when_second_kill_races_child_exit(self):
        process = FakeProcess(fail_flush=True)
        process.poll.return_value = None
        process.kill.side_effect = [None, ProcessLookupError("child exited before retry")]
        process.wait.side_effect = [subprocess.TimeoutExpired("owned-runtime", 5), 0]
        client = self.manual_client(process, startup=True)
        client._queue.put(frame("startup", error="writer_lease_present"))
        with self.assertRaises(XnetStartupError) as refused: client.call("health")
        self.assertEqual(refused.exception.code, "writer_lease_present")
        self.assertEqual(process.wait.call_count, 2)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        client._reader.join.assert_called_once_with(timeout=2)


if __name__ == "__main__":
    unittest.main()
