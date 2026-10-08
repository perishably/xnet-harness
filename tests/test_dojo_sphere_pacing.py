"""Quota rollover, original-call and lock-order checks; no model/network."""
from collections import deque
from contextlib import contextmanager
from pathlib import Path
import tempfile
import threading
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from adapters.dojo import sphere_pacing as pacing
from adapters.dojo.sphere_arbitration import install_serial_cycle
from adapters.openclaw import make_source_packet
from test_dojo_sphere_arbitration import fresh_sphere
from xnet import oroboros_sphere as original
from xnet.brains import _exclusive_file_lock
from xnet.protocol import canonical


class SpherePacingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dojo-paced-source-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sphere = fresh_sphere(self.root / "silos")
        install_serial_cycle(self.sphere)
        self.binding = pacing.install_source_pacing(self.sphere)
        for target in ("subprocess.Popen", "subprocess.run", "socket.create_connection"):
            handle = patch(target, side_effect=AssertionError("no process/model/network"))
            handle.start(); self.addCleanup(handle.stop)

    def packet(self, i):
        return make_source_packet(task_id="source-task", packet_id="card-" + str(i),
            producer="operator", kind="note", text="Authored public source " + str(i))

    def fake_time(self):
        clock = [100.0]
        waits = []
        def sleep(seconds):
            waits.append(seconds); clock[0] += seconds
        return clock, waits, sleep

    def test_full_readback_waits_at_original_quota_without_retry_reset_or_policy_change(self):
        clock, waits, sleep = self.fake_time()
        original_manifest = canonical(self.sphere.scopes.load(self.sphere.scope_id))
        # Real records exercise every read path. The actual original quota is
        # seeded in its existing deque instead of building 71 redundant cycles.
        with patch.object(pacing, "monotonic", lambda: clock[0]), \
                patch.object(pacing, "sleep", sleep), \
                patch.object(original.time, "monotonic", lambda: clock[0]):
            for i in range(2):
                self.sphere.cycle(self.packet(i), "powershell")
            queue = self.sphere.tools._requests[self.sphere.scope_id]
            quota = self.sphere.scopes.load(self.sphere.scope_id)["requests_per_minute"]
            self.assertEqual(quota, 600)
            queue.extend([clock[0]] * (quota - len(queue)))
            self.assertEqual(len(queue), quota)
            expired_stamp = clock[0]
            checked = self.sphere.verify()
            self.assertTrue(checked["ok"], checked["errors"])
            self.assertEqual((checked["packets"], checked["hops"], checked["verified_reads"]), (2, 8, 10))
            self.assertIs(self.sphere.tools._requests[self.sphere.scope_id], queue)
            self.assertEqual(len(queue), 10)  # one original admission per real read
            self.assertTrue(all(stamp - expired_stamp >= 60 for stamp in queue))
        self.assertTrue(waits)
        self.assertGreaterEqual(sum(waits), 60)
        self.assertTrue(all(0 < delay <= 1 for delay in waits))
        self.assertEqual(canonical(self.sphere.scopes.load(self.sphere.scope_id)), original_manifest)
        self.assertEqual(pacing.pacing_binding(self.sphere), self.binding)
        self.assertEqual(self.binding["original_execute_calls_per_admission"], 1)
        self.assertFalse(self.binding["queue_reset"])

    def test_single_fetch_rollover_calls_original_once_and_source_gate_precedes_os_lock(self):
        packet = self.packet("one")
        self.sphere.cycle(packet, "powershell")
        clock, waits, sleep = self.fake_time()
        queue = deque([clock[0]] * 600)
        self.sphere.tools._requests[self.sphere.scope_id] = queue
        before_manifest = canonical(self.sphere.scopes.load(self.sphere.scope_id))
        os_lock = original._exclusive_file_lock
        entries = []
        @contextmanager
        def inspected_lock(path, **kwargs):
            self.assertTrue(self.sphere.__dict__["_dojo_sphere_arbitration"].lock._is_owned())
            entries.append(True)
            with os_lock(path, **kwargs):
                yield
        with patch.object(pacing, "monotonic", lambda: clock[0]), \
                patch.object(pacing, "sleep", sleep), \
                patch.object(original.time, "monotonic", lambda: clock[0]), \
                patch.object(original, "_exclusive_file_lock", inspected_lock):
            raw = self.sphere.fetch("c_nvme", packet["packet_sha256"])
            self.assertEqual(raw, canonical(packet))
            self.assertEqual(len(queue), 1)  # original removed expired entries, admitted once
            self.sphere.verify()
        self.assertGreaterEqual(sum(waits), 60)
        self.assertEqual(len(entries), 2)
        self.assertEqual(canonical(self.sphere.scopes.load(self.sphere.scope_id)), before_manifest)
        self.sphere.tools.execute = MethodType(original.SphereTools.execute, self.sphere.tools)
        with self.assertRaisesRegex(ValueError, "identity/policy changed"):
            pacing.pacing_binding(self.sphere)




if __name__ == "__main__":
    unittest.main()
