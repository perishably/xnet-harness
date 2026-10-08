"""Signed inert fixtures: retained leases, full boundaries and source hashes."""
import hashlib
import os
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from xnet.artifact_integrity_guard_v3 import ArtifactIntegrityGuard, ArtifactIntegrityError, PATH_METHODS
from xnet.scope import ScopeAuthority


class ArtifactGuardControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="xnet-artifact-guard-inert-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).absolute()
        self.authority = ScopeAuthority(self.root / "authority")
        self.scope = self.authority.create(program="Inert artifact integrity controls",
            policy_url="fixture://artifact-integrity", policy_capture=b"inert files only",
            allowed_assets=["path:" + str(self.root)], fixture=True,
            methods=[*PATH_METHODS, "fixture-write"], requests_per_minute=600)
        self.calls = []
        self.model = self.make("model.fixture", b"inert fixed model bytes" * 128)
        self.runner = self.make("runner.fixture", b"inert fixed runner bytes" * 16)
        self.source = self.make("source.fixture", b"inert source implementation" * 16)
        for name in ("subprocess.Popen", "subprocess.run", "socket.create_connection"):
            handle = patch(name, side_effect=AssertionError("no model/process/network in artifact fixture"))
            handle.start(); self.addCleanup(handle.stop)

    def gate(self, method, target):
        self.authority.gate(self.scope["scope_id"], target, method)
        self.calls.append((method, target))

    def make(self, name, raw):
        path = self.root / name
        self.gate("fixture-write", "path:" + str(path))
        path.write_bytes(raw)
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}

    def guard(self, *, protection="auto", maximum=128):
        guard = ArtifactIntegrityGuard([self.model, self.runner], [self.source], self.gate,
            protection=protection, max_dispatch_checks=maximum)
        # Last-in-first-out cleanup releases the guard before deleting fixtures.
        self.addCleanup(guard.close)
        return guard

    def rewrite(self, row, raw):
        path = Path(row["path"])
        self.gate("fixture-write", "path:" + str(path))
        path.write_bytes(raw)

    def test_dispatch_avoids_retained_content_reads_and_rehashes_sources(self):
        guard = self.guard()
        initial = guard.establish()
        original = Path.open
        retained = {self.model["path"], self.runner["path"]}
        def reject_retained_read(path, *args, **kwargs):
            if str(path) in retained:
                raise AssertionError("retained bytes must not be opened by a dispatch check")
            return original(path, *args, **kwargs)
        for _ in range(20):
            with patch.object(Path, "open", new=reject_retained_read):
                evidence = guard.verify_dispatch()
                self.assertFalse(evidence["retained_content_rehashed"])
                self.assertTrue(evidence["source_content_rehashed"])
                self.assertFalse(evidence["metadata_is_cryptographic_proof"])
        boundary = guard.full_boundary("round-exit")
        self.assertEqual(initial["check_kind"], "full-content-sha256")
        self.assertEqual(boundary["boundary_number"], 2)
        metrics = guard.metrics()
        retained_bytes = sum(Path(row["path"]).stat().st_size for row in (self.model, self.runner))
        source_bytes = Path(self.source["path"]).stat().st_size
        self.assertEqual(metrics["retained_bytes_hashed"], 2 * retained_bytes)
        self.assertEqual(metrics["source_bytes_hashed"], 22 * source_bytes)
        self.assertEqual(metrics["dispatch_checks"], 20)
        hash_calls = [target for method, target in self.calls if method == "artifact_guard_hash"]
        self.assertEqual(hash_calls.count("path:" + self.model["path"]), 2)
        self.assertEqual(hash_calls.count("path:" + self.runner["path"]), 2)
        self.assertEqual(hash_calls.count("path:" + self.source["path"]), 22)

    def test_same_size_mutation_with_changed_mtime_refuses_and_cannot_heal(self):
        guard = self.guard(protection="metadata-only"); guard.establish()
        path = Path(self.model["path"]); before = path.stat()
        original = path.read_bytes(); changed = b"X" + original[1:]
        self.rewrite(self.model, changed)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "metadata-drift")
        self.rewrite(self.model, original)
        with self.assertRaises(ArtifactIntegrityError) as restored:
            guard.full_boundary("round-exit")
        self.assertEqual(restored.exception.reason, "prior-refusal")

    def test_same_size_replacement_same_mtime_changes_os_identity(self):
        guard = self.guard(protection="metadata-only"); guard.establish()
        path = Path(self.runner["path"]); before = path.stat()
        replacement = self.root / "replacement.fixture"
        self.make(replacement.name, path.read_bytes())
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.gate("fixture-write", "path:" + str(path)); os.replace(replacement, path)
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "metadata-drift")

    def test_hardlink_added_after_initial_hash_is_refused(self):
        guard = self.guard(protection="metadata-only"); guard.establish()
        alias = self.root / "hardlink.fixture"
        self.gate("fixture-write", "path:" + str(alias))
        os.link(self.runner["path"], alias)
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "path-unavailable-or-linked")

    def test_hardlink_present_at_establishment_is_refused(self):
        alias = self.root / "already-linked.fixture"
        self.gate("fixture-write", "path:" + str(alias)); os.link(self.model["path"], alias)
        guard = self.guard()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.establish()
        self.assertEqual(caught.exception.reason, "path-unavailable-or-linked")

    def test_source_mutation_is_never_cached(self):
        guard = self.guard(); guard.establish()
        self.rewrite(self.source, b"mutated source implementation")
        with self.assertRaises(ArtifactIntegrityError):
            guard.verify_dispatch()
        self.assertTrue(guard.metrics()["poisoned"])

    def test_wrong_selected_content_pin_refuses_initial_admission(self):
        self.model["sha256"] = "a" * 64
        guard = self.guard()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.establish()
        self.assertEqual(caught.exception.reason, "content-hash-mismatch")
        self.assertEqual(guard.metrics()["full_boundary_checks"], 0)

    def test_changed_hash_selection_and_caller_copy_do_not_replace_identity(self):
        guard = self.guard(); manifest = guard.manifest; guard.establish()
        self.model["sha256"] = "a" * 64
        manifest["retained_artifacts"][0]["sha256"] = "b" * 64
        guard.verify_dispatch()  # Detached caller selections do not change the frozen selection.
        guard._manifest["retained_artifacts"][0]["sha256"] = "c" * 64
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "selection-drift")

    def test_scope_refusal_is_typed_permanent_and_prevents_artifact_read(self):
        def refused(method, target):
            raise PermissionError("fixture signed scope refused")
        guard = ArtifactIntegrityGuard([self.model], [self.source], refused)
        self.addCleanup(guard.close)
        with patch.object(Path, "open", side_effect=AssertionError("no read after refused scope")):
            with self.assertRaises(ArtifactIntegrityError) as caught:
                guard.establish()
        self.assertEqual(caught.exception.reason, "scope-refused")

    def test_live_protection_or_gate_replacement_is_refused(self):
        guard = self.guard(); guard.establish()
        guard._protection = "metadata-only" if guard._protection != "metadata-only" else "windows-read-lease"
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "guard-configuration-drift")
        other = self.guard(); other.establish()
        other._gate = lambda method, target: None
        with self.assertRaises(ArtifactIntegrityError) as gate_changed:
            other.verify_dispatch()
        self.assertEqual(gate_changed.exception.reason, "guard-configuration-drift")

    def test_baseline_snapshot_replacement_is_refused(self):
        from dataclasses import replace
        guard = self.guard(); guard.establish()
        path = self.model["path"]
        guard._snapshots[path] = replace(guard._snapshots[path], mtime_ns=0)
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "retained-snapshot-drift")

    def test_source_change_during_a_full_boundary_is_refused(self):
        guard = self.guard(); guard.establish()
        original = hashlib.file_digest
        changed = False
        def source_change(stream, algorithm):
            nonlocal changed
            actual = original(stream, algorithm)
            if str(getattr(stream, "name", "")) == self.source["path"] and not changed:
                changed = True
                self.rewrite(self.source, b"source changed after its bytes were hashed")
            return actual
        with patch("xnet.artifact_integrity_guard_v3.hashlib.file_digest", side_effect=source_change):
            with self.assertRaises(ArtifactIntegrityError) as caught:
                guard.full_boundary("round-exit")
        self.assertTrue(changed)
        self.assertEqual(caught.exception.reason, "changed-during-hash")

    def test_unknown_or_unestablished_guard_cannot_dispatch(self):
        guard = self.guard()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "not-established")
        with self.assertRaises(ArtifactIntegrityError) as poisoned:
            guard.establish()
        self.assertEqual(poisoned.exception.reason, "prior-refusal")

    def test_closed_or_exhausted_guard_refuses_dispatch(self):
        guard = self.guard(maximum=1); guard.establish(); guard.verify_dispatch()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "dispatch-check-budget")
        other = self.guard(); other.establish(); other.close()
        with self.assertRaises(ArtifactIntegrityError) as closed:
            other.verify_dispatch()
        self.assertEqual(closed.exception.reason, "closed")

    @unittest.skipUnless(os.name == "nt", "Windows lease guarantee has no metadata-only substitution")
    def test_windows_lease_blocks_write_delete_and_preexisting_writable_handle(self):
        guard = self.guard(protection="windows-read-lease"); guard.establish()
        self.assertTrue(guard.metrics()["write_delete_sharing_denied"])
        with self.assertRaises(PermissionError):
            self.rewrite(self.model, b"X" * Path(self.model["path"]).stat().st_size)
        path = Path(self.runner["path"])
        self.gate("fixture-write", "path:" + str(path))
        with self.assertRaises(PermissionError):
            path.unlink()
        guard.verify_dispatch(); guard.full_boundary("release"); guard.close()
        # After explicit close a writable handle can exist; a new guard must
        # refuse admission rather than claiming its read lease protected it.
        self.gate("fixture-write", "path:" + self.model["path"])
        with Path(self.model["path"]).open("r+b"):
            refused = self.guard(protection="windows-read-lease")
            with self.assertRaises(ArtifactIntegrityError) as caught:
                refused.establish()
            self.assertEqual(caught.exception.reason, "retained-read-lease-refused")

    @unittest.skipUnless(os.name == "nt", "Actual Windows retained-handle identity control")
    def test_closed_windows_handle_refuses_even_when_path_metadata_is_unchanged(self):
        guard = self.guard(protection="windows-read-lease"); guard.establish()
        guard._leases[self.model["path"]].close()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "retained-lease-closed-or-unavailable")

    @unittest.skipUnless(os.name == "nt", "Windows has stable creation time for this residual control")
    def test_explicit_weaker_mode_detects_restored_metadata_change_at_full_boundary(self):
        guard = self.guard(protection="metadata-only"); guard.establish()
        path = Path(self.model["path"]); before = path.stat()
        self.rewrite(self.model, b"X" + path.read_bytes()[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        # If the OS exposes an additional changed field, a dispatch refusal is
        # stronger. Otherwise its weaker evidence must remain explicit and the
        # full boundary must still detect altered bytes.
        try:
            evidence = guard.verify_dispatch()
        except ArtifactIntegrityError:
            self.assertTrue(guard.metrics()["poisoned"])
        else:
            self.assertEqual(evidence["protection"], "metadata-only")
            self.assertFalse(evidence["write_delete_sharing_denied"])
            with self.assertRaises(ArtifactIntegrityError) as caught:
                guard.full_boundary("learner-admission")
            self.assertEqual(caught.exception.reason, "content-hash-mismatch")

    @unittest.skipUnless(os.name == "nt", "Real Windows suffix-derived mode mismatch")
    def test_inert_exe_suffix_reproduces_v1_refusal_and_v2_keeps_full_integrity(self):
        from xnet.artifact_integrity_guard_v1 import ArtifactIntegrityGuard as OldGuard
        from xnet.artifact_integrity_guard_v1 import ArtifactIntegrityError as OldError
        from xnet.artifact_integrity_guard_v3 import _Snapshot
        exe = self.make("inert-never-executed.exe", b"inert executable suffix fixture; never launch" * 64)
        path = Path(exe["path"])
        self.gate("artifact_guard_stat", "path:" + str(path))
        before = path.lstat()
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
        self.assertEqual(before.st_mode ^ opened.st_mode, 0o111)
        self.assertEqual(_Snapshot.from_stat(before), _Snapshot.from_stat(opened))
        old = OldGuard([exe], [self.source], self.gate, protection="windows-read-lease")
        self.addCleanup(old.close)
        with self.assertRaises(OldError) as caught:
            old.establish()
        self.assertEqual(caught.exception.reason, "retained-lease-identity-drift")
        self.assertEqual(caught.exception.path, str(path))
        guard = ArtifactIntegrityGuard([exe], [self.source], self.gate, protection="windows-read-lease")
        self.addCleanup(guard.close)
        guard.establish(); retained_bytes = guard.metrics()["retained_bytes_hashed"]
        guard.verify_dispatch()
        self.assertEqual(guard.metrics()["retained_bytes_hashed"], retained_bytes)
        with self.assertRaises(PermissionError):
            self.rewrite(exe, b"X" + path.read_bytes()[1:])
        self.gate("fixture-write", "path:" + str(path))
        with self.assertRaises(PermissionError):
            path.unlink()
        guard.full_boundary("release")
        self.assertEqual(guard.metrics()["retained_bytes_hashed"], 2 * before.st_size)
        self.assertTrue(guard.metrics()["write_delete_sharing_denied"])

    def test_mode_normalization_retains_type_readwrite_attributes_and_nonwindows_bits(self):
        from xnet.artifact_integrity_guard_v3 import _Snapshot
        raw = SimpleNamespace(st_dev=1, st_ino=2, st_size=3, st_mtime_ns=4,
            st_ctime_ns=5, st_birthtime_ns=5, st_mode=stat.S_IFREG | 0o777,
            st_nlink=1, st_file_attributes=0x20)
        with patch("xnet.artifact_integrity_guard_v3.os.name", "nt"):
            value = _Snapshot.from_stat(raw)
            self.assertEqual(value.mode, stat.S_IFREG | 0o666)
            for key, changed in (("st_mode", stat.S_IFREG | 0o444),
                    ("st_mode", stat.S_IFDIR | 0o777), ("st_file_attributes", 0x21),
                    ("st_file_attributes", 0x420), ("st_nlink", 2), ("st_ino", 9)):
                row = SimpleNamespace(**vars(raw)); setattr(row, key, changed)
                self.assertNotEqual(_Snapshot.from_stat(row), value, key)
        with patch("xnet.artifact_integrity_guard_v3.os.name", "posix"):
            self.assertEqual(_Snapshot.from_stat(raw).mode, stat.S_IFREG | 0o777)

    def transport_guard(self, *, protection="auto", maximum=128):
        exe = self.make("coach.exe", b"inert coach transport; never execute" * 128)
        guard = ArtifactIntegrityGuard([self.model, exe], [self.source], self.gate,
            protection=protection, max_dispatch_checks=maximum, transport_artifacts=[exe])
        self.addCleanup(guard.close)
        return guard, exe

    @unittest.skipUnless(os.name == "nt", "Actual Windows transport lease")
    def test_borrowed_transport_checks_avoid_reads_keep_boundaries_and_block_writes(self):
        guard, exe = self.transport_guard(); guard.establish()
        initial = guard.metrics()
        original_open = Path.open
        artifact_paths = {row["path"] for row in (exe, self.model, self.source)}
        def authority_reads_only(path, *args, **kwargs):
            if str(path) in artifact_paths:
                raise AssertionError("borrowed continuity cannot read artifact bytes")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", new=authority_reads_only):
            for _ in range(12):
                evidence = guard.verify_transport_artifacts([exe])
                self.assertFalse(evidence["retained_content_rehashed"])
                self.assertFalse(evidence["source_content_rehashed"])
                self.assertFalse(evidence["metadata_is_cryptographic_proof"])
        after = guard.metrics()
        self.assertEqual(after["transport_bytes_hashed"], initial["transport_bytes_hashed"])
        self.assertEqual(after["source_bytes_hashed"], initial["source_bytes_hashed"])
        self.assertEqual(after["transport_continuity_checks"], 12)
        with self.assertRaises(PermissionError):
            self.rewrite(exe, b"X" * Path(exe["path"]).stat().st_size)
        guard.full_boundary("learner-admission"); guard.full_boundary("release")
        self.assertEqual(guard.metrics()["transport_bytes_hashed"], 3 * initial["transport_bytes_hashed"])
        guard.close()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_transport_artifacts([exe])
        self.assertEqual(caught.exception.reason, "closed")

    def test_transport_role_requires_exact_retained_exe_dll_and_no_source_overlap(self):
        with self.assertRaisesRegex(ValueError, "EXE/DLL"):
            ArtifactIntegrityGuard([self.model], [self.source], self.gate, transport_artifacts=[self.model])
        exe = self.make("declared.exe", b"inert selected binary")
        wrong = dict(exe, sha256="a" * 64)
        with self.assertRaisesRegex(ValueError, "retained pins"):
            ArtifactIntegrityGuard([exe], [self.source], self.gate, transport_artifacts=[wrong])
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            ArtifactIntegrityGuard([exe], [exe], self.gate, transport_artifacts=[exe])

    @unittest.skipUnless(os.name == "nt", "Actual Windows transport lease")
    def test_transport_new_pin_or_unselected_file_refuses_without_read_or_new_authority(self):
        guard, exe = self.transport_guard(); guard.establish()
        before = len(self.calls)
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_transport_artifacts([dict(exe, sha256="f" * 64)])
        self.assertEqual(caught.exception.reason, "unselected-transport-artifact")
        self.assertEqual(len(self.calls), before)
        self.assertTrue(guard.metrics()["poisoned"])

    def test_metadata_only_mode_never_satisfies_transport_lease(self):
        guard, exe = self.transport_guard(protection="metadata-only"); guard.establish()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_transport_artifacts([exe])
        self.assertEqual(caught.exception.reason, "transport-read-lease-required")

    @unittest.skipUnless(os.name == "nt", "Actual Windows transport lease")
    def test_transport_closed_lease_and_exhausted_budget_refuse(self):
        guard, exe = self.transport_guard(maximum=1); guard.establish()
        guard.verify_transport_artifacts([exe])
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_transport_artifacts([exe])
        self.assertEqual(caught.exception.reason, "transport-check-budget")
        guard.close()
        other, other_exe = self.transport_guard(); other.establish()
        other._leases[other_exe["path"]].close()
        with self.assertRaises(ArtifactIntegrityError) as closed:
            other.verify_transport_artifacts([other_exe])
        self.assertEqual(closed.exception.reason, "retained-lease-closed-or-unavailable")

    def test_transport_role_mutation_poisoned_before_reclassification(self):
        guard, exe = self.transport_guard(); guard.establish()
        guard._transport = ()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.verify_dispatch()
        self.assertEqual(caught.exception.reason, "guard-configuration-drift")

    def test_typed_refusal_names_artifact_path(self):
        self.runner["sha256"] = "b" * 64
        guard = self.guard()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            guard.establish()
        self.assertEqual(caught.exception.path, self.runner["path"])
        self.assertIn(self.runner["path"], str(caught.exception))


if __name__ == "__main__":
    unittest.main()
