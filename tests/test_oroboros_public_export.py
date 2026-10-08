"""Public export and transport evidence controls; no actual provider calls."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from adapters.openclaw import make_source_packet
from xnet.oroboros_public_export import (
    PROVIDER_DOWNLOAD_SCHEMA, PublicArchiveStage, PublicExportError, PublicExportTools,
    build_public_export, export_public_artifacts, verify_public_readback,
)
from xnet.protocol import canonical, digest, sha256
from xnet.scope import ScopeAuthority, ScopeError
from xnet.oroboros_sphere import SphereController, bootstrap_config


class PublicExportTests(unittest.TestCase):
    def packet(self):
        return make_source_packet(task_id="public-export-fixture", producer="operator",
                                  kind="note", packet_id="public-export-a",
                                  text="Public source: C to D to Proton to Google to C.")

    def built(self):
        return build_public_export(namespace="XNET/public/r01", capsules=[self.packet()])

    def readback(self, built, **kwargs):
        path, raw = next(iter(built["objects"].items()))
        return verify_public_readback(built["manifest"], path, raw,
                                      namespace="XNET/public/r01", **kwargs)

    def test_receipt_projection_excludes_control_and_grading_material(self):
        private = "synthetic-private-control-material"
        original = {"schema": "private.receipt.v1", "task_id": "public-export-fixture",
                    "status": "completed", "head": "a" * 64, "model_calls": 0,
                    "signature_hmac_sha256": "b" * 64, "scope_key": private,
                    "sqlite": private, "hidden_originals": private,
                    "model_bytes": private, "payload": {"text": private},
                    "path": "C:/private/control/keys/scope.hmac"}
        built = build_public_export(namespace="XNET/public/r01", receipts=[original])
        raw = next(iter(built["objects"].values()))
        self.assertNotIn(private.encode(), raw)
        self.assertNotIn(b"scope.hmac", raw)
        self.assertNotIn(b"signature_hmac", raw)
        projected = json.loads(raw)
        self.assertEqual(projected["origin_receipt_sha256"], digest(original))
        self.assertEqual(projected["head"], original["head"])
        self.assertEqual(projected["authority"], "none")
        self.assertEqual(built["manifest"]["network_calls"], 0)

    def test_directory_bytes_and_generic_capsules_are_refused(self):
        for value in (Path("C:/private"), "C:/private", b"model-bytes", [{"files": ["scope.hmac"]}]):
            with self.subTest(value=type(value).__name__), self.assertRaises(PublicExportError):
                build_public_export(namespace="XNET/public/r01", capsules=value)
        for packet in ({"text": "ordinary source"}, {**self.packet(), "classification": "private"},
                       {**self.packet(), "authority": "scope-admin"}):
            with self.assertRaises(PublicExportError):
                build_public_export(namespace="XNET/public/r01", capsules=[packet])

    def test_known_secret_source_and_tampering_are_refused(self):
        packet = self.packet()
        body = {k: v for k, v in packet.items() if k != "packet_sha256"}
        body["text"] = "-----BEGIN " + "PRIVATE KEY-----\nsynthetic-only\n"
        body["text_sha256"] = sha256(body["text"].encode())
        secret = {**body, "packet_sha256": digest(body)}
        with self.assertRaises(PublicExportError):
            build_public_export(namespace="XNET/public/r01", sources=[secret])
        with self.assertRaises(PublicExportError):
            build_public_export(namespace="XNET/public/r01", sources=[{**packet, "text": "changed"}])

    def test_empty_oversized_and_traversal_exports_are_refused(self):
        with self.assertRaises(PublicExportError):
            build_public_export(namespace="XNET/public/r01")
        with self.assertRaises(PublicExportError):
            build_public_export(namespace="XNET/public/r01", capsules=[self.packet()] * 65)
        for namespace in ("../private", "/private", "XNET/../keys", "XNET\\keys", "XNET//keys"):
            with self.subTest(namespace=namespace), self.assertRaises(PublicExportError):
                build_public_export(namespace=namespace, sources=[self.packet()])
        with self.assertRaises(PublicExportError):
            build_public_export(namespace="XNET/public", receipts=[{"payload": "x" * 70_000}])

    def test_historical_archive_preserves_lifetime_and_future_source_is_refused(self):
        packet = make_source_packet(task_id="archive-fixture", producer="operator", kind="note",
                                    packet_id="archive-a", text="Public historical note.",
                                    now=1, ttl_seconds=1)
        built = build_public_export(namespace="XNET/archive/r01", sources=[packet])
        archived = json.loads(next(iter(built["objects"].values())))
        self.assertEqual(archived, packet)
        self.assertEqual(archived["expires_at"], 2)
        future = make_source_packet(task_id="archive-fixture", producer="operator", kind="note",
                                    packet_id="archive-future", text="Public future note.",
                                    now=int(time.time()) + 60)
        with self.assertRaises(PublicExportError):
            build_public_export(namespace="XNET/archive/r01", sources=[future])

    def test_local_and_client_readback_never_credit_remote_verification(self):
        built = self.built()
        for level in ("local", "client_folder", "injected_test"):
            result = self.readback(built, evidence_level=level)
            self.assertTrue(result["hash_verified"])
            self.assertFalse(result["remote_cloud_verified"])
            self.assertEqual(result["evidence_level"], level)
        with self.assertRaises(PublicExportError):
            self.readback(built, evidence_level="client_folder", provider_download={"verified": True})

    def provider_observation(self, built):
        path, raw = next(iter(built["objects"].items()))
        body = {"schema": PROVIDER_DOWNLOAD_SCHEMA, "provider": "google",
                "namespace": "XNET/public/r01", "parent_id": "fixture-provider-folder",
                "observed_parent_id": "fixture-provider-folder", "object_id": "fixture-provider-file",
                "observed_object_id": "fixture-provider-file", "member_path": path,
                "sha256": sha256(raw), "bytes": len(raw),
                "transport": "google_drive_connector_raw_download"}
        return {**body, "receipt_sha256": digest(body)}

    def test_provider_contract_requires_raw_bytes_hash_and_exact_namespace(self):
        # Synthetic metadata proves validation behavior only, never live access.
        built = self.built()
        observation = self.provider_observation(built)
        result = self.readback(built, evidence_level="provider_download", provider_download=observation)
        self.assertEqual(result["provider_observation_sha256"], observation["receipt_sha256"])
        self.assertFalse(result["provider_authentication_attested_by_helper"])
        mutations = {"namespace": "XNET/other", "observed_parent_id": "different-folder",
                     "observed_object_id": "different-file", "transport": "client_folder_read",
                     "sha256": "0" * 64, "bytes": True, "receipt_sha256": "0" * 64}
        for field, value in mutations.items():
            changed = {**observation, field: value}
            if field != "receipt_sha256":
                changed["receipt_sha256"] = digest({k: v for k, v in changed.items() if k != "receipt_sha256"})
            with self.subTest(field=field), self.assertRaises(PublicExportError):
                self.readback(built, evidence_level="provider_download", provider_download=changed)
        with self.assertRaises(PublicExportError):
            self.readback(built, evidence_level="provider_download")

    def test_tampered_manifest_wrong_namespace_or_changed_bytes_are_refused(self):
        built = self.built()
        path, raw = next(iter(built["objects"].items()))
        with self.assertRaises(PublicExportError):
            verify_public_readback(built["manifest"], path, raw + b" ", evidence_level="local",
                                   namespace="XNET/public/r01")
        with self.assertRaises(PublicExportError):
            verify_public_readback(built["manifest"], path, raw, evidence_level="local", namespace="XNET/other")
        changed = {**built["manifest"], "authority": "admin"}
        changed["manifest_sha256"] = digest({k: v for k, v in changed.items() if k != "manifest_sha256"})
        with self.assertRaises(PublicExportError):
            verify_public_readback(changed, path, raw, evidence_level="local", namespace="XNET/public/r01")

    def test_export_requires_signed_scope_is_idempotent_and_preserves_conflicts(self):
        with tempfile.TemporaryDirectory(prefix="xnet public export ") as temporary:
            base = Path(temporary).absolute()
            destination = base / "public"
            authority = ScopeAuthority(base / "private")
            scope = authority.create(program="public fixture export", policy_url="local:fixture",
                                     policy_capture=b"explicit bounded public fixture export",
                                     allowed_assets=["path:" + str(destination)],
                                     methods=list(PublicExportTools.METHODS), fixture=True)
            kwargs = dict(namespace="XNET/public/r01", capsules=[self.packet()],
                          authority=authority, scope_id=scope["scope_id"])
            with self.assertRaises(PublicExportError):
                PublicExportTools(authority).publish(scope["scope_id"], destination / "keys/scope.hmac",
                                                     b"synthetic-private-key", destination)
            self.assertFalse(destination.exists())
            manifest = export_public_artifacts(destination, **kwargs)
            files = {p.relative_to(destination).as_posix(): p.read_bytes()
                     for p in destination.rglob("*") if p.is_file()}
            self.assertEqual(len(files), 2)
            self.assertNotIn("keys/scope.hmac", files)
            self.assertEqual(export_public_artifacts(destination, **kwargs), manifest)
            member = manifest["members"][0]["path"]
            (destination / member).write_bytes(b"corruption")
            with self.assertRaises(PublicExportError):
                export_public_artifacts(destination, **kwargs)
            self.assertEqual((destination / member).read_bytes(), b"corruption")
            denied = base / "outside"
            with self.assertRaises(ScopeError):
                export_public_artifacts(denied, **kwargs)
            self.assertFalse(denied.exists())


class PublicArchiveStageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="xnet public archive ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).absolute()
        roots = {key: self.base / key for key in ("c_nvme", "d_4tb", "proton", "google")}
        for root in roots.values():
            root.mkdir()
        control = self.base / "sphere-private"
        config = control / "config.json"
        bootstrap_config(config, control, roots)
        self.sphere = SphereController(config)
        self.public = self.base / "public"
        self.authority = ScopeAuthority(self.base / "export-private")
        self.scope_id = self.authority.create(program="public archive fixture", policy_url="local:fixture",
            policy_capture=b"fixed public sphere archive fixture",
            allowed_assets=["path:" + str(self.public), "path:" + str(self.authority.data_dir)],
            methods=list(PublicArchiveStage.METHODS), requests_per_minute=600, fixture=True)["scope_id"]
        self.stage = PublicArchiveStage(self.sphere, self.public, namespace="XNET/public/archive",
                                        authority=self.authority, scope_id=self.scope_id)

    def request(self, *, remote=False, private_text="synthetic-private-held-out-original"):
        return {"schema": "xnet.oroboros-outer-request.v1", "task_id": "archive-fixture",
                "stage": "archive", "reservation_id": "archive-reservation-a",
                "scope_id": "outer-fixture-scope",
                "payload": {"private_original": private_text,
                            "archive": {"public_summary": "Public archive fixture summary.",
                                        "require_remote": remote}},
                "previous": {"work": {"candidate": private_text}, "validate": {"hidden": private_text}}}

    def test_borrowed_sphere_four_fetches_safe_exports_and_replay(self):
        request = self.request()
        result = self.stage.stage(request)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["outer_reservation_id"], request["reservation_id"])
        self.assertEqual(result["verified_fetches"], 4)
        self.assertEqual(result["hop_count"], 4)
        self.assertEqual(result["public_export_members"], 3)
        objects = [path.read_bytes() for path in self.public.rglob("*.json")]
        self.assertEqual(len(objects), 4)
        for raw in objects:
            self.assertNotIn(b"synthetic-private-held-out-original", raw)
            self.assertNotIn(b"scope.hmac", raw)
            self.assertNotIn(b"signature_hmac_sha256", raw)
        self.assertFalse(result["provider_readiness"]["proton"]["remote_cloud_verified"])
        # Other sphere traffic changes the current ledger head, but not the
        # immutable archive export's public metadata or reservation identity.
        other = make_source_packet(task_id="another-task", producer="operator", kind="note",
                                   text="Another public source.", packet_id="another-packet")
        self.sphere.cycle(other, "powershell")
        replay = self.stage.stage(request)
        self.assertEqual(replay["manifest_sha256"], result["manifest_sha256"])
        self.assertEqual(replay["packet_sha256"], result["packet_sha256"])
        self.assertEqual(len([p for p in self.public.rglob("*.json")]), 4)

    def test_required_remote_download_remains_waiting_after_local_completion(self):
        result = self.stage.stage(self.request(remote=True))
        self.assertEqual(result["status"], "waiting")
        self.assertEqual(result["outer_reservation_id"], "archive-reservation-a")
        self.assertEqual(result["verified_fetches"], 4)
        self.assertEqual(result["provider_readback_receipts"], {})
        self.assertTrue(all(row["evidence_level"] == "client_folder"
                            and row["remote_cloud_verified"] is False
                            for row in result["provider_readiness"].values()))

    def test_changed_reservation_private_input_and_private_root_overlap_refused(self):
        self.stage.stage(self.request())
        with self.assertRaises(PublicExportError):
            self.stage.stage(self.request(private_text="changed-original"))
        with self.assertRaises(PublicExportError):
            PublicArchiveStage(self.sphere, self.authority.data_dir / "public", namespace="XNET/public/archive",
                               authority=self.authority, scope_id=self.scope_id)

    def test_model_previous_output_cannot_fill_missing_public_summary(self):
        request = self.request()
        request["payload"].pop("archive")
        with self.assertRaises(PublicExportError):
            self.stage.stage(request)
        self.assertEqual(self.sphere.plan()["packets"], 0)


if __name__ == "__main__":
    unittest.main()
