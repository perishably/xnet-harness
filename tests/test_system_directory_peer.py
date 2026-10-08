"""Portable source discovery/peer checks; no discovered component execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

from adapters.jcode.system_directory_peer import SystemDirectoryPeer
from xnet import system_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "xnet/data/system-directory.json"


def request(command="query", query="rag", module_id="", limit=8):
    return {"schema": catalog.REQUEST_SCHEMA, "command": command, "query": query, "module_id": module_id, "limit": limit}


class SystemDirectoryPeerTests(unittest.TestCase):
    def setUp(self):
        self.peer = SystemDirectoryPeer(DIRECTORY, source_root=ROOT)

    def test_directory_is_portable_and_source_bound(self):
        directory = catalog.validate_directory(catalog.strict_json(DIRECTORY.read_bytes()))
        self.assertGreater(len(directory["entries"]), 20)
        for row in directory["entries"]:
            self.assertFalse(Path(row["path"]).is_absolute())
            self.assertNotIn("work/", row["path"])
            self.assertNotIn("C:\\", row["path"])
            self.assertTrue(catalog.verify_source(row, workspace_root=ROOT, verify_evidence=True)["source_verified"])

    def test_sampled_actual_sources_include_jcode_and_native(self):
        for name in ("xnet/rag", "xnet/system_catalog", "adapters/jcode/system_directory_peer", "adapters/loopback/stream_index", "rust/crates/xnet-system-index/src/lib"):
            response = self.peer.discover(request("select", module_id=name), verify_selected=True)
            self.assertEqual(response["entries"][0]["module_id"], name)
            self.assertTrue(response["source_checks"][0]["source_verified"])
            self.assertFalse(response["permission_granted"])

    def test_jcode_peer_query_never_executes_or_promotes(self):
        response = self.peer.discover(request("route-plan", query="jcode rag"), verify_selected=True)
        self.assertTrue(response["entries"])
        self.assertEqual(response["executed_commands"], 0)
        self.assertEqual(response["learning_promotions"], 0)
        self.assertFalse(response["permission_granted"])
        self.assertTrue(all(row["status"] == "candidate-needs-current-source-and-caller-gate" for row in response["route_plan"]))

    def test_unverified_file_presence_is_not_promoted_to_verified(self):
        directory = catalog.strict_json(DIRECTORY.read_bytes())
        for row in directory["entries"]:
            if row["status"] in {"verified", "wired"}:
                self.assertTrue(row["evidence"])
            self.assertEqual(row["authority"], "discovery-only")

    def test_invalid_peer_command_refused(self):
        with self.assertRaises(catalog.CatalogError):
            self.peer.discover(request("execute"))

    def test_peer_verification_detects_actual_source_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.py"
            source.write_bytes(b"one")
            row = {"module_id": "fixture/source", "path": "source.py", "source_sha256": catalog.sha256(b"one"), "language": "python", "status": "implemented", "features": ["source"], "call_contract": ["fixture bytes"], "scopes": ["caller-declared"], "side_effects": ["local-read"], "evidence": [], "notes": "Synthetic drift check.", "authority": "discovery-only"}
            directory = root / "directory.json"
            directory.write_bytes(catalog.canonical(catalog.make_directory([row], created_utc="2026-10-08T00:00:00+00:00")))
            peer = SystemDirectoryPeer(directory, source_root=root)
            self.assertTrue(peer.discover(request("select", module_id="fixture/source"), verify_selected=True)["source_checks"][0]["source_verified"])
            source.write_bytes(b"two")
            with self.assertRaises(catalog.CatalogError):
                peer.discover(request("select", module_id="fixture/source"), verify_selected=True)

    def test_builder_is_repeatable_for_an_explicit_timestamp(self):
        spec = importlib.util.spec_from_file_location("public_builder_test", ROOT / "scripts/build_system_directory.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        first = builder.build_directory(created_utc="2026-10-08T00:00:00+00:00")
        second = builder.build_directory(created_utc="2026-10-08T00:00:00+00:00")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
