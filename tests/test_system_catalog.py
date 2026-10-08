import copy
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parent
from xnet import system_catalog as catalog


def row(name="rag", *, status="implemented", pin="a" * 64):
    return {"module_id": "demo/" + name, "path": name + ".py", "source_sha256": pin, "language": "python", "status": status, "features": [name], "call_contract": ["function query"], "scopes": ["caller-declared"], "side_effects": ["local-read"], "evidence": [], "notes": "Synthetic protocol fixture; no model capability claim.", "authority": "discovery-only"}


def directory(rows=None):
    return catalog.make_directory(rows or [row()], created_utc="2026-10-08T00:00:00+00:00")


def request(command="query", query="rag", module_id="", limit=8):
    return {"schema": catalog.REQUEST_SCHEMA, "command": command, "query": query, "module_id": module_id, "limit": limit}


class CatalogTests(unittest.TestCase):
    def test_directory_roundtrip(self):
        value = directory()
        self.assertEqual(catalog.validate_directory(catalog.strict_json(catalog.canonical(value))), value)

    def test_query_is_deterministic(self):
        value = directory([row("rag"), row("rag_other")])
        self.assertEqual(catalog.handle_request(value, request()), catalog.handle_request(value, request()))

    def test_select_unknown_module_refused(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.handle_request(directory(), request("select", module_id="unknown"))

    def test_unknown_command_refused(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.handle_request(directory(), request("execute"))

    def test_permission_not_granted(self):
        result = catalog.handle_request(directory(), request("route-plan"))
        self.assertFalse(result["permission_granted"])
        self.assertEqual(result["executed_commands"], 0)
        self.assertEqual(result["learning_promotions"], 0)

    def test_metadata_permission_claim_refused(self):
        value = row()
        value["authority"] = "execute"
        with self.assertRaises(catalog.CatalogError):
            directory([value])

    def test_verified_without_evidence_refused(self):
        with self.assertRaises(catalog.CatalogError):
            directory([row(status="verified")])

    def test_wrong_source_evidence_refused(self):
        value = row(status="verified")
        value["evidence"] = [{"path": "report.json", "sha256": "b" * 64, "source_sha256": "c" * 64, "claim": "offline-check"}]
        with self.assertRaises(catalog.CatalogError):
            directory([value])

    def test_wired_without_binding_refused(self):
        with self.assertRaises(catalog.CatalogError):
            directory([row(status="wired")])

    def test_pending_without_source_allowed_but_not_routed(self):
        value = row(status="pending", pin=None)
        result = catalog.handle_request(directory([value]), request("route-plan"))
        self.assertEqual(result["route_plan"], [])

    def test_inactive_does_not_enter_route_plan(self):
        result = catalog.handle_request(directory([row(status="inactive")]), request("route-plan"))
        self.assertEqual(result["route_plan"], [])

    def test_path_traversal_refused(self):
        value = row()
        value["path"] = "../secret.py"
        with self.assertRaises(catalog.CatalogError):
            directory([value])

    def test_protected_dataset_refused(self):
        value = row()
        value["path"] = "data/private.parquet"
        with self.assertRaises(catalog.CatalogError):
            directory([value])

    def test_bool_limit_refused(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.handle_request(directory(), request(limit=True))

    def test_source_drift_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rag.py").write_bytes(b"actual")
            value = row(pin=catalog.sha256(b"actual"))
            self.assertTrue(catalog.verify_source(value, workspace_root=root)["source_verified"])
            (root / "rag.py").write_bytes(b"changed")
            with self.assertRaises(catalog.CatalogError):
                catalog.verify_source(value, workspace_root=root)

    def test_directory_mutation_detected(self):
        value = directory()
        value["entries"][0]["notes"] = "changed"
        with self.assertRaises(catalog.CatalogError):
            catalog.validate_directory(value)

    def test_duplicate_json_field_refused(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.strict_json(b'{"schema":1,"schema":2}')

    def test_unknown_schema_field_refused(self):
        value = row()
        value["command"] = "dangerous"
        with self.assertRaises(catalog.CatalogError):
            directory([value])

    def test_side_effects_cannot_mix_none(self):
        value = row()
        value["side_effects"] = ["local-read", "none"]
        with self.assertRaises(catalog.CatalogError):
            directory([value])

    def test_actual_selected_sources_verify_with_explicit_mounts(self):
        choices = ['xnet/rag.py', 'rust/crates/xnet-storage/src/lib.rs', 'adapters/loopback/stream_index.py']
        for relative in choices:
            source = WORKSPACE / relative
            entry = row(pin=catalog.sha256(source.read_bytes()))
            entry['path'] = relative
            self.assertTrue(catalog.verify_source(entry, workspace_root=WORKSPACE)['source_verified'])

    def test_explicit_mount_nested_escape_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root / "public"
            public.mkdir()
            (public / "rag.py").write_bytes(b"actual")
            value = row(pin=catalog.sha256(b"actual"))
            value["path"] = "outputs/rag.py"
            self.assertTrue(catalog.verify_source(value, workspace_root=root, mounts={"outputs": public})["source_verified"])

    def test_cross_language_fixture_replay(self):
        value = catalog.strict_json((ROOT / "fixtures/system-index-v1.json").read_bytes())
        for case in value["cases"]:
            self.assertEqual(catalog.handle_request(value["directory"], case["request"]), case["expected_response"])


if __name__ == "__main__":
    unittest.main()
