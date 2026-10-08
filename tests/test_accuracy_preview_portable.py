"""The practice preview is source-bound and isolated from public package tests."""
import json
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch

from lab.accuracy_preview import PREFIX, load_runtime, verify_sources


class PortablePreviewTests(unittest.TestCase):
    def test_cli_offline_checks_preserve_distributed_evidence(self):
        from lab.accuracy_preview import __main__ as cli
        lab = Path(cli.__file__).resolve().parent
        original = (lab / "evidence" / "offline-checks-r01.json").read_bytes()
        paths = []
        def fake_run(argv, *, cwd, timeout):
            isolated = Path(cwd)
            self.assertNotEqual(isolated, lab)
            self.assertTrue((isolated / "controller.py").is_file())
            self.assertEqual(Path(argv[-1]), isolated / "run_offline_checks.py")
            (isolated / "evidence" / "offline-checks-r01.json").write_bytes(b"new check")
            paths.append(isolated)
            return types.SimpleNamespace(returncode=0)
        with patch.object(cli.subprocess, "run", side_effect=fake_run):
            self.assertEqual(cli.main(["--offline-checks"]), 0)
        self.assertEqual((lab / "evidence" / "offline-checks-r01.json").read_bytes(), original)
        self.assertFalse(paths[0].exists())

    def test_import_preserves_public_xnet_and_unrelated_flat_module_names(self):
        import xnet
        import xnet.halo_context_v1
        public_package = sys.modules["xnet"]
        public_halo = sys.modules["xnet.halo_context_v1"]
        before_path = list(sys.path)
        aliases = ("controller", "metadata_bridge", "halo_binding", "frozen_integrations", "repo_agent",
                   "_accuracy_preview_metadata", "_accuracy_preview_common", "_accuracy_preview_public_review")
        prior = {name:sys.modules.get(name) for name in aliases}
        sentinels = {name:types.ModuleType(name) for name in aliases}
        try:
            sys.modules.update(sentinels)
            runtime = load_runtime()
            self.assertTrue(runtime.__name__.startswith(PREFIX + "."))
            self.assertTrue(runtime.adapter.__name__.startswith(PREFIX + "."))
            self.assertTrue(runtime.integrations.metadata.__name__.startswith(PREFIX + "."))
            self.assertIs(sys.modules["xnet"], public_package)
            self.assertIs(sys.modules["xnet.halo_context_v1"], public_halo)
            self.assertEqual(sys.path, before_path)
            for name in aliases: self.assertIs(sys.modules[name], sentinels[name])
            self.assertEqual(runtime.QualityPolicy().validate().max_calls, 24)
            self.assertEqual(len(verify_sources()), 13)
        finally:
            for name in aliases:
                if prior[name] is None: sys.modules.pop(name, None)
                else: sys.modules[name] = prior[name]

    def test_packaged_authored_alignment_suite(self):
        root = Path(__file__).resolve().parents[1]
        lab = root / "lab" / "accuracy_preview"
        # A verification run must not overwrite the distribution's frozen
        # acceptance receipt or invalidate its exact source inventory.
        with tempfile.TemporaryDirectory(prefix="xnet-portable-preview-") as scratch:
            isolated = Path(scratch) / "accuracy_preview"
            shutil.copytree(lab, isolated, ignore=shutil.ignore_patterns("__pycache__"))
            result = subprocess.run([sys.executable,"-B",str(isolated / "run_offline_checks.py")],
                cwd=isolated, capture_output=True, timeout=300)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode("utf-8", "replace")[-16000:])
            receipt = json.loads((isolated / "evidence" / "offline-checks-r01.json").read_bytes())
        self.assertIs(receipt["success"], True)
        self.assertEqual(receipt["tests_run"], 25)
        self.assertIs(receipt["source_stability_confirmed"], True)
        self.assertTrue(all(value == 0 for value in receipt["operations"].values()))


if __name__ == "__main__": unittest.main(verbosity=2)
