"""Read-only fixtures for the XNET component update boundary."""

from __future__ import annotations

import hashlib
from importlib import resources as package_resources
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from xnet import component_updates
from xnet.component_updates import (
    ComponentUpdateCenter,
    ComponentUpdateRefusal,
    FetchedResource,
    ProcessResult,
    canonical_json,
)


PROJECT = Path(__file__).resolve().parents[1]


class _ExplosivePath:
    def __init__(self) -> None:
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        raise AssertionError("mutation inspected the stage path")


class ComponentUpdateFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="xnet-component-update-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.notice = b"MIT fixture notice\n"

    def fixture(self, *, version: str = "1.2.0", artifact: bytes = b"fixed jcode fixture"):
        tag = "v" + version
        name = "jcode-windows-x86_64.exe"
        origin = "https://github.com/example/jcode"
        artifact_sha = hashlib.sha256(artifact).hexdigest()
        checksums = f"{artifact_sha}  {name}\n".encode("ascii")
        manifest = {
            "schema": "xnet.component-manifest.v1",
            "components": [{
                "id": "jcode",
                "name": "Jcode fixture",
                "official_origin": origin,
                "channel": "stable",
                "update_supported": False,
                "update_reason": "mutation-disabled-in-v0.1.0",
                "update_mode": "check-only",
                "release_policy": "pinned-stable",
                "pinned": {
                    "version": version,
                    "tag": tag,
                    "commit": "a" * 40,
                    "tag_object": "b" * 40,
                    "release_id": 42,
                    "published_at": "2026-10-07T00:00:00Z",
                    "release_url": f"{origin}/releases/tag/{tag}",
                    "release_api_url": f"https://api.github.com/repos/example/jcode/releases/tags/{tag}",
                },
                "license": {
                    "spdx": "MIT",
                    "notice_path": "NOTICE.txt",
                    "notice_sha256": hashlib.sha256(self.notice).hexdigest(),
                },
                "checksum_manifest": {
                    "name": "SHA256SUMS",
                    "size": len(checksums),
                    "sha256": hashlib.sha256(checksums).hexdigest(),
                },
                "release_assets": {
                    name: {"size": len(artifact), "sha256": artifact_sha},
                },
                "platform_assets": {"windows/x86_64": name},
                "version_probe": {
                    "argv": ["jcode", "--version"],
                    "stdout_regex": "^jcode v?(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)(?: \\([0-9a-f]{7,40}\\))?\\r?\\n?$",
                },
            }],
        }
        component = manifest["components"][0]
        asset_url = f"{origin}/releases/download/{tag}/{name}"
        checksum_url = f"{origin}/releases/download/{tag}/SHA256SUMS"
        metadata = {
            "id": 42,
            "tag_name": tag,
            "html_url": component["pinned"]["release_url"],
            "published_at": component["pinned"]["published_at"],
            "draft": False,
            "prerelease": False,
            "assets": [
                {
                    "name": name,
                    "browser_download_url": asset_url,
                    "size": len(artifact),
                    "state": "uploaded",
                    "digest": "sha256:" + artifact_sha,
                },
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": checksum_url,
                    "size": len(checksums),
                    "state": "uploaded",
                    "digest": "sha256:" + hashlib.sha256(checksums).hexdigest(),
                },
            ],
        }
        resources = {
            component["pinned"]["release_api_url"]: canonical_json(metadata),
            checksum_url: checksums,
            asset_url: artifact,
        }
        center = ComponentUpdateCenter(manifest)
        return center, manifest, metadata, resources, artifact

    @staticmethod
    def fetcher(resources, calls=None):
        def fetch(url):
            if calls is not None:
                calls.append(url)
            return FetchedResource(url=url, body=resources[url])
        return fetch

    def check(self, center, resources, *, current="1.1.0"):
        return center.check("jcode", current_version=current, system="Windows",
                            architecture="AMD64", fetcher=self.fetcher(resources))

    def assert_refusal(self, reason, callable_):
        with self.assertRaises(ComponentUpdateRefusal) as caught:
            callable_()
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_default_manifest_is_an_installed_package_resource(self):
        resource = package_resources.files("xnet").joinpath("data", "components.json")
        self.assertTrue(resource.is_file())
        self.assertEqual(resource.read_bytes(), component_updates.DEFAULT_MANIFEST_PATH.read_bytes())

        missing_source_path = self.root / "missing-source-layout" / "components.json"
        with patch.object(component_updates, "DEFAULT_MANIFEST_PATH", missing_source_path):
            center = ComponentUpdateCenter.from_default_manifest()
        self.assertEqual([row["id"] for row in center.inventory()["components"]],
                         ["jcode", "xnet"])

        packaging = tomllib.loads((PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
        package_data = packaging["tool"]["setuptools"]["package-data"]
        self.assertIn("data/components.json", package_data["xnet"])
        self.assertEqual(
            package_data["adapters.dojo"],
            ["assets/*.html", "assets/*.js", "assets/*.css"],
        )

    def test_official_registry_preserves_jcode_pin_and_disables_mutation(self):
        center = ComponentUpdateCenter.from_default_manifest()
        manifest = {row["id"]: row for row in center.manifest["components"]}
        jcode = manifest["jcode"]
        self.assertEqual(jcode["pinned"]["version"], "0.91.0")
        self.assertEqual(jcode["pinned"]["commit"], "439a243bb49a78456923f4abd412ddd8d815bac1")
        self.assertEqual(jcode["pinned"]["tag_object"], "d2ffcd62c9bc540dd913a046d62cdc0307b5e189")
        self.assertEqual(jcode["checksum_manifest"]["sha256"],
                         "63120e62fb3cb6cfdae429ac23a32c54f179f10296bff5b7191848e0c770799c")
        expected_assets = {
            "jcode-freebsd-x86_64.tar.gz": (40925876, "8d6f70da0e460e70de5b38f0e3be24ab8d1012106d713f86bbb8f699d1aa5de9"),
            "jcode-linux-aarch64.tar.gz": (45247700, "b73b76f7fc8fd8d4d3b11851525452e8d41bec88b01a40eaaa8c4c81551e5081"),
            "jcode-linux-x86_64.tar.gz": (43049151, "74e9426b0a8e26c5fcff7803d6a5716f8294d1158fa63feb1b429450ac3f705e"),
            "jcode-macos-aarch64.tar.gz": (45277957, "5bb77022d9771e71358cb6a3e495f420170cb259f2191f6095fd9b7d9cd3037c"),
            "jcode-macos-x86_64.tar.gz": (47684988, "fa84b54c85ef0dde6680e94399b08f3e73938d47619808332f6cab0596587548"),
            "jcode-windows-aarch64.exe": (86703104, "39e7dd194ddcce3332569834fd7a8771eb3c08448ad9c84a38b20fd14fb24959"),
            "jcode-windows-aarch64.tar.gz": (31820337, "32009ea13d3c2b3ce4048062748c35dd4af3483b434b527007320b75915b0c4d"),
            "jcode-windows-x86_64.exe": (115020288, "01cfad20a9a7ba4c5f9bd0ad65942a61c1e5c4303688067d58f65f479e50d327"),
            "jcode-windows-x86_64.tar.gz": (37703256, "789e132d596d43ad4a8ca3d965f067b0a93d278d8db82899178ce30dbdb9a79a"),
        }
        self.assertEqual(
            {name: (row["size"], row["sha256"]) for name, row in jcode["release_assets"].items()},
            expected_assets,
        )
        checksum_bytes = b"".join(
            f"{digest}  {name}\n".encode("ascii")
            for name, (_, digest) in expected_assets.items()
        )
        self.assertEqual(len(checksum_bytes), 836)
        self.assertEqual(hashlib.sha256(checksum_bytes).hexdigest(),
                         jcode["checksum_manifest"]["sha256"])
        self.assertEqual(jcode["platform_assets"]["windows/x86_64"],
                         "jcode-windows-x86_64.exe")
        self.assertEqual(jcode["update_mode"], "check-only")
        self.assertFalse(jcode["update_supported"])
        self.assertEqual(jcode["update_reason"], "mutation-disabled-in-v0.1.0")
        self.assertTrue(all(not row["update_supported"] for row in manifest.values()))
        self.assertIsNone(manifest["xnet"]["pinned"]["commit"])

    def test_check_is_read_only_and_does_not_fetch_artifact(self):
        center, _, _, resources, _ = self.fixture()
        network_calls = []
        check = center.check("jcode", current_version="1.1.0", system="win32",
                             architecture="x64", fetcher=self.fetcher(resources, network_calls))
        self.assertEqual(check.status, "update_available")
        self.assertEqual(check.asset_name, "jcode-windows-x86_64.exe")
        self.assertEqual(len(network_calls), 2)
        self.assertTrue(network_calls[0].startswith("https://api.github.com/"))
        self.assertTrue(network_calls[1].endswith("/SHA256SUMS"))
        self.assertFalse(any(url.endswith(".exe") for url in network_calls))
        self.assertEqual(check.receipt, canonical_json(check.as_dict()))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_process_probe_is_only_called_by_explicit_probe(self):
        center, _, _, resources, _ = self.fixture()
        calls = []

        def runner(argv):
            calls.append(argv)
            return ProcessResult(0, "jcode v1.2.0 (abcdef0)\n")

        self.check(center, resources)
        self.assertEqual(calls, [])
        self.assertEqual(center.probe_current_version("jcode", runner), "1.2.0")
        self.assertEqual(calls, [("jcode", "--version")])

    def test_all_mutations_refuse_before_fetch_or_filesystem_effects(self):
        center, _, _, resources, _ = self.fixture()
        check = self.check(center, resources)
        stage_path = _ExplosivePath()
        mutation_fetch_calls = []

        def mutation_fetch(url):
            mutation_fetch_calls.append(url)
            raise AssertionError("mutation called the fetcher")

        before = list(self.root.iterdir())
        stage_error = self.assert_refusal("mutation-disabled", lambda: center.stage(
            check, stage_root=stage_path, fetcher=mutation_fetch))
        apply_error = self.assert_refusal("mutation-disabled", lambda: center.apply(
            "jcode", stage_root=stage_path, system="windows", architecture="amd64"))
        rollback_error = self.assert_refusal("mutation-disabled", lambda: center.rollback(
            "jcode", stage_root=stage_path))

        self.assertEqual((stage_error.phase, apply_error.phase, rollback_error.phase),
                         ("stage", "apply", "rollback"))
        self.assertEqual(stage_path.calls, 0)
        self.assertEqual(mutation_fetch_calls, [])
        self.assertEqual(list(self.root.iterdir()), before)

    def test_mutations_refuse_even_malformed_or_unknown_inputs(self):
        center, _, _, _, _ = self.fixture()
        stage_path = _ExplosivePath()
        self.assert_refusal("mutation-disabled", lambda: center.stage(
            object(), stage_root=stage_path, fetcher=lambda _: None))
        self.assert_refusal("mutation-disabled", lambda: center.apply(
            "not-registered", stage_root=stage_path, system="plan9", architecture="mips"))
        self.assert_refusal("mutation-disabled", lambda: center.rollback(
            "not-registered", stage_root=stage_path))
        self.assertEqual(stage_path.calls, 0)

    def test_unsupported_report_only_component_cannot_stage(self):
        center = ComponentUpdateCenter.from_default_manifest()
        xnet = next(row for row in center.manifest["components"] if row["id"] == "xnet")
        metadata = canonical_json({
            "id": 99,
            "tag_name": "v0.2.0",
            "html_url": "https://github.com/perishably/xnet-harness/releases/tag/v0.2.0",
            "published_at": "2026-10-08T00:00:00Z",
            "draft": False,
            "prerelease": False,
            "assets": [],
        })
        url = xnet["pinned"]["release_api_url"]
        check = center.check("xnet", current_version="0.1.0",
                             fetcher=self.fetcher({url: metadata}))
        mutation_calls = []
        self.assert_refusal("mutation-disabled", lambda: center.stage(
            check,
            stage_root=_ExplosivePath(),
            fetcher=lambda requested: mutation_calls.append(requested),
        ))
        self.assertEqual(mutation_calls, [])

    def test_manifest_cannot_enable_v010_mutation(self):
        _, manifest, _, _, _ = self.fixture()
        manifest["components"][0]["update_supported"] = True
        manifest["components"][0]["update_reason"] = None
        self.assert_refusal("manifest-format", lambda: ComponentUpdateCenter(manifest))

        _, manifest, _, _, _ = self.fixture()
        manifest["components"][0]["update_mode"] = "stage-select"
        self.assert_refusal("manifest-format", lambda: ComponentUpdateCenter(manifest))

    def test_prerelease_is_refused(self):
        center, _, metadata, resources, _ = self.fixture()
        metadata["prerelease"] = True
        resources[next(iter(resources))] = canonical_json(metadata)
        self.assert_refusal("prerelease-refused", lambda: self.check(center, resources))

    def test_wrong_release_and_asset_origins_are_refused(self):
        center, _, metadata, resources, _ = self.fixture()
        metadata["html_url"] = "https://github.com/attacker/jcode/releases/tag/v1.2.0"
        resources[next(iter(resources))] = canonical_json(metadata)
        self.assert_refusal("wrong-origin", lambda: self.check(center, resources))

        center, _, metadata, resources, _ = self.fixture()
        metadata["assets"][0]["browser_download_url"] = "https://example.invalid/jcode.exe"
        resources[next(iter(resources))] = canonical_json(metadata)
        self.assert_refusal("wrong-origin", lambda: self.check(center, resources))

    def test_returned_url_mismatch_is_refused(self):
        center, manifest, _, resources, _ = self.fixture()
        url = manifest["components"][0]["pinned"]["release_api_url"]

        def redirected(_requested):
            return FetchedResource("https://attacker.invalid/release", resources[url])

        self.assert_refusal("fetch-result-format", lambda: center.check(
            "jcode", current_version="1.1.0", system="windows", architecture="amd64",
            fetcher=redirected,
        ))

    def test_missing_checksum_and_traversal_asset_are_refused(self):
        center, _, metadata, resources, _ = self.fixture()
        metadata["assets"] = metadata["assets"][:1]
        resources[next(iter(resources))] = canonical_json(metadata)
        self.assert_refusal("missing-checksum", lambda: self.check(center, resources))

        center, _, metadata, resources, _ = self.fixture()
        metadata["assets"].insert(0, {
            "name": "../escape.exe",
            "browser_download_url": "https://github.com/example/jcode/releases/download/v1.2.0/escape.exe",
            "size": 1,
        })
        resources[next(iter(resources))] = canonical_json(metadata)
        self.assert_refusal("path-traversal", lambda: self.check(center, resources))

    def test_checksum_hash_mismatch_is_refused(self):
        center, _, _, resources, _ = self.fixture()
        checksum_url = next(url for url in resources if url.endswith("SHA256SUMS"))
        resources[checksum_url] = b"0" * 64 + b"  jcode-windows-x86_64.exe\n"
        self.assert_refusal("hash-mismatch", lambda: self.check(center, resources))

    def test_downgrade_and_unsupported_platform_are_refused(self):
        center, _, _, resources, _ = self.fixture()
        self.assert_refusal("downgrade-refused", lambda: self.check(
            center, resources, current="1.3.0"))
        calls = []
        self.assert_refusal("unsupported-platform", lambda: center.check(
            "jcode", current_version="1.1.0", system="plan9", architecture="mips64",
            fetcher=self.fetcher(resources, calls)))
        self.assertEqual(calls, [])

    def test_materialized_response_limits_are_enforced(self):
        center, manifest, _, resources, _ = self.fixture()
        api_url = manifest["components"][0]["pinned"]["release_api_url"]
        resources[api_url] = b"x" * (2 * 1024 * 1024 + 1)
        self.assert_refusal("response-too-large", lambda: self.check(center, resources))

        center, _, _, resources, _ = self.fixture()
        checksum_url = next(url for url in resources if url.endswith("SHA256SUMS"))
        resources[checksum_url] = b"x" * (64 * 1024 + 1)
        self.assert_refusal("response-too-large", lambda: self.check(center, resources))

    def test_duplicate_release_json_key_is_refused(self):
        center, manifest, _, resources, _ = self.fixture()
        api_url = manifest["components"][0]["pinned"]["release_api_url"]
        resources[api_url] = b'{"id":42,"id":43}\n'
        self.assert_refusal("duplicate-json-key", lambda: self.check(center, resources))


if __name__ == "__main__":
    unittest.main()
