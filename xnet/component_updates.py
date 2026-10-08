"""Verified component inventory and read-only release checks.

This module deliberately has no HTTP client and imports no process launcher.
Callers must provide a fetch callback for each networked operation and may
provide a process callback only to the explicit version-probe method.  XNET
v0.1.0 exposes no staging, apply, rollback, extraction, or execution path.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import hmac
from importlib import resources
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Callable, Mapping, NoReturn
from urllib.parse import urlsplit


MANIFEST_SCHEMA = "xnet.component-manifest.v1"
CHECK_SCHEMA = "xnet.component-check-receipt.v1"
DEFAULT_MANIFEST_RESOURCE = "data/components.json"
DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent / "data" / "components.json"
_MAX_MANIFEST_BYTES = 1024 * 1024

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SEMVER = re.compile(r"^(?:v)?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
_SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SAFE_ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,254})$")
_OS_ALIASES = {
    "darwin": "macos",
    "freebsd": "freebsd",
    "linux": "linux",
    "macos": "macos",
    "win32": "windows",
    "windows": "windows",
}
_ARCH_ALIASES = {
    "aarch64": "aarch64",
    "amd64": "x86_64",
    "arm64": "aarch64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
}
_COMPONENT_KEYS = {
    "id",
    "name",
    "official_origin",
    "channel",
    "update_supported",
    "update_reason",
    "update_mode",
    "release_policy",
    "pinned",
    "license",
    "checksum_manifest",
    "release_assets",
    "platform_assets",
    "version_probe",
}
_PINNED_KEYS = {
    "version",
    "tag",
    "commit",
    "tag_object",
    "release_id",
    "published_at",
    "release_url",
    "release_api_url",
}
_LICENSE_KEYS = {"spdx", "notice_path", "notice_sha256"}
_CHECKSUM_KEYS = {"name", "size", "sha256"}
_ASSET_KEYS = {"size", "sha256"}
_PROBE_KEYS = {"argv", "stdout_regex"}
class ComponentUpdateRefusal(RuntimeError):
    """A typed fail-closed refusal from the component update boundary."""

    def __init__(
        self,
        reason: str,
        *,
        phase: str,
        component: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.reason = reason
        self.phase = phase
        self.component = component
        self.detail = detail
        text = f"component update refused: {reason} during {phase}"
        if component:
            text += f" for {component}"
        if detail:
            text += f" ({detail})"
        super().__init__(text)


@dataclass(frozen=True)
class FetchedResource:
    """Bytes and effective URL reported by a caller-owned, policy-enforcing fetcher."""

    url: str
    body: bytes
    status: int = 200


@dataclass(frozen=True)
class ProcessResult:
    """Result returned by a caller-owned, shell-free version probe."""

    returncode: int
    stdout: str | bytes
    stderr: str | bytes = ""


@dataclass(frozen=True)
class UpdateCheck:
    component: str
    status: str
    current_version: str
    release_version: str
    platform_os: str | None
    platform_arch: str | None
    asset_name: str | None
    receipt: bytes
    receipt_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return _strict_json(self.receipt, phase="check-receipt", component=self.component)


Fetcher = Callable[[str], FetchedResource]
ProcessRunner = Callable[[tuple[str, ...]], ProcessResult]


def canonical_json(value: Any) -> bytes:
    """Return the one canonical JSON representation used by all receipts."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def receipt_sha256(receipt: bytes) -> str:
    return hashlib.sha256(receipt).hexdigest()


def normalize_platform(system: str, architecture: str) -> tuple[str, str]:
    """Normalize caller-supplied platform labels without inspecting the host."""

    if not isinstance(system, str) or not isinstance(architecture, str):
        _refuse("unsupported-platform", "platform")
    normalized_os = _OS_ALIASES.get(system.strip().lower())
    normalized_arch = _ARCH_ALIASES.get(architecture.strip().lower())
    if normalized_os is None or normalized_arch is None:
        _refuse("unsupported-platform", "platform", detail=f"{system}/{architecture}")
    return normalized_os, normalized_arch


class ComponentUpdateCenter:
    """A manifest-bound component inventory and read-only update checker."""

    def __init__(self, manifest: Mapping[str, Any]) -> None:
        if not isinstance(manifest, Mapping):
            _refuse("manifest-format", "manifest")
        self._manifest = copy.deepcopy(dict(manifest))
        self._components = _validate_manifest(self._manifest)
        self._manifest_sha256 = hashlib.sha256(canonical_json(self._manifest)).hexdigest()

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "ComponentUpdateCenter":
        candidate = Path(path).absolute()
        if not os.path.lexists(candidate) or not candidate.is_file() or _is_linkish(candidate):
            _refuse("manifest-path", "manifest")
        manifest_path = candidate.resolve(strict=True)
        before = manifest_path.lstat()
        if before.st_nlink != 1 or before.st_size > _MAX_MANIFEST_BYTES:
            _refuse("manifest-path", "manifest")
        raw = manifest_path.read_bytes()
        after = manifest_path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _refuse("manifest-changed-during-read", "manifest")
        manifest = _strict_json(raw, phase="manifest")
        if not isinstance(manifest, dict):
            _refuse("manifest-format", "manifest")
        return cls(manifest)

    @classmethod
    def from_default_manifest(cls) -> "ComponentUpdateCenter":
        """Load the reviewed registry from installed ``xnet`` package data."""

        try:
            resource = resources.files("xnet").joinpath(*DEFAULT_MANIFEST_RESOURCE.split("/"))
            with resource.open("rb") as stream:
                raw = stream.read(_MAX_MANIFEST_BYTES + 1)
        except (FileNotFoundError, IsADirectoryError, OSError) as exc:
            raise ComponentUpdateRefusal("manifest-path", phase="manifest") from exc
        if len(raw) > _MAX_MANIFEST_BYTES:
            _refuse("manifest-path", "manifest")
        manifest = _strict_json(raw, phase="manifest")
        if not isinstance(manifest, dict):
            _refuse("manifest-format", "manifest")
        return cls(manifest)

    @property
    def manifest_sha256(self) -> str:
        return self._manifest_sha256

    @property
    def manifest(self) -> dict[str, Any]:
        return copy.deepcopy(self._manifest)

    def inventory(self) -> dict[str, Any]:
        """Return one deterministic, read-only view of every registered component."""

        rows = []
        for component_id in sorted(self._components):
            component = self._components[component_id]
            rows.append({
                "id": component_id,
                "name": component["name"],
                "official_origin": component["official_origin"],
                "channel": component["channel"],
                "pinned_version": component["pinned"]["version"],
                "pinned_tag": component["pinned"]["tag"],
                "pinned_commit": component["pinned"]["commit"],
                "update_supported": component["update_supported"],
                "update_reason": component["update_reason"],
                "update_mode": component["update_mode"],
                "supported_platforms": sorted(component["platform_assets"]),
            })
        return {
            "schema": "xnet.component-inventory.v1",
            "manifest_sha256": self._manifest_sha256,
            "components": rows,
        }

    def inventory_receipt(self) -> bytes:
        """Return the inventory in the canonical receipt encoding."""

        return canonical_json(self.inventory())

    def probe_current_version(self, component_id: str, process: ProcessRunner) -> str:
        """Run only the manifest's fixed ``--version`` probe through a supplied callback."""

        component = self._component(component_id)
        probe = component["version_probe"]
        if probe is None:
            _refuse("version-probe-unavailable", "probe", component=component_id)
        if not callable(process):
            _refuse("process-callback-required", "probe", component=component_id)
        argv = tuple(probe["argv"])
        try:
            result = process(argv)
        except Exception as exc:
            raise ComponentUpdateRefusal("process-probe-failed", phase="probe",
                                         component=component_id) from exc
        if not isinstance(result, ProcessResult) or isinstance(result.returncode, bool):
            _refuse("process-result-format", "probe", component=component_id)
        if result.returncode != 0:
            _refuse("process-probe-failed", "probe", component=component_id)
        output = _decode_process_text(result.stdout, component_id)
        match = re.fullmatch(probe["stdout_regex"], output)
        if match is None or "version" not in match.groupdict():
            _refuse("version-probe-format", "probe", component=component_id)
        version, _ = _parse_version(match.group("version"), phase="probe", component=component_id)
        return version

    def check(
        self,
        component_id: str,
        *,
        current_version: str,
        fetcher: Fetcher,
        system: str | None = None,
        architecture: str | None = None,
    ) -> UpdateCheck:
        """Fetch and validate release evidence without changing local state."""

        component = self._component(component_id)
        current, current_key = _parse_version(current_version, phase="check", component=component_id)
        platform_os: str | None = None
        platform_arch: str | None = None
        asset_name: str | None = None
        if component["update_mode"] == "check-only":
            if system is None or architecture is None:
                _refuse("unsupported-platform", "platform", component=component_id)
            platform_os, platform_arch = normalize_platform(system, architecture)
            platform_key = f"{platform_os}/{platform_arch}"
            asset_name = component["platform_assets"].get(platform_key)
            if asset_name is None:
                _refuse("unsupported-platform", "platform", component=component_id,
                        detail=platform_key)
        release_resource = _fetch_exact(fetcher, component["pinned"]["release_api_url"],
                                        maximum=2 * 1024 * 1024, phase="release-metadata",
                                        component=component_id)
        release, assets = self._parse_release(component, release_resource.body)
        release_version, release_key = _parse_version(release["version"], phase="release-metadata",
                                                       component=component_id)
        if release_key < current_key:
            _refuse("downgrade-refused", "check", component=component_id,
                    detail=f"{current}>{release_version}")
        status = "current" if release_key == current_key else "update_available"

        asset_record: dict[str, Any] | None = None
        checksum_record: dict[str, Any] | None = None

        if component["update_mode"] == "check-only":
            checksum_cfg = component["checksum_manifest"]
            checksum_asset = assets[checksum_cfg["name"]]
            checksum_resource = _fetch_exact(fetcher, checksum_asset["url"], maximum=64 * 1024,
                                             phase="checksum", component=component_id)
            checksum_actual = hashlib.sha256(checksum_resource.body).hexdigest()
            if not hmac.compare_digest(checksum_actual, checksum_cfg["sha256"]):
                _refuse("hash-mismatch", "checksum", component=component_id)
            checksums = _parse_checksums(checksum_resource.body, component["release_assets"], component_id)
            selected = component["release_assets"][asset_name]
            if asset_name not in checksums:
                _refuse("missing-checksum", "checksum", component=component_id, detail=asset_name)
            if not hmac.compare_digest(checksums[asset_name], selected["sha256"]):
                _refuse("hash-mismatch", "checksum", component=component_id, detail=asset_name)
            remote_asset = assets[asset_name]
            asset_record = {
                "name": asset_name,
                "url": remote_asset["url"],
                "size": selected["size"],
                "sha256": selected["sha256"],
            }
            checksum_record = {
                "name": checksum_cfg["name"],
                "url": checksum_asset["url"],
                "size": checksum_cfg["size"],
                "sha256": checksum_cfg["sha256"],
            }

        receipt_object = {
            "schema": CHECK_SCHEMA,
            "action": "check",
            "component": component_id,
            "channel": component["channel"],
            "update_mode": component["update_mode"],
            "manifest_sha256": self._manifest_sha256,
            "current_version": current,
            "status": status,
            "release": release,
            "platform": None if platform_os is None else {"os": platform_os, "arch": platform_arch},
            "artifact": asset_record,
            "checksum_manifest": checksum_record,
        }
        receipt = canonical_json(receipt_object)
        return UpdateCheck(component_id, status, current, release_version, platform_os,
                           platform_arch, asset_name, receipt, receipt_sha256(receipt))

    def stage(
        self,
        check: UpdateCheck,
        *,
        stage_root: str | os.PathLike[str],
        fetcher: Fetcher,
    ) -> NoReturn:
        """Refuse staging before using its path or invoking caller callbacks."""

        component = check.component if isinstance(check, UpdateCheck) else None
        _refuse("mutation-disabled", "stage", component=component)

    def apply(
        self,
        component_id: str,
        *,
        stage_root: str | os.PathLike[str],
        system: str,
        architecture: str,
    ) -> NoReturn:
        """Refuse selection before inspecting the filesystem or platform inputs."""

        component = component_id if isinstance(component_id, str) else None
        _refuse("mutation-disabled", "apply", component=component)

    def rollback(self, component_id: str, *, stage_root: str | os.PathLike[str]) -> NoReturn:
        """Refuse rollback before inspecting the filesystem."""

        component = component_id if isinstance(component_id, str) else None
        _refuse("mutation-disabled", "rollback", component=component)

    def _component(self, component_id: str) -> dict[str, Any]:
        if not isinstance(component_id, str) or component_id not in self._components:
            _refuse("unknown-component", "component", detail=str(component_id))
        return self._components[component_id]

    def _parse_release(self, component: Mapping[str, Any], raw: bytes) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        component_id = component["id"]
        metadata = _strict_json(raw, phase="release-metadata", component=component_id)
        if not isinstance(metadata, dict):
            _refuse("release-metadata-format", "release-metadata", component=component_id)
        for key in ("tag_name", "html_url", "draft", "prerelease", "assets"):
            if key not in metadata:
                _refuse("release-metadata-format", "release-metadata", component=component_id,
                        detail=f"missing {key}")
        if type(metadata["draft"]) is not bool or type(metadata["prerelease"]) is not bool:
            _refuse("release-metadata-format", "release-metadata", component=component_id)
        if metadata["draft"]:
            _refuse("draft-refused", "release-metadata", component=component_id)
        if metadata["prerelease"]:
            _refuse("prerelease-refused", "release-metadata", component=component_id)
        tag = metadata["tag_name"]
        html_url = metadata["html_url"]
        if not isinstance(tag, str) or not isinstance(html_url, str) or not isinstance(metadata["assets"], list):
            _refuse("release-metadata-format", "release-metadata", component=component_id)
        release_id = metadata.get("id")
        published_at = metadata.get("published_at")
        if (type(release_id) is not int or release_id <= 0
                or not isinstance(published_at, str)
                or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", published_at) is None
                or len(metadata["assets"]) > 256):
            _refuse("release-metadata-format", "release-metadata", component=component_id)
        version, _ = _parse_version(tag, phase="release-metadata", component=component_id)
        expected_url = f"{component['official_origin']}/releases/tag/{tag}"
        if html_url != expected_url:
            _refuse("wrong-origin", "release-metadata", component=component_id)

        pinned = component["pinned"]
        if component["release_policy"] == "pinned-stable":
            if tag != pinned["tag"] or version != pinned["version"] or html_url != pinned["release_url"]:
                _refuse("release-pin-mismatch", "release-metadata", component=component_id)
            if metadata.get("id") != pinned["release_id"]:
                _refuse("release-pin-mismatch", "release-metadata", component=component_id,
                        detail="release id")
            if metadata.get("published_at") != pinned["published_at"]:
                _refuse("release-pin-mismatch", "release-metadata", component=component_id,
                        detail="published_at")

        assets: dict[str, dict[str, Any]] = {}
        for row in metadata["assets"]:
            if not isinstance(row, dict):
                _refuse("release-metadata-format", "release-assets", component=component_id)
            for key in ("name", "browser_download_url", "size"):
                if key not in row:
                    _refuse("release-metadata-format", "release-assets", component=component_id)
            name = row["name"]
            if not isinstance(name, str) or not _SAFE_ASSET.fullmatch(name) or "/" in name or "\\" in name:
                _refuse("path-traversal", "release-assets", component=component_id)
            if name in assets:
                _refuse("duplicate-asset", "release-assets", component=component_id, detail=name)
            size = row["size"]
            url = row["browser_download_url"]
            if type(size) is not int or size <= 0 or not isinstance(url, str):
                _refuse("release-metadata-format", "release-assets", component=component_id)
            expected_download = f"{component['official_origin']}/releases/download/{tag}/{name}"
            if url != expected_download:
                _refuse("wrong-origin", "release-assets", component=component_id, detail=name)
            if row.get("state", "uploaded") != "uploaded":
                _refuse("asset-not-uploaded", "release-assets", component=component_id, detail=name)
            assets[name] = {"name": name, "url": url, "size": size, "digest": row.get("digest")}

        if component["update_mode"] == "check-only":
            checksum = component["checksum_manifest"]
            expected_names = set(component["release_assets"]) | {checksum["name"]}
            if checksum["name"] not in assets:
                _refuse("missing-checksum", "release-assets", component=component_id)
            if set(assets) != expected_names:
                _refuse("asset-allowlist-mismatch", "release-assets", component=component_id)
            expected_records = dict(component["release_assets"])
            expected_records[checksum["name"]] = checksum
            for name, expected in expected_records.items():
                actual = assets[name]
                if actual["size"] != expected["size"]:
                    _refuse("partial-write", "release-assets", component=component_id, detail=name)
                digest = actual["digest"]
                if digest is not None and digest != f"sha256:{expected['sha256']}":
                    _refuse("hash-mismatch", "release-assets", component=component_id, detail=name)

        release = {
            "version": version,
            "tag": tag,
            "commit": pinned["commit"] if component["release_policy"] == "pinned-stable" else None,
            "tag_object": pinned["tag_object"] if component["release_policy"] == "pinned-stable" else None,
            "url": html_url,
            "api_url": pinned["release_api_url"],
            "release_id": release_id,
            "published_at": published_at,
        }
        return release, assets


def _validate_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if set(manifest) != {"schema", "components"} or manifest.get("schema") != MANIFEST_SCHEMA:
        _refuse("manifest-format", "manifest")
    rows = manifest.get("components")
    if not isinstance(rows, list) or not rows:
        _refuse("manifest-format", "manifest")
    components: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != _COMPONENT_KEYS:
            _refuse("manifest-format", "manifest")
        component_id = row.get("id")
        if not isinstance(component_id, str) or not _SAFE_ID.fullmatch(component_id) or component_id in components:
            _refuse("manifest-format", "manifest", detail="component id")
        if not isinstance(row["name"], str) or not row["name"]:
            _refuse("manifest-format", "manifest", component=component_id)
        if row["channel"] != "stable" or row["update_mode"] not in {"report-only", "check-only"}:
            _refuse("manifest-format", "manifest", component=component_id)
        if row["update_supported"] is not False:
            _refuse("manifest-format", "manifest", component=component_id)
        if not isinstance(row["update_reason"], str) or not row["update_reason"]:
            _refuse("manifest-format", "manifest", component=component_id)
        expected_policy = "latest-stable" if row["update_mode"] == "report-only" else "pinned-stable"
        if row["release_policy"] != expected_policy:
            _refuse("manifest-format", "manifest", component=component_id)
        origin = row["official_origin"]
        if not _valid_github_origin(origin):
            _refuse("wrong-origin", "manifest", component=component_id)
        pinned = row["pinned"]
        if not isinstance(pinned, dict) or set(pinned) != _PINNED_KEYS:
            _refuse("manifest-format", "manifest", component=component_id)
        version, _ = _parse_version(pinned.get("version"), phase="manifest", component=component_id)
        if version != pinned["version"]:
            _refuse("manifest-format", "manifest", component=component_id)
        owner_repo = origin.removeprefix("https://github.com/")
        if row["release_policy"] == "pinned-stable":
            if (not isinstance(pinned["commit"], str) or not _HEX40.fullmatch(pinned["commit"])
                    or pinned["tag"] != f"v{version}" or not isinstance(pinned["tag_object"], str)
                    or not _HEX40.fullmatch(pinned["tag_object"])
                    or type(pinned["release_id"]) is not int or pinned["release_id"] <= 0
                    or not isinstance(pinned["published_at"], str)
                    or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                                    pinned["published_at"]) is None
                    or pinned["release_url"] != f"{origin}/releases/tag/{pinned['tag']}"
                    or pinned["release_api_url"] != f"https://api.github.com/repos/{owner_repo}/releases/tags/{pinned['tag']}"):
                _refuse("manifest-format", "manifest", component=component_id)
        else:
            if (pinned["commit"] is not None or pinned["tag"] is not None or pinned["tag_object"] is not None
                    or pinned["release_id"] is not None or pinned["published_at"] is not None
                    or pinned["release_url"] is not None
                    or pinned["release_api_url"] != f"https://api.github.com/repos/{owner_repo}/releases/latest"):
                _refuse("manifest-format", "manifest", component=component_id)
        license_row = row["license"]
        if not isinstance(license_row, dict) or set(license_row) != _LICENSE_KEYS:
            _refuse("manifest-format", "manifest", component=component_id)
        if license_row["spdx"] != "MIT" or not _HEX64.fullmatch(str(license_row["notice_sha256"])):
            _refuse("manifest-format", "manifest", component=component_id)
        _validate_relative_path(license_row["notice_path"], phase="manifest", component=component_id)
        assets = row["release_assets"]
        platforms = row["platform_assets"]
        if not isinstance(assets, dict) or not isinstance(platforms, dict):
            _refuse("manifest-format", "manifest", component=component_id)
        for name, asset in assets.items():
            _validate_asset_name(name, component_id)
            if (not isinstance(asset, dict) or set(asset) != _ASSET_KEYS
                    or type(asset["size"]) is not int or asset["size"] <= 0
                    or not isinstance(asset["sha256"], str) or not _HEX64.fullmatch(asset["sha256"])):
                _refuse("manifest-format", "manifest", component=component_id)
        for platform_key, name in platforms.items():
            if (not isinstance(platform_key, str) or not re.fullmatch(r"[a-z0-9_]+/[a-z0-9_]+", platform_key)
                    or name not in assets):
                _refuse("manifest-format", "manifest", component=component_id)
            platform_os, platform_arch = platform_key.split("/", 1)
            if platform_os not in set(_OS_ALIASES.values()) or platform_arch not in set(_ARCH_ALIASES.values()):
                _refuse("manifest-format", "manifest", component=component_id)
        checksum = row["checksum_manifest"]
        if row["update_mode"] == "check-only":
            if not assets or not platforms or not isinstance(checksum, dict) or set(checksum) != _CHECKSUM_KEYS:
                _refuse("manifest-format", "manifest", component=component_id)
            _validate_asset_name(checksum["name"], component_id)
            if (checksum["name"] in assets or type(checksum["size"]) is not int or checksum["size"] <= 0
                    or not isinstance(checksum["sha256"], str) or not _HEX64.fullmatch(checksum["sha256"])):
                _refuse("manifest-format", "manifest", component=component_id)
        elif checksum is not None or assets or platforms:
            _refuse("manifest-format", "manifest", component=component_id)
        probe = row["version_probe"]
        if probe is not None:
            if not isinstance(probe, dict) or set(probe) != _PROBE_KEYS:
                _refuse("manifest-format", "manifest", component=component_id)
            argv = probe["argv"]
            if (not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or not arg for arg in argv)
                    or any("\x00" in arg for arg in argv) or not isinstance(probe["stdout_regex"], str)):
                _refuse("manifest-format", "manifest", component=component_id)
            try:
                compiled = re.compile(probe["stdout_regex"])
            except re.error as exc:
                raise ComponentUpdateRefusal("manifest-format", phase="manifest", component=component_id) from exc
            if "version" not in compiled.groupindex:
                _refuse("manifest-format", "manifest", component=component_id)
        components[component_id] = row
    return components


def _parse_checksums(raw: bytes, expected_assets: Mapping[str, Any], component: str) -> dict[str, str]:
    if b"\r" in raw or not raw.endswith(b"\n") or raw.startswith(b"\xef\xbb\xbf"):
        _refuse("checksum-format", "checksum", component=component)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ComponentUpdateRefusal("checksum-format", phase="checksum", component=component) from exc
    values: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            _refuse("checksum-format", "checksum", component=component)
        digest, name = match.groups()
        _validate_asset_name(name, component)
        if name in values:
            _refuse("duplicate-checksum", "checksum", component=component, detail=name)
        values[name] = digest
    missing = set(expected_assets) - set(values)
    if missing:
        _refuse("missing-checksum", "checksum", component=component,
                detail=sorted(missing)[0])
    if set(values) != set(expected_assets):
        _refuse("checksum-allowlist-mismatch", "checksum", component=component)
    for name, expected in expected_assets.items():
        if not hmac.compare_digest(values[name], expected["sha256"]):
            _refuse("hash-mismatch", "checksum", component=component, detail=name)
    return values


def _fetch_exact(fetcher: Fetcher, url: str, *, maximum: int, phase: str,
                 component: str) -> FetchedResource:
    if not callable(fetcher):
        _refuse("fetcher-required", phase, component=component)
    try:
        resource = fetcher(url)
    except ComponentUpdateRefusal:
        raise
    except Exception as exc:
        raise ComponentUpdateRefusal("fetch-failed", phase=phase, component=component) from exc
    if (not isinstance(resource, FetchedResource) or resource.url != url
            or type(resource.status) is not int or resource.status != 200
            or not isinstance(resource.body, bytes)):
        _refuse("fetch-result-format", phase, component=component)
    if len(resource.body) > maximum:
        _refuse("response-too-large", phase, component=component)
    return resource


def _strict_json(raw: bytes, *, phase: str, component: str | None = None) -> Any:
    if not isinstance(raw, bytes) or raw.startswith(b"\xef\xbb\xbf"):
        _refuse("json-format", phase, component=component)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ComponentUpdateRefusal("json-format", phase=phase, component=component) from exc

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _refuse("duplicate-json-key", phase, component=component, detail=key)
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        _refuse("json-format", phase, component=component, detail=value)

    try:
        return json.loads(text, object_pairs_hook=pairs_hook, parse_constant=reject_constant)
    except ComponentUpdateRefusal:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
        raise ComponentUpdateRefusal("json-format", phase=phase, component=component) from exc


def _parse_version(value: Any, *, phase: str, component: str | None = None) -> tuple[str, tuple[int, int, int]]:
    if not isinstance(value, str):
        _refuse("version-format", phase, component=component)
    match = _SEMVER.fullmatch(value)
    if match is None:
        _refuse("version-format", phase, component=component)
    parts = tuple(int(piece) for piece in match.groups())
    return ".".join(str(piece) for piece in parts), parts  # type: ignore[return-value]


def _valid_github_origin(value: Any) -> bool:
    if not isinstance(value, str) or value.endswith("/"):
        return False
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and parsed.netloc == "github.com" and not parsed.query
            and not parsed.fragment and parsed.username is None and parsed.password is None
            and re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", parsed.path) is not None)


def _validate_asset_name(name: Any, component: str) -> None:
    if (not isinstance(name, str) or not _SAFE_ASSET.fullmatch(name)
            or name in {".", ".."} or "/" in name or "\\" in name):
        _refuse("path-traversal", "asset-name", component=component)


def _validate_relative_path(value: Any, *, phase: str, component: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        _refuse("path-traversal", phase, component=component)
    raw_parts = value.split("/")
    if any(not part or part in {".", ".."} or not _SAFE_ASSET.fullmatch(part) for part in raw_parts):
        _refuse("path-traversal", phase, component=component)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _refuse("path-traversal", phase, component=component)
    return path


def _is_linkish(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    if hasattr(path, "is_junction"):
        try:
            if path.is_junction():
                return True
        except OSError:
            return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse and attributes & reparse)


def _decode_process_text(value: str | bytes, component: str) -> str:
    if isinstance(value, bytes):
        if len(value) > 4096:
            _refuse("version-probe-format", "probe", component=component)
        try:
            return value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ComponentUpdateRefusal("version-probe-format", phase="probe", component=component) from exc
    if isinstance(value, str) and len(value.encode("utf-8")) <= 4096:
        return value
    _refuse("version-probe-format", "probe", component=component)


def _refuse(reason: str, phase: str, *, component: str | None = None,
            detail: str | None = None) -> None:
    raise ComponentUpdateRefusal(reason, phase=phase, component=component, detail=detail)


__all__ = [
    "CHECK_SCHEMA",
    "ComponentUpdateCenter",
    "ComponentUpdateRefusal",
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_MANIFEST_RESOURCE",
    "FetchedResource",
    "MANIFEST_SCHEMA",
    "ProcessResult",
    "UpdateCheck",
    "canonical_json",
    "normalize_platform",
    "receipt_sha256",
]
