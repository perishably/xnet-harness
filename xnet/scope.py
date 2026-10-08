"""Signed, explicit engagement scope and hard action admission."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .protocol import canonical, sha256


class ScopeError(PermissionError):
    pass


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


class ScopeAuthority:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.key_file = self.data_dir / "keys" / "scope.hmac"
        self.scope_dir = self.data_dir / "scopes"

    def init(self) -> None:
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        self.scope_dir.mkdir(parents=True, exist_ok=True)
        if not self.key_file.exists():
            fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(secrets.token_bytes(32))
                out.flush()
                os.fsync(out.fileno())

    def _key(self) -> bytes:
        if not self.key_file.is_file():
            raise ScopeError("scope authority is not initialized")
        return self.key_file.read_bytes()

    def create(self, *, program: str, policy_url: str, policy_capture: bytes, allowed_assets: list[str], methods: list[str], excluded_assets: list[str] | None = None, expires_at: int | None = None, allow_live_network: bool = False, requests_per_minute: int = 30, max_parallel: int = 2, fixture: bool = False) -> dict:
        self.init()
        if not program or not allowed_assets or not methods:
            raise ScopeError("program, allowed assets, and methods are required")
        if not fixture and (not policy_url.startswith("https://") or not policy_capture):
            raise ScopeError("a captured HTTPS program policy is required")
        if any(a in ("*", "0.0.0.0/0", "::/0") for a in allowed_assets):
            raise ScopeError("unbounded assets are forbidden")
        if not 1 <= requests_per_minute <= 600 or not 1 <= max_parallel <= 16:
            raise ScopeError("rate and parallelism limits out of range")
        now = int(time.time())
        manifest = {
            "v": 1, "scope_id": str(uuid.uuid4()), "policy_version": "xnet-v1", "program": program,
            "policy_url": policy_url, "policy_capture_sha256": sha256(policy_capture), "captured_at": now,
            "expires_at": expires_at or now + 7 * 86400, "allowed_assets": allowed_assets,
            "excluded_assets": excluded_assets or [], "methods": methods,
            "allow_live_network": bool(allow_live_network), "requests_per_minute": requests_per_minute,
            "max_parallel": max_parallel, "fixture": bool(fixture), "created_at": now,
        }
        if manifest["expires_at"] <= now:
            raise ScopeError("scope expiration must be in the future")
        manifest["signature_hmac_sha256"] = hmac.new(self._key(), canonical(manifest), hashlib.sha256).hexdigest()
        target = self.scope_dir / f"{manifest['scope_id']}.json"
        with target.open("x", encoding="utf-8") as out:
            json.dump(manifest, out, indent=2, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        return manifest

    def load(self, scope_id: str) -> dict:
        if not scope_id or any(c not in "0123456789abcdef-" for c in scope_id.lower()) or len(scope_id) > 64:
            raise ScopeError("invalid scope ID")
        path = self.scope_dir / f"{scope_id}.json"
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ScopeError(f"scope unavailable: {scope_id}") from exc
        sig = manifest.pop("signature_hmac_sha256", "")
        expected = hmac.new(self._key(), canonical(manifest), hashlib.sha256).hexdigest()
        manifest["signature_hmac_sha256"] = sig
        if not hmac.compare_digest(sig, expected) or manifest.get("scope_id") != scope_id:
            raise ScopeError("scope signature mismatch")
        if manifest.get("expires_at", 0) <= int(time.time()):
            raise ScopeError("scope expired")
        return manifest

    def gate(self, scope_id: str, target: str, method: str, *, network: bool = False) -> dict:
        manifest = self.load(scope_id)
        if method not in manifest["methods"]:
            raise ScopeError(f"method {method} not permitted")
        if network and not manifest["allow_live_network"]:
            raise ScopeError("live network interaction is disabled in this scope")
        if not target:
            raise ScopeError("target is required")
        if target.startswith("path:"):
            path = Path(target[5:]).resolve(strict=False)
            def match(pattern: str) -> bool:
                return pattern.startswith("path:") and _under(path, Path(pattern[5:]))
        else:
            parts = urlsplit(target)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
                raise ScopeError("network target must be an HTTP(S) URL without userinfo")
            host = parts.hostname.lower().rstrip(".")
            authority = f"{host}:{parts.port}" if parts.port else host
            def match(pattern: str) -> bool:
                pattern = pattern.lower().rstrip(".")
                if pattern.startswith("*."):
                    suffix = pattern[1:]
                    return host.endswith(suffix) and host != suffix[1:]
                return pattern in (host, authority)
        if any(match(p) for p in manifest["excluded_assets"]):
            raise ScopeError("target is excluded")
        if not any(match(p) for p in manifest["allowed_assets"]):
            raise ScopeError("target is outside signed scope")
        return manifest
