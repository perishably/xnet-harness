"""Pinned fixed-action CLI for both Oroboros shell membranes."""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import re
import stat
import sys
from pathlib import Path

def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _regular_local(path: Path) -> None:
    if not path.is_absolute() or str(path).startswith(("\\\\", "//")):
        raise ValueError("local absolute file required")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked file path refused")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("regular unlinked file required")


def _preflight(path: Path) -> None:
    """Check signed source pins with stdlib before importing repository code."""
    _regular_local(path)
    with path.open("rb") as stream:
        raw = stream.read(65_537)
    if len(raw) > 65_536:
        raise ValueError("config frame exceeds 64 KiB")
    config = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    if Path(config["control_root"]) / "config.json" != path:
        raise ValueError("config must remain at its private control root")
    unsigned = {key: item for key, item in config.items() if key != "signature_hmac_sha256"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    key_path = path.parent / "keys" / "scope.hmac"
    _regular_local(key_path)
    with key_path.open("rb") as stream:
        key = stream.read(33)
    if len(key) != 32:
        raise ValueError("invalid scope key length")
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, config["signature_hmac_sha256"]):
        raise ValueError("sphere config signature mismatch")
    repo = Path(__file__).resolve().parent.parent
    for name, pin in config["source_pins"].items():
        if not re.fullmatch(r"(?:xnet|scripts|adapters/openclaw|adapters)/[A-Za-z0-9_.-]+", name):
            raise ValueError("invalid repository source path")
        source = repo / name
        if pin == "absent":
            if name != "adapters/__init__.py" or source.exists():
                raise ValueError("namespace package identity changed")
        else:
            _regular_local(source)
            if hashlib.sha256(source.read_bytes()).hexdigest() != pin:
                raise ValueError("repository dependency pin mismatch: " + name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--lane", required=True, choices=("powershell", "git-bash"))
    parser.add_argument("--action", required=True, choices=("plan", "cycle", "verify"))
    parser.add_argument("--packet", type=Path)
    args = parser.parse_args()
    if (args.action == "cycle") != (args.packet is not None):
        parser.error("only cycle requires --packet")
    try:
        _preflight(args.config)
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from xnet.oroboros_sphere import SphereController, load_json_file
        sphere = SphereController(args.config)
        if args.action == "cycle":
            result = sphere.cycle(load_json_file(args.packet), args.lane)
        elif args.action == "verify":
            result = sphere.verify(args.lane)
        else:
            result = sphere.plan()
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 0 if result.get("ok", True) else 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
