"""Build and verify the exact XNET~ public source inventory.

The inventory is based on Git's tracked and non-ignored candidate set.  Build
artifacts and private runtime roots must be ignored before this tool is run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


MANIFEST_HEADER = "# Exact reviewed source distribution; no recursive include rules.\n"
SOURCE_MANIFEST = "source-manifest.json"


def _candidate_paths(root: Path) -> list[str]:
    completed = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = sorted(
        item.decode("utf-8")
        for item in completed.stdout.split(b"\0")
        if item
    )
    for relative in paths:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"public inventory requires a regular file: {relative}")
        if "\\" in relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError(f"unsafe public inventory path: {relative}")
    return paths


def _manifest_text(paths: list[str]) -> str:
    return MANIFEST_HEADER + "".join(f"include {path}\n" for path in paths)


def _source_manifest(root: Path, paths: list[str]) -> bytes:
    rows = []
    for relative in paths:
        if relative == SOURCE_MANIFEST:
            continue
        raw = (root / relative).read_bytes()
        rows.append(
            {
                "bytes": len(raw),
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    body = {
        "files": rows,
        "license": "MIT",
        "release": "0.1.0",
        "schema": "xnet.public-source-manifest.v1",
    }
    return (
        json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def build(root: Path) -> tuple[bytes, bytes]:
    paths = _candidate_paths(root)
    manifest = _manifest_text(paths).encode("utf-8")
    # MANIFEST.in is itself part of the candidate set; hash the bytes that will
    # actually ship, then build the source manifest from the resulting tree.
    (root / "MANIFEST.in").write_bytes(manifest)
    source = _source_manifest(root, paths)
    return manifest, source


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()

    old_manifest = (root / "MANIFEST.in").read_bytes()
    old_source = (root / SOURCE_MANIFEST).read_bytes()
    manifest, source = build(root)
    if args.check:
        # Restore the original bytes so a failed check is read-only.
        (root / "MANIFEST.in").write_bytes(old_manifest)
        (root / SOURCE_MANIFEST).write_bytes(old_source)
        if manifest != old_manifest or source != old_source:
            print("release inventory is stale")
            return 1
        print("release inventory verified")
        return 0

    (root / SOURCE_MANIFEST).write_bytes(source)
    print(f"wrote MANIFEST.in and {SOURCE_MANIFEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
