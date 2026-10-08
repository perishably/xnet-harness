"""Verify the bounded XNET~ wheel payload before publication."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import zipfile


REQUIRED_PAYLOAD = {
    "adapters/dojo/assets/app.js",
    "adapters/dojo/assets/index.html",
    "adapters/dojo/assets/style.css",
    "xnet/component_updates.py",
    "xnet/data/components.json",
}
REQUIRED_LICENSES = {
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "third_party/hermes-agent-LICENSE.txt",
    "third_party/jcode-LICENSE.txt",
    "third_party/nullclaw-LICENSE.txt",
    "third_party/openclaw-LICENSE.txt",
}


def _select_wheel(value: Path) -> Path:
    if value.is_file():
        choices = [value]
    elif value.is_dir():
        choices = sorted(value.glob("xnet_harness-*.whl"))
    else:
        raise ValueError(f"wheel path does not exist: {value}")
    if len(choices) != 1 or not choices[0].is_file():
        raise ValueError("expected exactly one xnet_harness wheel")
    return choices[0]


def verify(path: str | Path) -> dict[str, object]:
    wheel = _select_wheel(Path(path).resolve())
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]

    if len(names) != len(set(names)):
        raise ValueError("wheel contains duplicate member names")
    folded = [name.casefold() for name in names]
    if len(folded) != len(set(folded)):
        raise ValueError("wheel contains case-colliding member names")
    for name in names:
        pure = PurePosixPath(name)
        if not name or "\\" in name or pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"unsafe wheel member: {name!r}")

    members = set(names)
    missing_payload = sorted(REQUIRED_PAYLOAD - members)
    if missing_payload:
        raise ValueError(f"wheel is missing required payload: {missing_payload}")

    dist_info = sorted({name.split("/", 1)[0] for name in names if ".dist-info/" in name})
    if len(dist_info) != 1:
        raise ValueError("wheel must contain exactly one dist-info directory")
    license_prefix = f"{dist_info[0]}/licenses/"
    license_members = {
        name[len(license_prefix):]
        for name in names
        if name.startswith(license_prefix) and not name.endswith("/")
    }
    missing_licenses = sorted(REQUIRED_LICENSES - license_members)
    if missing_licenses:
        raise ValueError(f"wheel is missing required licenses: {missing_licenses}")

    return {
        "wheel": wheel.name,
        "bytes": wheel.stat().st_size,
        "members": len(names),
        "required_payload": len(REQUIRED_PAYLOAD),
        "required_licenses": len(REQUIRED_LICENSES),
        "verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path, help="wheel file or directory containing one XNET~ wheel")
    args = parser.parse_args()
    result = verify(args.wheel)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
