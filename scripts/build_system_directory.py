"""Build portable source discovery metadata, without importing components.

Only explicitly selected public source trees are read. Runtime activation,
permissions and verified behavior cannot be inferred from source presence.
Rebuild after changing public source; source verification rejects stale entries.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "xnet/system_catalog.py"
_SPEC = importlib.util.spec_from_file_location("xnet_public_directory_builder", MODULE)
catalog = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(catalog)

EXTENSIONS = {".py": "python", ".rs": "rust", ".toml": "toml", ".ps1": "powershell", ".go": "go", ".zig": "zig", ".jl": "julia"}
TREES = (
    ("xnet", ("*.py",)),
    ("xnet_sdk", ("*.py",)),
    ("adapters", ("**/*.py", "**/src/*.rs", "**/Cargo.toml", "*.ps1", "**/*.ps1")),
    ("rust", ("**/src/*.rs", "**/Cargo.toml")),
    ("scripts", ("*.py", "*.ps1")),
    ("examples", ("**/*.go", "**/*.zig", "**/*.jl")),
    ("lab/accuracy_preview", ("*.py", "dependencies/*.py", "dependencies/xnet/*.py")),
)

# Callback entry points can dispatch more than their filenames reveal. These
# conservative declarations remain discovery metadata, never permission grants.
LAB_EFFECTS = {
    "lab/accuracy_preview/controller.py": {"network", "model-call", "process-control", "container"},
    "lab/accuracy_preview/feedback_preview.py": {"network", "model-call", "process-control", "container"},
    "lab/accuracy_preview/preview_cli.py": {"network", "model-call", "process-control", "container"},
    "lab/accuracy_preview/__main__.py": {"network", "model-call", "process-control", "container"},
    "lab/accuracy_preview/dependencies/repo_agent.py": {"network", "model-call", "process-control"},
    "lab/accuracy_preview/dependencies/public_review.py": {"network", "process-control", "container"},
    "lab/accuracy_preview/dependencies/common_r02.py": {"network", "process-control", "container"},
}


def selected_sources(root=ROOT):
    root = Path(root).resolve(strict=True)
    selected = set()
    for directory, patterns in TREES:
        base = root / directory
        if not base.is_dir():
            continue
        if base.is_symlink() or (hasattr(base, "is_junction") and base.is_junction()):
            raise ValueError("linked inventory root refused")
        for pattern in patterns:
            for path in base.glob(pattern):
                if any(part in {"target", "build", "node_modules", "__pycache__", "tests"} for part in path.relative_to(root).parts):
                    continue
                if directory == "lab/accuracy_preview" and (path.name.startswith("test_") or path.name == "run_offline_checks.py"):
                    continue
                # Never follow an undeclared nested source-tree link.
                for part in (path, *path.parents):
                    if part == root:
                        break
                    if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                        raise ValueError("linked inventory path refused")
                if path.is_file() and path.suffix in EXTENSIONS:
                    path.resolve(strict=True).relative_to(root)
                    selected.add(path)
    if not 1 <= len(selected) <= 1024:
        raise ValueError("public directory source count outside bounds")
    return sorted(selected)


def declared_contract(path, raw):
    if path.suffix == ".py":
        tree = ast.parse(raw.decode("utf-8-sig"), filename=path.name)
        symbols = ["function " + node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_")]
        symbols += ["class " + node.name for node in tree.body if isinstance(node, ast.ClassDef) and not node.name.startswith("_")]
    else:
        text = raw.decode("utf-8-sig")
        expression = {
            ".rs": r"pub\s+(?:async\s+)?(?:fn|struct|enum|trait|mod)\s+([A-Za-z0-9_]+)",
            ".go": r"func\s+(?:\([^\n)]*\)\s*)?([A-Za-z0-9_]+)\s*\(",
            ".zig": r"(?:pub\s+)?fn\s+([A-Za-z0-9_]+)",
            ".jl": r"function\s+([A-Za-z0-9_!]+)",
            ".ps1": r"(?i)function\s+([A-Za-z0-9_-]+)",
        }.get(path.suffix)
        symbols = ["declared symbol " + name for name in re.findall(expression, text)] if expression else []
    return sorted(set(symbols))[:32] or ["source declarations; caller review required"]


def source_entry(path, root=ROOT):
    root = Path(root).resolve(strict=True)
    relative = path.relative_to(root).as_posix()
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("public source bound exceeded")
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("public source grew beyond bound")
    language = EXTENSIONS[path.suffix]
    features = set(re.findall(r"[a-z][a-z0-9_]{1,63}", path.stem.lower()))
    for word in ("rag", "halo", "hce", "oroboros", "learning", "epoch", "replay", "claw", "nullclaw", "scope", "gate", "browser", "phone", "mobile", "jcode", "precog", "trinity", "ledger", "storage", "metadata", "stream", "router", "loopback"):
        if word in relative.lower():
            features.add(word)
    features.add(language)
    status = "implemented"
    notes = "Public source declarations; no runtime activation, capability or caller permission is inferred."
    if any(word in path.stem.lower() for word in ("neckband", "lfm_relay", "lfm_context", "cloud_arc", "arc_benchmark", "cruxeval")):
        status = "inactive"
        notes = "Preserved source outside the current public development arm; discovery never starts it."
    if language == "toml":
        effects = ["none"]
        notes += " Package manifest only; native runtime verification is separate."
    else:
        effects = {"local-read", "local-write"}
        name = path.stem.lower()
        if any(word in name for word in ("cloud", "server", "transport", "provider", "mobile", "phone", "peer", "fetch", "feed", "sync", "gateway")):
            effects.add("network")
        if any(word in name for word in ("provider", "repair_loop", "learning_epoch", "learning_cycle")):
            effects.add("model-call")
        if language == "powershell" or any(word in name for word in ("control", "supervisor", "launcher")):
            effects.add("process-control")
        if language == "rust":
            notes += " Native effects are conservative declarations, not binary activation certification."
        if relative in LAB_EFFECTS:
            effects.update(LAB_EFFECTS[relative])
            notes += " Includes possible caller transport and test-worker callback effects; defaults dispatch no work."
        effects = sorted(effects)
    return {"module_id": relative.removesuffix(path.suffix), "path": relative, "source_sha256": catalog.sha256(raw), "language": language, "status": status, "features": sorted(features)[:32], "call_contract": declared_contract(path, raw), "scopes": ["caller-declared-task-scope", "existing-component-policy"], "side_effects": effects, "evidence": [], "notes": notes, "authority": "discovery-only"}


def build_directory(root=ROOT, *, created_utc):
    return catalog.make_directory([source_entry(path, root) for path in selected_sources(root)], created_utc=created_utc)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--created-utc", default=None, help="explicit timestamp permits byte-identical regeneration")
    args = parser.parse_args(argv)
    directory = build_directory(created_utc=args.created_utc or datetime.now(timezone.utc).isoformat())
    output = ROOT / "xnet/data/system-directory.json"
    output.parent.mkdir(exist_ok=True)
    output.write_bytes(catalog.canonical(directory))
    print(catalog.canonical({"schema": "xnet.public-system-directory-build.v1", "path": output.relative_to(ROOT).as_posix(), "directory_sha256": directory["directory_sha256"], "modules": len(directory["entries"]), "status_counts": catalog.status_counts(directory), "language_counts": dict(sorted(Counter(row["language"] for row in directory["entries"]).items())), "catalog_source_sha256": catalog.sha256(MODULE.read_bytes()), "builder_source_sha256": catalog.sha256(Path(__file__).read_bytes()), "runtime_activation": False, "permission_granted": False}).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
