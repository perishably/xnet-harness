"""Source-bound XNET component discovery. Metadata never grants permission.

JSON protocol also implemented by the optional xnet-system-index Rust crate.
This module never imports a discovered component, executes a command, performs
network work, selects a model process or promotes a lesson.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

DIRECTORY_SCHEMA = "xnet.system-directory.v1"
REQUEST_SCHEMA = "xnet.system-index-request.v1"
RESPONSE_SCHEMA = "xnet.system-index-response.v1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@/-]{1,192}\Z")
STATUSES = frozenset({"implemented", "wired", "verified", "inactive", "pending", "evidence"})
EFFECTS = frozenset({"none", "local-read", "local-write", "network", "model-call", "process-control", "container", "user-interface"})
LANGUAGES = frozenset({"python", "rust", "go", "zig", "julia", "powershell", "json", "markdown", "toml"})
ENTRY_FIELDS = frozenset({"module_id", "path", "source_sha256", "language", "status", "features", "call_contract", "scopes", "side_effects", "evidence", "notes", "authority"})
EVIDENCE_FIELDS = frozenset({"path", "sha256", "source_sha256", "claim"})


class CatalogError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha256(canonical(value))


def strict_json(raw):
    if type(raw) not in {bytes, str} or len(raw) > 4 * 1024 * 1024:
        raise CatalogError("JSON input bound exceeded")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise CatalogError("duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(CatalogError("nonfinite JSON")))
    except (ValueError, UnicodeError) as exc:
        raise CatalogError("invalid JSON") from exc


def _identifier(value):
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise CatalogError("bounded identifier required")
    return value


def _hash(value):
    if type(value) is not str or not HASH.fullmatch(value):
        raise CatalogError("full lowercase SHA256 required")
    return value


def _path(value):
    if type(value) is not str or not 1 <= len(value) <= 384 or ":" in value or "\\" in value:
        raise CatalogError("workspace-relative POSIX path required")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise CatalogError("escaping or ambiguous path")
    if any(part.lower() in {".ssh", ".env", "credentials", "private_selftest", "evaluator-only", "protected-dataset"} for part in path.parts) or path.suffix.lower() in {".key", ".pem", ".pfx", ".parquet", ".gguf", ".qcow2"}:
        raise CatalogError("private runtime or protected dataset path refused")
    return value


def _strings(values, maximum, *, identifiers=True):
    if type(values) is not list or len(values) > maximum or any(type(value) is not str for value in values) or values != sorted(set(values)):
        raise CatalogError("bounded sorted unique string list required")
    for value in values:
        if identifiers:
            _identifier(value)
        elif not 1 <= len(value.encode("utf-8")) <= 512 or any(ord(char) < 32 for char in value):
            raise CatalogError("bounded display contract required")


def validate_entry(entry):
    if type(entry) is not dict or set(entry) != ENTRY_FIELDS:
        raise CatalogError("closed component schema required")
    _identifier(entry["module_id"])
    _path(entry["path"])
    if entry["status"] not in STATUSES or entry["language"] not in LANGUAGES or entry["authority"] != "discovery-only":
        raise CatalogError("unknown status/language or permission claim")
    if entry["source_sha256"] is None:
        if entry["status"] != "pending":
            raise CatalogError("only pending entries may lack source bytes")
    else:
        _hash(entry["source_sha256"])
    _strings(entry["features"], 32)
    _strings(entry["scopes"], 16)
    _strings(entry["call_contract"], 32, identifiers=False)
    _strings(entry["side_effects"], 8)
    if not entry["side_effects"] or any(value not in EFFECTS for value in entry["side_effects"]) or ("none" in entry["side_effects"] and len(entry["side_effects"]) != 1):
        raise CatalogError("unknown or contradictory side-effect declaration")
    if type(entry["notes"]) is not str or len(entry["notes"].encode("utf-8")) > 1024 or any(ord(char) < 32 for char in entry["notes"]):
        raise CatalogError("bounded one-line notes required")
    if type(entry["evidence"]) is not list or len(entry["evidence"]) > 8:
        raise CatalogError("bounded evidence pointers required")
    for evidence in entry["evidence"]:
        if type(evidence) is not dict or set(evidence) != EVIDENCE_FIELDS:
            raise CatalogError("closed evidence pointer schema required")
        _path(evidence["path"])
        _hash(evidence["sha256"])
        _hash(evidence["source_sha256"])
        if evidence["source_sha256"] != entry["source_sha256"] or evidence["claim"] not in {"offline-check", "live-development", "source-integrity", "integration-binding", "historical-evidence"}:
            raise CatalogError("evidence source binding or claim differs")
    if entry["status"] == "verified" and not any(row["claim"] in {"offline-check", "live-development", "source-integrity"} for row in entry["evidence"]):
        raise CatalogError("verified status requires exact-source check evidence")
    if entry["status"] == "wired" and not any(row["claim"] == "integration-binding" for row in entry["evidence"]):
        raise CatalogError("wired status requires exact-source binding evidence")
    if entry["status"] in {"inactive", "pending"} and not entry["notes"]:
        raise CatalogError("inactive/pending entries require a limitation")
    return strict_json(canonical(entry))


def make_directory(entries, *, created_utc):
    body = {"schema": DIRECTORY_SCHEMA, "created_utc": created_utc, "entries": sorted(entries, key=lambda row: row["module_id"])}
    return validate_directory({**body, "directory_sha256": digest(body)})


def validate_directory(directory):
    if type(directory) is not dict or set(directory) != {"schema", "created_utc", "entries", "directory_sha256"} or directory["schema"] != DIRECTORY_SCHEMA:
        raise CatalogError("closed system directory schema required")
    if type(directory["created_utc"]) is not str or not 1 <= len(directory["created_utc"]) <= 64:
        raise CatalogError("creation timestamp required")
    if type(directory["entries"]) is not list or not 1 <= len(directory["entries"]) <= 4096:
        raise CatalogError("directory entry bound exceeded")
    entries = [validate_entry(entry) for entry in directory["entries"]]
    ids = [row["module_id"] for row in entries]
    if ids != sorted(set(ids)):
        raise CatalogError("component IDs must be unique and sorted")
    body = {key: value for key, value in directory.items() if key != "directory_sha256"}
    if digest(body) != _hash(directory["directory_sha256"]):
        raise CatalogError("directory digest differs")
    return strict_json(canonical(directory))


def _read_source(root, path, mounts=None):
    root = Path(root).resolve()
    path = _path(path)
    relative = path
    if mounts is not None:
        if type(mounts) is not dict or len(mounts) > 8:
            raise CatalogError("at most eight explicit source mounts")
        choices = []
        for prefix, mounted_root in mounts.items():
            _path(prefix)
            if path == prefix or path.startswith(prefix + "/"):
                choices.append((len(prefix), prefix, mounted_root))
        if choices:
            _, prefix, mounted_root = max(choices, key=lambda value: value[0])
            # The caller explicitly authorizes this mount root's resolution;
            # links beneath it remain refused. Nothing auto-follows a source
            # tree junction merely because it was inventoried.
            root = Path(mounted_root).resolve(strict=True)
            relative = path[len(prefix):].lstrip("/")
    target = root / relative
    for part in (target, *target.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise CatalogError("linked source paths are refused")
    try:
        target.resolve(strict=True).relative_to(root)
    except (ValueError, OSError) as exc:
        raise CatalogError("source absent or outside declared workspace") from exc
    if not target.is_file() or target.stat().st_size > 2 * 1024 * 1024:
        raise CatalogError("source not a bounded regular file")
    with target.open("rb") as file:
        raw = file.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise CatalogError("source grew beyond bound")
    return raw


def verify_source(entry, *, workspace_root, verify_evidence=False, mounts=None):
    entry = validate_entry(entry)
    if entry["source_sha256"] is None:
        return {"module_id": entry["module_id"], "status": "pending", "source_verified": False, "permission_granted": False}
    raw = _read_source(workspace_root, entry["path"], mounts)
    if sha256(raw) != entry["source_sha256"]:
        raise CatalogError("component source drift detected")
    if verify_evidence:
        for evidence in entry["evidence"]:
            if sha256(_read_source(workspace_root, evidence["path"], mounts)) != evidence["sha256"]:
                raise CatalogError("component evidence drift detected")
    return {"module_id": entry["module_id"], "status": entry["status"], "source_verified": True, "permission_granted": False, "bytes": len(raw), "source_sha256": sha256(raw)}


def status_counts(directory):
    value = validate_directory(directory)
    counts = Counter(row["status"] for row in value["entries"])
    return {status: counts.get(status, 0) for status in sorted(STATUSES)}


def handle_request(directory, request):
    directory = validate_directory(directory)
    if type(request) is not dict or set(request) != {"schema", "command", "query", "module_id", "limit"} or request["schema"] != REQUEST_SCHEMA:
        raise CatalogError("closed discovery request schema required")
    if request["command"] not in {"list", "query", "select", "route-plan"}:
        raise CatalogError("unknown command; execution is not provided")
    if type(request["limit"]) is not int or not 1 <= request["limit"] <= 128:
        raise CatalogError("discovery limit outside bounds")
    if type(request["query"]) is not str or len(request["query"].encode("utf-8")) > 512 or type(request["module_id"]) is not str or len(request["module_id"]) > 192:
        raise CatalogError("bounded query/selection required")
    entries = directory["entries"]
    command = request["command"]
    if command == "select":
        _identifier(request["module_id"])
        selected = [row for row in entries if row["module_id"] == request["module_id"]]
        if not selected:
            raise CatalogError("unknown module identity")
    elif command in {"query", "route-plan"}:
        terms = sorted(set(re.findall(r"[A-Za-z0-9_]{2,64}", request["query"].lower())))
        if not terms:
            raise CatalogError("query terms required")
        scored = []
        for row in entries:
            text = " ".join([row["module_id"], row["path"], *row["features"], *row["call_contract"]]).lower()
            score = sum(term in text for term in terms)
            if score:
                scored.append((score, row))
        selected = [row for _, row in sorted(scored, key=lambda pair: (-pair[0], pair[1]["module_id"]))]
    else:
        selected = entries
    selected = selected[:request["limit"]]
    result = {"schema": RESPONSE_SCHEMA, "command": command, "directory_sha256": directory["directory_sha256"], "entries": selected, "status_counts": status_counts(directory), "authority": "discovery-only", "permission_granted": False, "executed_commands": 0, "learning_promotions": 0}
    if command == "route-plan":
        result["route_plan"] = [{"order": number + 1, "module_id": row["module_id"], "source_sha256": row["source_sha256"], "required_scopes": row["scopes"], "side_effects": row["side_effects"], "status": "candidate-needs-current-source-and-caller-gate"} for number, row in enumerate(selected) if row["status"] in {"implemented", "wired", "verified"}]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--command", choices=("list", "query", "select", "route-plan"), default="list")
    parser.add_argument("--query", default="")
    parser.add_argument("--module-id", default="")
    parser.add_argument("--limit", type=int, default=32)
    parser.add_argument("--workspace-root")
    parser.add_argument("--verify-selected", action="store_true")
    parser.add_argument("--mount", action="append", default=[], help="explicit workspace-prefix=local-root; nested links remain refused")
    args = parser.parse_args(argv)
    path = Path(args.directory)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise CatalogError("directory file bound exceeded")
    directory = strict_json(path.read_bytes())
    result = handle_request(directory, {"schema": REQUEST_SCHEMA, "command": args.command, "query": args.query, "module_id": args.module_id, "limit": args.limit})
    if args.verify_selected:
        if not args.workspace_root:
            raise CatalogError("verification requires explicit workspace root")
        mounts = {}
        for item in args.mount:
            if "=" not in item:
                raise CatalogError("mount requires workspace-prefix=local-root")
            prefix, target = item.split("=", 1)
            if prefix in mounts or not target:
                raise CatalogError("duplicate or empty explicit mount")
            mounts[prefix] = target
        result["source_checks"] = [verify_source(row, workspace_root=args.workspace_root, verify_evidence=True, mounts=mounts) for row in result["entries"]]
    print(canonical(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
