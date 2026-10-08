"""Detached, source-pinned public datasets for caller-owned learning epochs.

No task source is compiled, imported or executed here. Public smoke expectations
are permitted; references, hidden tests and credentials are not. Content hashes
ignore task/case ID labels, and normalized hashes also normalize case/spacing.
Caller-supplied near-duplicate clusters are declarations, not semantic novelty
proof. A retained external manifest digest is required to detect wholesale edits.
"""
from __future__ import annotations

import copy
import math
from pathlib import Path
import re
import unicodedata

from .protocol import canonical, digest, sha256


SCHEMA = "xnet.learning-dataset.v1"
SPLITS = ("train", "validation", "unseen")
PUBLIC_FIELDS = {"task_id", "category", "issue", "files", "entry_file",
                 "entry_function", "editable_files", "api_contract", "public_cases"}
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\.py\Z")
_FORBIDDEN = {"reference", "references", "reference_source", "reference_files",
    "reference_patch", "reference_cases", "reference_answer", "repaired_source",
    "gold", "gold_answer", "gold_answers", "gold_patch", "gold_source", "gold_cases",
    "answer", "answers", "answer_payload", "solution", "solutions", "solution_source",
    "solution_files", "private_cases", "held_out_cases", "heldout_cases",
    "password", "credentials", "credential", "authorization", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "secret", "secrets"}


class LearningDatasetError(ValueError):
    pass


def _label(value, field):
    if type(value) is not str or not _LABEL.fullmatch(value):
        raise LearningDatasetError(field + " must be an exact bounded label")
    return value


def _hash(value, field):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise LearningDatasetError(field + " must be an exact SHA256 string")
    return value


def _key_name(value):
    # Covers camelCase, hyphens and spaces without granting aliases to schemas.
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", value).casefold())


_FORBIDDEN_KEYS = {_key_name(key) for key in _FORBIDDEN}


def _public_value(value, path=(), *, count=None):
    """Bound JSON data, reject private aliases even deep inside public inputs."""
    if count is None:
        count = [0]
    count[0] += 1
    if len(path) > 16 or count[0] > 6000:
        raise LearningDatasetError("public task JSON exceeds depth/node bounds")
    kind = type(value)
    if value is None or kind is bool:
        return
    if kind is int:
        if not -(2**63) <= value < 2**63:
            raise LearningDatasetError("public integer exceeds portable bounds")
        return
    if kind is float:
        if not math.isfinite(value):
            raise LearningDatasetError("nonfinite public number")
        return
    if kind is str:
        if len(value.encode("utf-8", "strict")) > 16384 or "\x00" in value:
            raise LearningDatasetError("public string exceeds bounds")
        if "PRIVATE KEY-----" in value:
            raise LearningDatasetError("private key material is not public task data")
        return
    if kind is list:
        if len(value) > 256:
            raise LearningDatasetError("public list exceeds bounds")
        for index, item in enumerate(value):
            _public_value(item, path + (index,), count=count)
        return
    if kind is dict:
        if len(value) > 256:
            raise LearningDatasetError("public object exceeds bounds")
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 128:
                raise LearningDatasetError("public JSON keys must be exact bounded strings")
            normalized = _key_name(key)
            marker = (key == "hidden" and len(path) == 2 and
                      path[0] == "public_cases" and type(path[1]) is int)
            if marker:
                if item is not False:
                    raise LearningDatasetError("public case hidden marker must be exact false")
            elif (normalized.startswith(("hidden", "reference", "gold", "solution", "answer"))
                  or normalized in _FORBIDDEN_KEYS):
                raise LearningDatasetError("private/reference/credential field refused: " + key)
            _public_value(item, path + (key,), count=count)
        return
    raise LearningDatasetError("public task must contain exact bounded JSON types")


def _text(value, field, limit=8192):
    if type(value) is not str or not value or len(value.encode("utf-8", "strict")) > limit:
        raise LearningDatasetError(field + " must be a bounded nonempty string")


def _task(task):
    if type(task) is not dict or set(task) != PUBLIC_FIELDS:
        raise LearningDatasetError("exact public task view fields required")
    _public_value(task)
    _label(task["task_id"], "task_id")
    _text(task["category"], "category", 128)
    _text(task["issue"], "issue")
    files = task["files"]
    if type(files) is not dict or not 1 <= len(files) <= 8:
        raise LearningDatasetError("one to eight inert source files required")
    for name, text in files.items():
        if type(name) is not str or not _FILE.fullmatch(name):
            raise LearningDatasetError("source filenames must be flat Python labels")
        _text(text, "source file")
    if type(task["entry_file"]) is not str or task["entry_file"] not in files:
        raise LearningDatasetError("entry_file must name a supplied file")
    _label(task["entry_function"], "entry_function")
    editable = task["editable_files"]
    if (type(editable) is not list or not editable or
        any(type(name) is not str or name not in files for name in editable) or
        len(set(editable)) != len(editable)):
        raise LearningDatasetError("editable_files must be distinct supplied filenames")
    contract = task["api_contract"]
    if type(contract) is not dict or set(contract) != {
            "signature", "requirements", "dependencies", "replacement_limit_bytes"}:
        raise LearningDatasetError("exact public API contract required")
    for field in ("signature", "requirements", "dependencies"):
        _text(contract[field], field)
    if (type(contract["replacement_limit_bytes"]) is not int or
        not 1 <= contract["replacement_limit_bytes"] <= 8192):
        raise LearningDatasetError("replacement_limit_bytes must be an exact bounded integer")
    cases = task["public_cases"]
    if type(cases) is not list or not 1 <= len(cases) <= 64:
        raise LearningDatasetError("bounded public cases required")
    for case in cases:
        required = {"args", "kwargs", "case_type", "case_id", "name", "hidden"}
        if (type(case) is not dict or not required <= set(case) or
            set(case) - required not in ({"expected"}, {"raises"})):
            raise LearningDatasetError("exact public case fields required")
        if (type(case["args"]) is not list or type(case["kwargs"]) is not dict or
            type(case["case_type"]) is not str or case["case_type"] not in ("F2P", "P2P") or
            case["hidden"] is not False or type(case["name"]) is not str or
            case["name"] != task["entry_function"]):
            raise LearningDatasetError("invalid public case types/bindings")
        _label(case["case_id"], "case_id")
        if "raises" in case:
            _label(case["raises"], "raises")
    if len(canonical(task)) > 65536:
        raise LearningDatasetError("public task exceeds byte budget")


def _content(task):
    value = copy.deepcopy(task)
    value.pop("task_id")
    for case in value["public_cases"]:
        case.pop("case_id")
    return value


def _normalize(value):
    if type(value) is str:
        return " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    if type(value) is list:
        return [_normalize(item) for item in value]
    if type(value) is dict:
        return {key: _normalize(item) for key, item in value.items()}
    return value


def _provenance(value):
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise LearningDatasetError("task source provenance required")
    base = {"kind", "source_manifest_sha256"}
    kind = value["kind"]
    if kind == "synthetic-authored":
        if set(value) != base:
            raise LearningDatasetError("exact synthetic provenance fields required")
    elif kind == "pattern-derived":
        if set(value) != base | {"original_change_sha256", "transform_sha256"}:
            raise LearningDatasetError("derived provenance must pin original change and transform")
        _hash(value["original_change_sha256"], "original_change_sha256")
        _hash(value["transform_sha256"], "transform_sha256")
    else:
        raise LearningDatasetError("unsupported provenance; derived fixtures are not raw repo benchmarks")
    _hash(value["source_manifest_sha256"], "source_manifest_sha256")
    return copy.deepcopy(value)


def _hash_list(values, field):
    if type(values) not in (list, tuple) or len(values) > 10000:
        raise LearningDatasetError(field + " must be a bounded list/tuple")
    result = [_hash(value, field) for value in values]
    if len(set(result)) != len(result):
        raise LearningDatasetError("duplicate deny-list identity")
    return sorted(result)


def _source_pins():
    directory = Path(__file__).resolve().parent
    return {name: sha256((directory / name).read_bytes())
            for name in ("learning_dataset.py", "protocol.py")}


def freeze_learning_dataset(splits, provenance, *, clusters=None,
        cluster_provenance=None, denied_content_sha256=(), denied_cluster_ids=(),
        caller_source_sha256=None):
    """Seal exact PUBLIC views; each of train/validation/unseen has 2..50 tasks.

    ``provenance`` maps every task ID to ``{kind, source_manifest_sha256}``.
    ``pattern-derived`` additionally requires original_change_sha256 and
    transform_sha256. ``clusters`` optionally maps selected task IDs to stable
    caller cluster labels. Its provenance must contain method_id, source_sha256
    and assignment_sha256=digest(clusters). Cluster IDs may not span splits.
    Known evaluated exact/normalized content pins and caller cluster IDs are
    refused in validation/unseen. They may recur in train as retired practice.
    No semantic novelty or authenticity is inferred from caller declarations.
    Returned dictionaries are detached hash-sealed data, not mutable authority.
    """
    if type(splits) is not dict or set(splits) != set(SPLITS):
        raise LearningDatasetError("exact train/validation/unseen split fields required")
    task_ids = []
    for split in SPLITS:
        tasks = splits[split]
        if type(tasks) is not list or not 2 <= len(tasks) <= 50:
            raise LearningDatasetError("each split requires two to fifty exact public tasks")
        for task in tasks:
            _task(task)
            task_ids.append(task["task_id"])
    if len(set(task_ids)) != len(task_ids):
        raise LearningDatasetError("task IDs must be globally distinct")
    if type(provenance) is not dict or set(provenance) != set(task_ids):
        raise LearningDatasetError("provenance must bind every exact task ID")
    sources = {task_id: _provenance(provenance[task_id]) for task_id in task_ids}
    denied_content = _hash_list(denied_content_sha256, "denied_content_sha256")
    if type(denied_cluster_ids) not in (list, tuple) or len(denied_cluster_ids) > 10000:
        raise LearningDatasetError("denied_cluster_ids must be a bounded list/tuple")
    denied_clusters = [_label(value, "denied_cluster_id") for value in denied_cluster_ids]
    if len(set(denied_clusters)) != len(denied_clusters):
        raise LearningDatasetError("duplicate denied cluster ID")
    denied_clusters.sort()
    assignments = {} if clusters is None else copy.deepcopy(clusters)
    if (type(assignments) is not dict or not set(assignments) <= set(task_ids) or
        any(type(task_id) is not str for task_id in assignments)):
        raise LearningDatasetError("clusters must assign known exact task IDs")
    for cluster_id in assignments.values():
        _label(cluster_id, "cluster_id")
    if assignments:
        if (type(cluster_provenance) is not dict or set(cluster_provenance) != {
                "method_id", "source_sha256", "assignment_sha256"}):
            raise LearningDatasetError("supplied cluster assignments require source/method identity")
        _label(cluster_provenance["method_id"], "cluster method_id")
        _hash(cluster_provenance["source_sha256"], "cluster source_sha256")
        _hash(cluster_provenance["assignment_sha256"], "cluster assignment_sha256")
        if cluster_provenance["assignment_sha256"] != digest(assignments):
            raise LearningDatasetError("cluster assignment identity differs")
    elif cluster_provenance is not None:
        raise LearningDatasetError("cluster provenance without assignments")
    if caller_source_sha256 is not None:
        _hash(caller_source_sha256, "caller_source_sha256")
    seen_content, seen_normalized, seen_clusters = {}, {}, {}
    rows = {}
    for split in SPLITS:
        rows[split] = []
        for task in splits[split]:
            tid = task["task_id"]
            exact = digest(_content(task))
            normalized = digest(_normalize(_content(task)))
            cluster_id = assignments.get(tid)
            for identity, seen in ((exact, seen_content), (normalized, seen_normalized)):
                if identity in seen and seen[identity] != split:
                    raise LearningDatasetError("duplicate public content crosses splits")
                seen[identity] = split
            if cluster_id is not None:
                if cluster_id in seen_clusters and seen_clusters[cluster_id] != split:
                    raise LearningDatasetError("declared near-duplicate cluster crosses splits")
                seen_clusters[cluster_id] = split
            if split != "train" and (exact in denied_content or normalized in denied_content or
                                    cluster_id in denied_clusters):
                raise LearningDatasetError("known prior evaluated content/cluster reused as holdout")
            rows[split].append({"task_id": tid, "public_task": copy.deepcopy(task),
                "public_task_sha256": digest(task), "content_sha256": exact,
                "normalized_content_sha256": normalized, "cluster_id": cluster_id,
                "provenance": sources[tid], "derived": sources[tid]["kind"] == "pattern-derived",
                "raw_repo_benchmark": False})
    body = {"schema": SCHEMA, "splits": rows,
        "clusters": assignments, "cluster_provenance": copy.deepcopy(cluster_provenance),
        "denied_content_sha256": denied_content, "denied_cluster_ids": denied_clusters,
        "caller_source_sha256": caller_source_sha256, "source_pins": _source_pins(),
        "normalization": {"id": "public-content-no-id-nfkc-casefold-whitespace-v1",
                          "unicode_version": unicodedata.unidata_version},
        "public_only": True, "weights_updated": False, "semantic_novelty_proven": False,
        "cluster_basis": "caller-declared; no automatic semantic similarity proof"}
    return copy.deepcopy({**body, "manifest_sha256": digest(body)})


def verify_learning_dataset(manifest, *, expected_sha256=None):
    """Revalidate source/content/splits and return a detached verified manifest.

    ``expected_sha256`` should be the retained digest bound into LearningCycle.
    Without an external expected digest, this validates consistency only.
    """
    fields = {"schema", "splits", "clusters", "cluster_provenance", "denied_content_sha256",
        "denied_cluster_ids", "caller_source_sha256", "source_pins", "normalization",
        "public_only", "weights_updated", "semantic_novelty_proven", "cluster_basis", "manifest_sha256"}
    if type(manifest) is not dict or set(manifest) != fields:
        raise LearningDatasetError("exact sealed learning dataset fields required")
    _hash(manifest["manifest_sha256"], "manifest_sha256")
    if expected_sha256 is not None:
        _hash(expected_sha256, "expected_sha256")
        if manifest["manifest_sha256"] != expected_sha256:
            raise LearningDatasetError("learning dataset differs from external manifest pin")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if digest(body) != manifest["manifest_sha256"]:
        raise LearningDatasetError("learning dataset manifest hash mismatch")
    if manifest["source_pins"] != _source_pins():
        raise LearningDatasetError("learning dataset source/helper identity changed")
    if type(manifest["splits"]) is not dict or set(manifest["splits"]) != set(SPLITS):
        raise LearningDatasetError("invalid sealed learning splits")
    tasks, sources = {}, {}
    row_fields = {"task_id", "public_task", "public_task_sha256", "content_sha256",
                  "normalized_content_sha256", "cluster_id", "provenance", "derived", "raw_repo_benchmark"}
    for split in SPLITS:
        rows = manifest["splits"][split]
        if type(rows) is not list or not 2 <= len(rows) <= 50:
            raise LearningDatasetError("invalid sealed split bounds")
        tasks[split] = []
        for row in rows:
            if type(row) is not dict or set(row) != row_fields:
                raise LearningDatasetError("exact sealed task row required")
            _label(row["task_id"], "task_id")
            if row["task_id"] in sources:
                raise LearningDatasetError("duplicate sealed task ID")
            tasks[split].append(row["public_task"])
            sources[row["task_id"]] = row["provenance"]
    rebuilt = freeze_learning_dataset(tasks, sources, clusters=manifest["clusters"],
        cluster_provenance=manifest["cluster_provenance"],
        denied_content_sha256=manifest["denied_content_sha256"],
        denied_cluster_ids=manifest["denied_cluster_ids"],
        caller_source_sha256=manifest["caller_source_sha256"])
    if canonical(rebuilt) != canonical(manifest):
        raise LearningDatasetError("sealed public content, flags or provenance differs")
    return copy.deepcopy(rebuilt)
