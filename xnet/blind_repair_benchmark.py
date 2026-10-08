"""Frozen three-lane repair comparison with a held-out grading boundary.

The runner receives public tasks plus a digest commitment to the held-out file.
It cannot grade.  ``grade`` opens that file only after every public choice is
frozen.  Candidate Python remains inert and is interpreted by the bounded XNET
AST worker; it is never imported into the host interpreter.

This is a custom SWE-style benchmark, not official SWE-bench.
"""
from __future__ import annotations

import ast
import copy
import json
import math
import os
from pathlib import Path
import re
import statistics
import tempfile
import time
from typing import Callable

from .brains import _exclusive_file_lock
from .hce_capsule_v1 import encode_capsule
from .protocol import canonical, digest, sha256
from .repair_loop import is_noop_patch
from .swe_repair_evaluator import (bundle_hashes, declared_import_graph,
                                   evaluate_bundle, public_feedback,
                                   repair_capability_contract)

SCHEMA = "xnet.blind-repair50.run.v1"
LANES = ("raw", "retrieval", "full-xnet")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_]+")
_BENCHMARK_CLAIM = "custom frozen SWE-style; not official SWE-bench"
_SOURCE_FILES = (
    "benchmark_environment.py",
    "blind_repair_benchmark.py",
    "brains.py",
    "hce_capsule_v1.py",
    "local_provider.py",
    "protocol.py",
    "repair_evaluator.py",
    "repair_loop.py",
    "swe_repair_evaluator.py",
)
_PUBLIC_FIELDS = {"task_id", "category", "issue", "files", "entry_file",
                  "entry_function", "editable_files", "api_contract", "public_cases"}
_PUBLIC_OPTIONAL_FIELDS = {"family", "fixture_version"}
_COMMON_SYSTEM = (
    "Repair the supplied bounded multi-file Python task. Return only one JSON object "
    "with exactly this shape: {\"files\":{\"changed.py\":\"complete UTF-8 source\"}}. "
    "Return only changed editable files. Preserve the API and declared local imports. "
    "Do not use Markdown, tools, filesystem, network, subprocess, dynamic imports or hidden tests. "
)
_FULL_SYSTEM = (
    "XNET route: trace the entrypoint through supplied helpers; identify the failed invariant; "
    "apply the narrowest general repair; check the public counterexample and preserve passing behavior. "
)


class BenchmarkError(ValueError):
    pass


class PendingGeneration(BenchmarkError):
    """A durable request exists but no response is known; never dispatch it again."""


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BenchmarkError("duplicate JSON field")
        value[key] = item
    return value


def _load_json(path: Path, *, maximum=8 * 1024 * 1024):
    path = Path(path)
    raw = path.read_bytes()
    if not 1 <= len(raw) <= maximum:
        raise BenchmarkError("JSON artifact exceeds bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(BenchmarkError("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BenchmarkError("canonical UTF-8 JSON artifact required") from exc
    return value, raw


def _atomic_new(path: Path, value):
    """Write one immutable receipt, binding its body with receipt_sha256."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(path)
    body = copy.deepcopy(value)
    if type(body) is not dict or "receipt_sha256" in body:
        raise BenchmarkError("receipt body must be an object without receipt_sha256")
    body["receipt_sha256"] = digest(body)
    raw = canonical(body) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".xnet-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return body


def _read_receipt(path: Path):
    value, raw = _load_json(path)
    if type(value) is not dict or type(value.get("receipt_sha256")) is not str:
        raise BenchmarkError("sealed receipt required")
    expected = value["receipt_sha256"]
    body = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if not _HEX.fullmatch(expected) or digest(body) != expected:
        raise BenchmarkError("receipt hash mismatch")
    if raw != canonical(value) + b"\n":
        raise BenchmarkError("receipt must use canonical UTF-8 JSON encoding")
    return value


def _exact_object(value, fields, label):
    if type(value) is not dict or set(value) != set(fields):
        raise BenchmarkError(label + " fields differ from frozen schema")
    return value


def _hash_pin(value, label):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise BenchmarkError(label + " must be a lowercase SHA-256")
    return value


def _exact_int(value, label, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise BenchmarkError(label + " must be an exact integer")
    return value


def _validate_sealed(value, *, schema, fields, label):
    _exact_object(value, set(fields) | {"receipt_sha256"}, label)
    if value["schema"] != schema:
        raise BenchmarkError("unsupported " + label + " schema")
    expected = _hash_pin(value["receipt_sha256"], label + " receipt_sha256")
    body = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if digest(body) != expected:
        raise BenchmarkError("receipt hash mismatch")
    return value


def _validate_manifest(value):
    fields = {
        "schema", "created_unix_ns", "task_count", "lanes", "schedule",
        "public_suite_sha256", "public_tasks_sha256", "hidden_suite_sha256",
        "protocol_sha256", "corpus_sha256", "provider_profile_sha256",
        "environment_receipt_sha256", "environment_identity_sha256",
        "cold_prompt_attested",
        "source_sha256", "model_calls_during_prepare", "hidden_suite_opened",
        "candidate_execution", "benchmark_claim",
    }
    _validate_sealed(value, schema=SCHEMA, fields=fields, label="run manifest")
    _exact_int(value["created_unix_ns"], "created_unix_ns", minimum=1)
    task_count = _exact_int(value["task_count"], "task_count", minimum=1)
    if (value["lanes"] != list(LANES) or value["model_calls_during_prepare"] != 0
            or value["hidden_suite_opened"] is not False
            or value["candidate_execution"] is not False
            or value["benchmark_claim"] != _BENCHMARK_CLAIM):
        raise BenchmarkError("run manifest invariant differs")
    for name in ("public_suite_sha256", "public_tasks_sha256", "hidden_suite_sha256",
                 "protocol_sha256", "corpus_sha256", "provider_profile_sha256"):
        _hash_pin(value[name], name)
    for name in ("environment_receipt_sha256", "environment_identity_sha256"):
        if value[name] is not None:
            _hash_pin(value[name], name)
    if (type(value["cold_prompt_attested"]) is not bool
            or (value["environment_receipt_sha256"] is None)
               != (value["environment_identity_sha256"] is None)
            or value["cold_prompt_attested"]
               != (value["environment_identity_sha256"] is not None)):
        raise BenchmarkError("benchmark environment linkage differs")
    sources = _exact_object(value["source_sha256"], _SOURCE_FILES, "source pin")
    for name, item in sources.items():
        _hash_pin(item, "source_sha256." + name)
    schedule = value["schedule"]
    if type(schedule) is not list or len(schedule) != task_count * len(LANES):
        raise BenchmarkError("run manifest schedule is incomplete")
    identities = set()
    for slot in schedule:
        _exact_object(slot, {"task_id", "lane", "case_id"}, "schedule slot")
        if (type(slot["task_id"]) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", slot["task_id"]) is None
                or slot["lane"] not in LANES
                or slot["case_id"] != slot["lane"] + "--" + slot["task_id"]):
            raise BenchmarkError("invalid run manifest schedule slot")
        identity = (slot["task_id"], slot["lane"])
        if identity in identities:
            raise BenchmarkError("duplicate run manifest schedule slot")
        identities.add(identity)
    return value


def _portable_number(value, name):
    if value is None:
        return None
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
        raise BenchmarkError(name + " must be a nonnegative finite number or null")
    return value


def _receipt_body(value):
    return {key: item for key, item in value.items() if key != "receipt_sha256"}


def _validate_request_receipt(value, expected=None):
    fields = {"schema", "manifest_sha256", "case_id", "task_id", "lane", "attempt",
              "messages", "context_evidence", "max_output_tokens", "temperature", "seed",
              "hidden_data_used"}
    _validate_sealed(value, schema="xnet.blind-repair50.request.v1", fields=fields,
                     label="generation request")
    _hash_pin(value["manifest_sha256"], "request manifest_sha256")
    if (type(value["task_id"]) is not str or value["lane"] not in LANES
            or value["case_id"] != value["lane"] + "--" + value["task_id"]
            or value["attempt"] not in (1, 2)
            or type(value["max_output_tokens"]) is not int or value["max_output_tokens"] < 1
            or type(value["seed"]) is not int or type(value["seed"]) is bool
            or type(value["temperature"]) not in (int, float)
            or type(value["temperature"]) is bool or not math.isfinite(value["temperature"])
            or value["hidden_data_used"] is not False):
        raise BenchmarkError("generation request invariant differs")
    context = value["context_evidence"]
    if (type(context) is not dict or context.get("lane") != value["lane"]
            or context.get("attempt") != value["attempt"]
            or context.get("hidden_data_used") is not False
            or context.get("authority") != "none"
            or context.get("messages_sha256") != digest(value["messages"])):
        raise BenchmarkError("generation request context linkage differs")
    if expected is not None and _receipt_body(value) != expected:
        raise BenchmarkError("generation request differs from frozen task and protocol")
    return value


def _validate_response_receipt(value, reservation=None):
    fields = {"schema", "reservation_sha256", "generation", "callback_wall_seconds"}
    _validate_sealed(value, schema="xnet.blind-repair50.response.v1", fields=fields,
                     label="generation response")
    _hash_pin(value["reservation_sha256"], "response reservation_sha256")
    if reservation is not None and value["reservation_sha256"] != reservation["receipt_sha256"]:
        raise BenchmarkError("generation response does not link to its request")
    callback = _portable_number(value["callback_wall_seconds"], "callback_wall_seconds")
    if callback is None:
        raise BenchmarkError("callback_wall_seconds must be observed")
    if _normalize_generation(value["generation"]) != value["generation"]:
        raise BenchmarkError("generation response is not normalized")
    return value


def _validate_public_task(task):
    if (type(task) is not dict or not _PUBLIC_FIELDS <= set(task)
            or set(task) - _PUBLIC_FIELDS - _PUBLIC_OPTIONAL_FIELDS):
        raise BenchmarkError("public task fields differ from frozen schema")
    if (type(task["task_id"]) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", task["task_id"]) is None
            or type(task["category"]) is not str or type(task["issue"]) is not str):
        raise BenchmarkError("invalid public task identity")
    files = task["files"]
    if type(files) is not dict or not 2 <= len(files) <= 4 or set(task["editable_files"]) != set(files):
        raise BenchmarkError("task requires two to four declared editable modules")
    if task["entry_file"] not in files or type(task["entry_function"]) is not str:
        raise BenchmarkError("invalid task entrypoint")
    for name, source in files.items():
        if (type(name) is not str or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*\.py", name) is None
                or type(source) is not str or "\x00" in source):
            raise BenchmarkError("invalid public source bundle")
    bundle_hashes(files)
    declared_import_graph(files)
    contract = task["api_contract"]
    if type(contract) is not dict or type(contract.get("replacement_limit_bytes")) is not int:
        raise BenchmarkError("invalid API contract")
    cases = task["public_cases"]
    if type(cases) is not list or len(cases) != 2:
        raise BenchmarkError("exactly two public cases required")
    if {case.get("case_type") for case in cases} != {"F2P", "P2P"}:
        raise BenchmarkError("public cases require one F2P and one P2P")
    for case in cases:
        if type(case) is not dict or case.get("hidden") is not False or case.get("name") != task["entry_function"]:
            raise BenchmarkError("public case visibility or entrypoint changed")
        if ("expected" in case) == ("raises" in case):
            raise BenchmarkError("public case requires exactly one outcome")
    if any(token in canonical(task).decode("utf-8").lower()
           for token in ('"hidden_cases"', '"gold_patch"', '"repaired_source"')):
        raise BenchmarkError("grader material in public task")
    return copy.deepcopy(task)


def _validate_public_suite(value, raw):
    if type(value) is not dict:
        raise BenchmarkError("public suite fields differ from frozen schema")
    simple = value.get("schema") == "xnet.blind-repair50.public.v1"
    authored = value.get("schema") == "xnet.blind50-public-suite.v1"
    expected = ({"schema", "tasks"} if simple else
                {"schema", "classification", "fixture_version", "task_count",
                 "public_case_count", "tasks"} if authored else set())
    _exact_object(value, expected, "public suite")
    if not (simple or authored):
        raise BenchmarkError("unsupported public suite schema")
    tasks_raw = value["tasks"]
    if type(tasks_raw) is not list or not tasks_raw:
        raise BenchmarkError("public suite requires tasks")
    lowered = raw.lower()
    if any(marker in lowered for marker in (b'"hidden_cases"', b'"gold_patch"',
                                             b'"repaired_source"', b'"reference_patch"')):
        raise BenchmarkError("public suite contains grader or reference material")
    tasks = [_validate_public_task(task) for task in tasks_raw]
    if len({task["task_id"] for task in tasks}) != len(tasks):
        raise BenchmarkError("public task IDs must be unique")
    if authored and (value["classification"]
            != "external-custom-swe-style-blind-exam-not-official-swe-bench"
            or type(value["fixture_version"]) is not str
            or re.fullmatch(r"xnet\.blind50\.[0-9]{8}\.r[0-9]{2}",
                            value["fixture_version"]) is None
            or value["task_count"] != len(tasks)
            or type(value["task_count"]) is not int
            or value["public_case_count"] != sum(len(task["public_cases"]) for task in tasks)
            or type(value["public_case_count"]) is not int):
        raise BenchmarkError("public suite provenance or counts differ")
    return tasks


def _validate_protocol(value, task_count):
    required = {"schema", "benchmark_name", "benchmark_kind", "official_swe_bench",
                "base_commit", "task_count", "lanes", "inference", "success_gate"}
    if (type(value) is not dict or not required <= set(value)
            or value.get("schema") != "xnet.blind-repair50.protocol.v1"
            or value.get("task_count") != task_count or type(value.get("task_count")) is not int
            or value.get("lanes") != list(LANES)
            or value.get("official_swe_bench") is not False
            or type(value.get("benchmark_name")) is not str
            or type(value.get("benchmark_kind")) is not str
            or type(value.get("base_commit")) is not str
            or _COMMIT.fullmatch(value["base_commit"]) is None):
        raise BenchmarkError("protocol identity or task count differs")
    inference = value.get("inference")
    inference_required = {"temperature", "seed", "max_output_tokens", "max_attempts",
                          "stateless_calls", "cross_task_kv_reuse", "hidden_feedback"}
    if (type(inference) is not dict or not inference_required <= set(inference)
            or type(inference.get("temperature")) not in (int, float)
            or type(inference.get("temperature")) is bool or inference["temperature"] != 0
            or type(inference.get("seed")) is not int or inference["seed"] != 0
            or type(inference.get("max_output_tokens")) is not int
            or inference["max_output_tokens"] < 1
            or type(inference.get("max_attempts")) is not int
            or not 1 <= inference["max_attempts"] <= 2
            or inference["stateless_calls"] is not True
            or inference["cross_task_kv_reuse"] is not False
            or inference["hidden_feedback"] is not False):
        raise BenchmarkError("invalid frozen inference policy")
    gate = value["success_gate"]
    gate_fields = {"full_minus_raw_minimum_solves", "full_minus_retrieval_minimum_solves",
                   "p2p_preservation_minimum_tasks", "maximum_hidden_or_retrieval_leaks",
                   "maximum_candidate_host_executions", "full_lane_median_task_seconds_maximum",
                   "full_to_raw_total_token_ratio_maximum",
                   "confirmatory_full_minus_raw_minimum_solves"}
    if type(gate) is not dict or not gate_fields <= set(gate):
        raise BenchmarkError("invalid frozen success gate")
    for name in gate_fields - {"full_lane_median_task_seconds_maximum",
                              "full_to_raw_total_token_ratio_maximum"}:
        if type(gate[name]) is not int or gate[name] < 0:
            raise BenchmarkError("invalid frozen success gate")
    for name in ("full_lane_median_task_seconds_maximum",
                 "full_to_raw_total_token_ratio_maximum"):
        if (_portable_number(gate[name], name) is None or gate[name] <= 0):
            raise BenchmarkError("invalid frozen success gate")
    if "lane_order" in value and value["lane_order"] != {
            "index_mod_3_0": list(lane_order(0)),
            "index_mod_3_1": list(lane_order(1)),
            "index_mod_3_2": list(lane_order(2))}:
        raise BenchmarkError("protocol lane order differs")
    return copy.deepcopy(value)


def _validate_provider_profile(value, protocol):
    from .local_provider import LocalProviderProfile
    try:
        normalized = LocalProviderProfile.from_mapping(value).as_dict()
    except ValueError as exc:
        raise BenchmarkError("frozen local provider profile required") from exc
    if normalized != value:
        raise BenchmarkError("provider profile is not normalized")
    inference = protocol["inference"]
    if (value["max_output_tokens"] != inference["max_output_tokens"]
            or value["temperature"] != float(inference["temperature"])
            or value["seed"] != inference["seed"]):
        raise BenchmarkError("provider settings differ from frozen protocol")
    return normalized


def _validate_corpus(value):
    if type(value) is not dict or value.get("schema") != "xnet.repair-card-corpus.v1":
        raise BenchmarkError("unsupported retrieval corpus")
    cards = value.get("cards")
    if type(cards) is not list or not 1 <= len(cards) <= 128:
        raise BenchmarkError("bounded retrieval cards required")
    identifiers = set()
    for card in cards:
        if (type(card) is not dict or set(card) != {"id", "tags", "text"}
                or type(card["id"]) is not str or not re.fullmatch(r"[a-z0-9-]{1,64}", card["id"])
                or card["id"] in identifiers or type(card["tags"]) is not list
                or any(type(tag) is not str for tag in card["tags"])
                or type(card["text"]) is not str or not 1 <= len(card["text"].encode("utf-8")) <= 2048):
            raise BenchmarkError("invalid retrieval card")
        identifiers.add(card["id"])
        lowered = card["text"].lower()
        if any(word in lowered for word in ("hidden case", "gold patch", "expected output", "task id")):
            raise BenchmarkError("retrieval card appears to contain evaluator material")
    return copy.deepcopy(value)


def lane_order(index):
    orders = (("raw", "retrieval", "full-xnet"),
              ("retrieval", "full-xnet", "raw"),
              ("full-xnet", "raw", "retrieval"))
    if type(index) is not int or index < 0:
        raise BenchmarkError("task index must be a nonnegative integer")
    return orders[index % 3]


def _terms(text):
    return [term.lower() for term in _TOKEN.findall(text)]


def retrieve_cards(task, corpus, *, limit=2):
    """Small deterministic BM25-like public-card selector with lexical ties."""
    if type(limit) is not int or not 1 <= limit <= 8:
        raise BenchmarkError("retrieval limit outside bound")
    query_text = task["issue"] + " " + canonical(task["api_contract"]).decode("utf-8")
    query = set(_terms(query_text))
    cards = corpus["cards"]
    documents = [set(_terms(" ".join(card["tags"]) + " " + card["text"])) for card in cards]
    frequency = {term: sum(term in document for document in documents) for term in query}
    rows = []
    for card, document in zip(cards, documents):
        score = sum(math.log((len(cards) + 1) / (frequency[term] + 1)) + 1
                    for term in query & document)
        rows.append({"id": card["id"], "text": card["text"],
                     "score": round(score, 9), "text_sha256": sha256(card["text"].encode("utf-8"))})
    rows.sort(key=lambda row: (-row["score"], row["id"]))
    return rows[:limit]


def _cards_evidence(cards):
    result = []
    for card in cards:
        raw = card["text"].encode("utf-8")
        wire = encode_capsule(raw, expected_source_sha256=sha256(raw), ring=1,
                              kind="repair-card", classification="public")
        result.append({"id": card["id"], "score": card["score"],
                       "text_sha256": card["text_sha256"],
                       "capsule_sha256": sha256(wire), "capsule_bytes": len(wire)})
    return result


def _compact_cards(cards):
    return "\n".join("[" + card["id"] + "#" + card["text_sha256"][:12] + "] " + card["text"]
                     for card in cards)


def build_messages(task, lane, attempt, base_files, feedback, corpus):
    if lane not in LANES or attempt not in (1, 2):
        raise BenchmarkError("invalid lane or attempt")
    public = copy.deepcopy(task)
    public["files"] = copy.deepcopy(base_files)
    context = {"task": public, "public_feedback": copy.deepcopy(feedback),
               "base_strategy": "last admitted proposal; otherwise original public source"}
    cards = []
    if lane == "retrieval":
        cards = retrieve_cards(public, corpus, limit=2)
    elif lane == "full-xnet":
        cards = retrieve_cards(public, corpus, limit=1 if attempt == 1 else 3)
    if cards:
        context["repair_cards"] = _compact_cards(cards)
    system = _COMMON_SYSTEM + repair_capability_contract()
    if lane == "full-xnet":
        system += " " + _FULL_SYSTEM
        if attempt == 2:
            system += " Accordion retry: expand only from the bounded public failure and selected public cards."
    user = canonical(context).decode("utf-8")
    prompt = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    evidence = {"lane": lane, "attempt": attempt, "messages_sha256": digest(prompt),
                "message_bytes": len(canonical(prompt)), "cards": _cards_evidence(cards),
                "selected_card_bytes": sum(len(card["text"].encode("utf-8")) for card in cards),
                "verbose_card_bytes": len(canonical(cards)) if cards else 0,
                "hidden_data_used": False, "authority": "none"}
    return prompt, evidence


def _parse_candidate(text, task, base_files):
    if type(text) is not str or not 1 <= len(text.encode("utf-8")) <= 32768:
        raise BenchmarkError("bounded candidate JSON text required")
    normalized = text
    normalization = []
    stripped = normalized.strip()
    fenced = re.fullmatch(r"```(?:json)?[ \t]*\r?\n(.*)\r?\n```", stripped,
                          flags=re.IGNORECASE | re.DOTALL)
    if fenced is not None:
        normalized = fenced.group(1)
        normalization.append("unwrap-single-json-fence")
    try:
        value = json.loads(normalized, object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(BenchmarkError("nonfinite JSON")))
    except json.JSONDecodeError as original:
        trimmed = normalized.rstrip()
        if original.pos < len(trimmed) - 1:
            raise BenchmarkError("candidate is not strict UTF-8 JSON") from original
        stack = []
        in_string = False
        escaped = False
        mismatched = False
        for character in trimmed:
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character == "{":
                stack.append("}")
            elif character == "[":
                stack.append("]")
            elif character in "}]":
                if not stack or stack[-1] != character:
                    mismatched = True
                    break
                stack.pop()
        if in_string or escaped or mismatched or not 1 <= len(stack) <= 2:
            raise BenchmarkError("candidate is not strict UTF-8 JSON") from original
        closers = "".join(reversed(stack))
        normalized = trimmed + closers
        normalization.append("append-missing-terminal-closers:" + closers)
        try:
            value = json.loads(normalized, object_pairs_hook=_unique_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(
                                   BenchmarkError("nonfinite JSON")))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise BenchmarkError("candidate is not strict UTF-8 JSON") from exc
    except (UnicodeError, RecursionError) as exc:
        raise BenchmarkError("candidate is not strict UTF-8 JSON") from exc
    if type(value) is not dict or set(value) != {"files"} or type(value["files"]) is not dict:
        raise BenchmarkError("candidate requires exactly a files map")
    edits = value["files"]
    if not edits or set(edits) - set(task["editable_files"]):
        raise BenchmarkError("candidate changed undeclared files or is empty")
    result = dict(base_files)
    for name, source in edits.items():
        if (type(source) is not str or "\x00" in source
                or len(source.encode("utf-8")) > task["api_contract"]["replacement_limit_bytes"]):
            raise BenchmarkError("invalid replacement source")
        result[name] = source
    if set(result) != set(task["files"]):
        raise BenchmarkError("candidate bundle differs from declared files")
    bundle_hashes(result)
    return result, normalization


def _normalize_generation(value):
    required = {"text", "usage", "timing", "transport", "speculative"}
    optional = {"throughput"}
    if (type(value) is not dict or not required <= set(value)
            or set(value) - required - optional or type(value["text"]) is not str):
        raise BenchmarkError("generation callback returned an unexpected envelope")
    usage = value["usage"]
    usage_required = {"input_tokens", "output_tokens", "total_tokens"}
    usage_optional = {"cached_input_tokens"}
    if (type(usage) is not dict or not usage_required <= set(usage)
            or set(usage) - usage_required - usage_optional):
        raise BenchmarkError("generation usage fields differ")
    normalized_usage = {
        key: None if usage.get(key) is None else int(_portable_number(usage[key], key))
        for key in ("input_tokens", "output_tokens", "total_tokens", "cached_input_tokens")}
    if any(item is not None and type(usage.get(key)) is not int
           for key, item in normalized_usage.items()):
        raise BenchmarkError("token counters must be exact integers or null")
    if (normalized_usage["cached_input_tokens"] is not None
            and normalized_usage["input_tokens"] is not None
            and normalized_usage["cached_input_tokens"] > normalized_usage["input_tokens"]):
        raise BenchmarkError("cached input tokens exceed input tokens")
    timing = value["timing"]
    timing_fields = {"prompt_seconds", "decode_seconds", "ttft_seconds", "total_seconds"}
    if type(timing) is not dict or set(timing) != timing_fields:
        raise BenchmarkError("generation timing fields differ")
    normalized_timing = {key: _portable_number(item, key) for key, item in timing.items()}
    transport = value["transport"]
    if (type(transport) is not dict or set(transport) != {"request_sha256", "response_sha256", "status"}
            or not _HEX.fullmatch(transport["request_sha256"])
            or not _HEX.fullmatch(transport["response_sha256"])
            or type(transport["status"]) is not int):
        raise BenchmarkError("generation transport evidence differs")
    speculative = value["speculative"]
    if type(speculative) is not dict or set(speculative) != {"drafted_tokens", "accepted_tokens"}:
        raise BenchmarkError("speculative counters differ")
    normalized_speculative = {key: None if item is None else int(_portable_number(item, key))
                              for key, item in speculative.items()}
    if any(item is not None and type(speculative[key]) is not int
           for key, item in normalized_speculative.items()):
        raise BenchmarkError("speculative counters must be exact integers or null")
    throughput = value.get("throughput", {})
    throughput_fields = {"prompt_tokens_per_second", "decode_tokens_per_second"}
    if type(throughput) is not dict or set(throughput) - throughput_fields:
        raise BenchmarkError("generation throughput fields differ")
    normalized_throughput = {
        key: _portable_number(throughput.get(key), key) for key in sorted(throughput_fields)}
    return {"text": value["text"], "usage": normalized_usage, "timing": normalized_timing,
            "transport": copy.deepcopy(transport), "speculative": normalized_speculative,
            "throughput": normalized_throughput}


def local_provider_callback(profile, *, timeout_seconds=120):
    """Adapt :mod:`xnet.local_provider` to the benchmark's frozen callback.

    The adapter refuses per-call setting drift.  It performs one request and no
    retry; uncertain transport outcomes remain uncertain rather than being sent
    a second time.
    """
    from .local_provider import LocalProviderProfile, chat_completion
    if type(profile) is not LocalProviderProfile:
        raise BenchmarkError("LocalProviderProfile required")

    def generate(messages, *, max_output_tokens, temperature, seed, **_identity):
        if (max_output_tokens != profile.max_output_tokens
                or float(temperature) != profile.temperature or seed != profile.seed):
            raise BenchmarkError("benchmark settings differ from frozen provider profile")
        value = chat_completion(profile, messages, timeout_seconds=timeout_seconds)
        metrics = value["metrics"]["values"]
        receipt = value["http_receipt"]
        client_seconds = receipt["client_elapsed_ms"] / 1000 if receipt["client_elapsed_ms"] is not None else None
        return {"text": value["candidate_text"],
                "usage": {"input_tokens": metrics["input_tokens"],
                          "output_tokens": metrics["output_tokens"],
                          "total_tokens": metrics["total_tokens"],
                          "cached_input_tokens": metrics["cached_input_tokens"]},
                "timing": {"prompt_seconds": (metrics["prompt_ms"] / 1000
                                                if metrics["prompt_ms"] is not None else None),
                           "decode_seconds": (metrics["decode_ms"] / 1000
                                               if metrics["decode_ms"] is not None else None),
                           "ttft_seconds": (metrics["time_to_first_token_ms"] / 1000
                                             if metrics["time_to_first_token_ms"] is not None else None),
                           "total_seconds": client_seconds},
                "transport": {"request_sha256": receipt["raw_request_body_sha256"],
                              "response_sha256": receipt["raw_response_body_sha256"],
                              "status": receipt["http_status"]},
                "speculative": {"drafted_tokens": metrics["speculative_drafted_tokens"],
                                "accepted_tokens": metrics["speculative_accepted_tokens"]},
                "throughput": {
                    "prompt_tokens_per_second": metrics["prompt_tokens_per_second"],
                    "decode_tokens_per_second": metrics["decode_tokens_per_second"]}}
    return generate


def prepare(root, *, public_suite, hidden_suite_sha256, protocol, corpus, provider_profile,
            environment_receipt=None):
    """Freeze public inputs and the held-out digest. Performs zero model calls."""
    root = Path(root).absolute()
    if root.exists():
        raise FileExistsError(root)
    if type(hidden_suite_sha256) is not str or not _HEX.fullmatch(hidden_suite_sha256):
        raise BenchmarkError("exact hidden-suite SHA256 commitment required")
    public_value, public_raw = _load_json(Path(public_suite))
    protocol_value, protocol_raw = _load_json(Path(protocol))
    corpus_value, corpus_raw = _load_json(Path(corpus))
    profile_value, profile_raw = _load_json(Path(provider_profile))
    tasks = _validate_public_suite(public_value, public_raw)
    protocol_value = _validate_protocol(protocol_value, len(tasks))
    corpus_value = _validate_corpus(corpus_value)
    _validate_provider_profile(profile_value, protocol_value)
    from .local_provider import LocalProviderProfile
    profile_object = LocalProviderProfile.from_mapping(profile_value)
    environment_value = environment_raw = None
    requires_environment = "prompt_cache_policy" in protocol_value["inference"]
    if environment_receipt is not None:
        from .benchmark_environment import validate_environment
        environment_value, environment_raw = _load_json(Path(environment_receipt))
        try:
            validate_environment(environment_value, profile_object)
        except ValueError as exc:
            raise BenchmarkError("invalid frozen benchmark environment") from exc
        if environment_raw != canonical(environment_value) + b"\n":
            raise BenchmarkError("benchmark environment must use canonical UTF-8 JSON encoding")
    if requires_environment and environment_value is None:
        raise BenchmarkError("cold-prompt protocol requires a benchmark environment receipt")
    root.mkdir(parents=True)
    for name in ("cases", "frozen"):
        (root / name).mkdir()
    (root / "public-suite.json").write_bytes(public_raw)
    (root / "protocol.json").write_bytes(protocol_raw)
    (root / "retrieval-corpus.json").write_bytes(corpus_raw)
    (root / "provider-profile.json").write_bytes(profile_raw)
    if environment_raw is not None:
        (root / "environment.json").write_bytes(environment_raw)
    schedule = []
    for index, task in enumerate(tasks):
        for lane in lane_order(index):
            schedule.append({"task_id": task["task_id"], "lane": lane,
                             "case_id": lane + "--" + task["task_id"]})
    sources = [Path(__file__).with_name(name) for name in _SOURCE_FILES]
    manifest = {"schema": SCHEMA, "created_unix_ns": time.time_ns(), "task_count": len(tasks),
                "lanes": list(LANES), "schedule": schedule,
                "public_suite_sha256": sha256(public_raw), "public_tasks_sha256": digest(tasks),
                "hidden_suite_sha256": hidden_suite_sha256,
                "protocol_sha256": sha256(protocol_raw), "corpus_sha256": sha256(corpus_raw),
                "provider_profile_sha256": sha256(profile_raw),
                "environment_receipt_sha256": (sha256(environment_raw)
                                                if environment_raw is not None else None),
                "environment_identity_sha256": (environment_value["environment_sha256"]
                                                 if environment_value is not None else None),
                "cold_prompt_attested": environment_value is not None,
                "source_sha256": {path.name: sha256(path.read_bytes()) for path in sources},
                "model_calls_during_prepare": 0, "hidden_suite_opened": False,
                "candidate_execution": False, "benchmark_claim": _BENCHMARK_CLAIM}
    return _validate_manifest(_atomic_new(root / "manifest.json", manifest))


def _load_run(root):
    root = Path(root).absolute()
    manifest = _validate_manifest(_read_receipt(root / "manifest.json"))
    inputs = {}
    for name, key in (("public-suite.json", "public_suite_sha256"),
                      ("protocol.json", "protocol_sha256"),
                      ("retrieval-corpus.json", "corpus_sha256"),
                      ("provider-profile.json", "provider_profile_sha256")):
        value, raw = _load_json(root / name)
        if sha256(raw) != manifest[key]:
            raise BenchmarkError("frozen input changed: " + name)
        inputs[name] = value
    if manifest["environment_receipt_sha256"] is not None:
        from .benchmark_environment import validate_environment
        from .local_provider import LocalProviderProfile
        environment, raw = _load_json(root / "environment.json")
        if sha256(raw) != manifest["environment_receipt_sha256"]:
            raise BenchmarkError("frozen input changed: environment.json")
        try:
            validate_environment(environment,
                LocalProviderProfile.from_mapping(inputs["provider-profile.json"]))
        except ValueError as exc:
            raise BenchmarkError("frozen benchmark environment differs") from exc
        if environment["environment_sha256"] != manifest["environment_identity_sha256"]:
            raise BenchmarkError("benchmark environment identity differs")
        inputs["environment.json"] = environment
    for name, expected in manifest["source_sha256"].items():
        path = Path(__file__).with_name(name)
        if sha256(path.read_bytes()) != expected:
            raise BenchmarkError("benchmark source changed; use a new run root")
    public_raw = (root / "public-suite.json").read_bytes()
    tasks = _validate_public_suite(inputs["public-suite.json"], public_raw)
    if digest(tasks) != manifest["public_tasks_sha256"]:
        raise BenchmarkError("public tasks changed")
    protocol = _validate_protocol(inputs["protocol.json"], len(tasks))
    _validate_corpus(inputs["retrieval-corpus.json"])
    _validate_provider_profile(inputs["provider-profile.json"], protocol)
    expected_schedule = [{"task_id": task["task_id"], "lane": lane,
                          "case_id": lane + "--" + task["task_id"]}
                         for index, task in enumerate(tasks) for lane in lane_order(index)]
    if manifest["task_count"] != len(tasks) or manifest["schedule"] != expected_schedule:
        raise BenchmarkError("run manifest schedule differs from frozen public tasks")
    return root, manifest, tasks, inputs


def _case_directory(root, lane, task_id):
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", task_id) is None:
        raise BenchmarkError("task ID is not path safe")
    return root / "cases" / lane / task_id


def _attempt_rows(directory):
    rows = []
    for attempt in (1, 2):
        path = directory / ("attempt-" + str(attempt)) / "result.json"
        if path.exists():
            rows.append(_read_receipt(path))
    return rows


def _validate_attempt_receipt(value, *, manifest, task, lane, attempt, base_files,
                              reservation, response):
    fields = {"schema", "manifest_sha256", "reservation_sha256", "response_sha256",
              "case_id", "task_id", "lane", "attempt", "candidate_valid",
              "candidate_execution", "hidden_data_used", "files", "changed_files",
              "bundle_hashes", "no_op", "public_evaluation", "generation",
              "candidate_text_normalization",
              "callback_wall_seconds", "admission_outcome", "admission_seconds",
              "e2e_seconds"}
    _validate_sealed(value, schema="xnet.blind-repair50.attempt.v2", fields=fields,
                     label="attempt result")
    if (value["manifest_sha256"] != manifest["receipt_sha256"]
            or value["reservation_sha256"] != reservation["receipt_sha256"]
            or value["response_sha256"] != response["receipt_sha256"]
            or value["case_id"] != lane + "--" + task["task_id"]
            or value["task_id"] != task["task_id"] or value["lane"] != lane
            or value["attempt"] != attempt or value["candidate_execution"] is not False
            or value["hidden_data_used"] is not False
            or type(value["candidate_valid"]) is not bool or type(value["no_op"]) is not bool):
        raise BenchmarkError("attempt result linkage or invariant differs")
    normalization = value["candidate_text_normalization"]
    if (type(normalization) is not list or len(normalization) > 2
            or any(type(item) is not str or len(item) > 64 for item in normalization)):
        raise BenchmarkError("candidate text normalization evidence differs")
    if (value["generation"] != response["generation"]
            or value["callback_wall_seconds"] != response["callback_wall_seconds"]
            or _normalize_generation(value["generation"]) != value["generation"]):
        raise BenchmarkError("attempt result generation linkage differs")
    admission = _portable_number(value["admission_seconds"], "admission_seconds")
    e2e = _portable_number(value["e2e_seconds"], "e2e_seconds")
    if admission is None or e2e is None or e2e != value["callback_wall_seconds"] + admission:
        raise BenchmarkError("attempt result timing linkage differs")
    if value["admission_outcome"] not in {"admitted", "schema-error", "no-op", "timeout", "error"}:
        raise BenchmarkError("attempt admission outcome differs")
    report = value["public_evaluation"]
    if (type(report) is not dict or report.get("schema_version") != "xnet.swe-repair-evaluation.v1"
            or report.get("visibility") != "public" or type(report.get("resolved")) is not bool
            or type(report.get("passed")) is not int
            or report.get("total") != len(task["public_cases"]) or type(report.get("cases")) is not list):
        raise BenchmarkError("attempt public evaluation differs")
    feedback = public_feedback(report)
    if (feedback["resolved"] != report["resolved"] or feedback["passed"] != report["passed"]
            or feedback["total"] != report["total"]):
        raise BenchmarkError("attempt public evaluation is internally inconsistent")
    if value["candidate_valid"] != (report.get("status") == "evaluated"):
        raise BenchmarkError("candidate admission and evaluation status differ")
    if value["admission_outcome"] == "admitted" and not value["candidate_valid"]:
        raise BenchmarkError("admitted candidate was not evaluated")
    if value["no_op"] != (value["admission_outcome"] == "no-op"):
        raise BenchmarkError("no-op admission outcome differs")
    files = value["files"]
    if files is None:
        if (value["changed_files"] != [] or value["bundle_hashes"] is not None
                or normalization != []):
            raise BenchmarkError("absent candidate carries bundle evidence")
    else:
        if (type(files) is not dict or set(files) != set(task["files"])
                or value["bundle_hashes"] != bundle_hashes(files)
                or value["changed_files"] != sorted(
                    name for name in files if files[name] != base_files[name])):
            raise BenchmarkError("attempt candidate bundle evidence differs")
        try:
            parsed, derived_normalization = _parse_candidate(
                response["generation"]["text"], task, base_files)
        except BenchmarkError as exc:
            raise BenchmarkError("sealed candidate was not produced by its response") from exc
        if parsed != files or derived_normalization != normalization:
            raise BenchmarkError("sealed candidate differs from its response")
    return value


def _validated_attempt_rows(root, manifest, task, lane, inputs):
    directory = _case_directory(root, lane, task["task_id"])
    rows = _attempt_rows(directory)
    if [row.get("attempt") for row in rows] != list(range(1, len(rows) + 1)):
        raise BenchmarkError("attempt sequence is incomplete")
    previous = None
    for attempt, row in enumerate(rows, 1):
        if previous is not None and previous["public_evaluation"]["resolved"]:
            raise BenchmarkError("attempt exists after a resolved public result")
        base_files = (previous["files"] if previous and previous["candidate_valid"]
                      else task["files"])
        feedback = public_feedback(previous["public_evaluation"]) if previous else None
        if previous and previous["no_op"]:
            feedback["host_reason"] = "PATCH_WAS_A_NO_OP: change the implementation"
        messages, context = build_messages(
            task, lane, attempt, base_files, feedback, inputs["retrieval-corpus.json"])
        protocol = inputs["protocol.json"]
        expected_request = {
            "schema": "xnet.blind-repair50.request.v1",
            "manifest_sha256": manifest["receipt_sha256"],
            "case_id": lane + "--" + task["task_id"], "task_id": task["task_id"],
            "lane": lane, "attempt": attempt, "messages": messages,
            "context_evidence": context,
            "max_output_tokens": protocol["inference"]["max_output_tokens"],
            "temperature": protocol["inference"]["temperature"],
            "seed": protocol["inference"]["seed"], "hidden_data_used": False}
        attempt_root = directory / ("attempt-" + str(attempt))
        reservation = _validate_request_receipt(
            _read_receipt(attempt_root / "reservation.json"), expected_request)
        response = _validate_response_receipt(
            _read_receipt(attempt_root / "response.json"), reservation)
        profile = inputs["provider-profile.json"]
        provider_request = {"model": profile["model"], "messages": messages,
            "max_tokens": profile["max_output_tokens"], "temperature": profile["temperature"],
            "seed": profile["seed"], "stream": False}
        if response["generation"]["transport"]["request_sha256"] != sha256(canonical(provider_request)):
            raise BenchmarkError("provider request hash differs from frozen messages/settings")
        previous = _validate_attempt_receipt(
            row, manifest=manifest, task=task, lane=lane, attempt=attempt,
            base_files=base_files, reservation=reservation, response=response)
    return rows


def _run_locked(root, generate: Callable, *, task_ids=None):
    """Run/resume the counterbalanced public exam. Hidden input is impossible here."""
    root, manifest, tasks, inputs = _load_run(root)
    if (root / "frozen" / "choices.json").exists():
        raise BenchmarkError("run is already frozen")
    task_map = {task["task_id"]: task for task in tasks}
    selected = set(task_map) if task_ids is None else set(task_ids)
    if not selected or selected - set(task_map) or (task_ids is not None and len(selected) != len(task_ids)):
        raise BenchmarkError("task selection contains unknown or duplicate IDs")
    protocol = inputs["protocol.json"]
    corpus = inputs["retrieval-corpus.json"]
    max_attempts = protocol["inference"]["max_attempts"]
    completed = []
    for slot in manifest["schedule"]:
        if slot["task_id"] not in selected:
            continue
        task, lane = task_map[slot["task_id"]], slot["lane"]
        directory = _case_directory(root, lane, task["task_id"])
        rows = _validated_attempt_rows(root, manifest, task, lane, inputs)
        for attempt in range(1, max_attempts + 1):
            if rows and rows[-1]["public_evaluation"]["resolved"]:
                break
            if any(row["attempt"] == attempt for row in rows):
                continue
            attempt_root = directory / ("attempt-" + str(attempt))
            reservation_path = attempt_root / "reservation.json"
            response_path = attempt_root / "response.json"
            if response_path.exists() and not reservation_path.exists():
                raise BenchmarkError("generation response exists without its request")
            previous = rows[-1] if rows else None
            base_files = (previous["files"] if previous and previous["candidate_valid"]
                          else task["files"])
            feedback = public_feedback(previous["public_evaluation"]) if previous else None
            if previous and previous["no_op"]:
                feedback["host_reason"] = "PATCH_WAS_A_NO_OP: change the implementation"
            messages, context = build_messages(task, lane, attempt, base_files, feedback, corpus)
            request = {"schema": "xnet.blind-repair50.request.v1", "manifest_sha256": manifest["receipt_sha256"],
                       "case_id": slot["case_id"], "task_id": task["task_id"], "lane": lane,
                       "attempt": attempt, "messages": messages, "context_evidence": context,
                       "max_output_tokens": protocol["inference"]["max_output_tokens"],
                       "temperature": protocol["inference"]["temperature"],
                       "seed": protocol["inference"]["seed"], "hidden_data_used": False}
            if not reservation_path.exists():
                reservation = _validate_request_receipt(
                    _atomic_new(reservation_path, request), request)
                started = time.monotonic()
                returned = _normalize_generation(generate(copy.deepcopy(messages),
                    max_output_tokens=request["max_output_tokens"], temperature=request["temperature"],
                    seed=request["seed"], task_id=task["task_id"], lane=lane, attempt=attempt))
                response = _validate_response_receipt(_atomic_new(response_path, {
                    "schema": "xnet.blind-repair50.response.v1",
                    "reservation_sha256": reservation["receipt_sha256"],
                    "generation": returned, "callback_wall_seconds": time.monotonic() - started}),
                    reservation)
            else:
                reservation = _validate_request_receipt(_read_receipt(reservation_path), request)
                if not response_path.exists():
                    raise PendingGeneration(str(reservation_path))
                response = _validate_response_receipt(_read_receipt(response_path), reservation)
            profile = inputs["provider-profile.json"]
            expected_provider_request = {"model": profile["model"], "messages": messages,
                "max_tokens": profile["max_output_tokens"], "temperature": profile["temperature"],
                "seed": profile["seed"], "stream": False}
            if response["generation"]["transport"]["request_sha256"] != sha256(canonical(expected_provider_request)):
                raise BenchmarkError("provider request hash differs from frozen messages/settings")
            rejection = {"schema_version": "xnet.swe-repair-evaluation.v1", "visibility": "public",
                         "status": "rejected", "resolved": False, "passed": 0,
                         "total": len(task["public_cases"]), "cases": []}
            result = {"schema": "xnet.blind-repair50.attempt.v2", "manifest_sha256": manifest["receipt_sha256"],
                      "reservation_sha256": reservation["receipt_sha256"],
                      "response_sha256": response["receipt_sha256"], "case_id": slot["case_id"],
                      "task_id": task["task_id"], "lane": lane, "attempt": attempt,
                       "candidate_valid": False, "candidate_execution": False, "hidden_data_used": False,
                       "files": None, "changed_files": [], "bundle_hashes": None, "no_op": False,
                       "candidate_text_normalization": [],
                       "public_evaluation": rejection, "generation": response["generation"],
                       "callback_wall_seconds": response["callback_wall_seconds"],
                       "admission_outcome": "schema-error"}
            admission_started = time.monotonic()
            try:
                files, normalization = _parse_candidate(
                    response["generation"]["text"], task, base_files)
                result["admission_outcome"] = "error"
                no_op = is_noop_patch(base_files, files)
                if no_op:
                    result["admission_outcome"] = "no-op"
                    raise BenchmarkError("PATCH_WAS_A_NO_OP")
                report = evaluate_bundle(files, task["entry_file"], task["entry_function"], task["public_cases"],
                    allowed_files=task["files"], import_graph=declared_import_graph(task["files"]), timeout_seconds=3)
                public_feedback(report)
                result["admission_outcome"] = {
                    "evaluated": "admitted", "rejected": "schema-error",
                    "timed-out": "timeout"}.get(report["status"], "error")
                result.update(candidate_valid=report["status"] == "evaluated", files=files,
                              changed_files=sorted(name for name in files if files[name] != base_files[name]),
                              bundle_hashes=bundle_hashes(files), no_op=no_op,
                              candidate_text_normalization=normalization,
                              public_evaluation=report)
            except Exception as exc:
                result["public_evaluation"] = {**rejection,
                    "error": type(exc).__name__ + ": " + str(exc)[:200]}
                result["no_op"] = "PATCH_WAS_A_NO_OP" in str(exc)
            result["admission_seconds"] = time.monotonic() - admission_started
            result["e2e_seconds"] = result["callback_wall_seconds"] + result["admission_seconds"]
            row = _atomic_new(attempt_root / "result.json", result)
            rows.append(row)
        completed.extend(rows)
    return completed


def run(root, generate: Callable, *, task_ids=None):
    """Run under one cross-process writer lease."""
    root = Path(root).absolute()
    with _exclusive_file_lock(root / "benchmark.lock", timeout=3):
        return _run_locked(root, generate, task_ids=task_ids)


def _validate_choices_receipt(value, manifest, tasks):
    fields = {"schema", "manifest_sha256", "choices", "choice_count",
              "hidden_data_used", "model_calls"}
    _validate_sealed(value, schema="xnet.blind-repair50.choices.v1", fields=fields,
                     label="frozen choices")
    if (value["manifest_sha256"] != manifest["receipt_sha256"]
            or value["hidden_data_used"] is not False or value["model_calls"] != 0):
        raise BenchmarkError("frozen choices linkage or invariant differs")
    expected = [(task["task_id"], lane) for task in tasks for lane in LANES]
    choices = value["choices"]
    if (type(choices) is not list or value["choice_count"] != len(expected)
            or len(choices) != len(expected)):
        raise BenchmarkError("frozen choices are incomplete")
    for choice, identity in zip(choices, expected):
        _exact_object(choice, {"task_id", "lane", "first_attempt_receipt_sha256",
                               "selected_attempt", "selected_receipt_sha256",
                               "attempt_receipt_sha256"}, "frozen choice")
        if (choice["task_id"], choice["lane"]) != identity:
            raise BenchmarkError("frozen choice order or identity differs")
        attempts = choice["attempt_receipt_sha256"]
        if (type(attempts) is not list or not 1 <= len(attempts) <= 2
                or len(set(attempts)) != len(attempts)):
            raise BenchmarkError("frozen choice attempt list differs")
        for item in attempts:
            _hash_pin(item, "attempt receipt")
        if choice["first_attempt_receipt_sha256"] != attempts[0]:
            raise BenchmarkError("frozen choice first attempt linkage differs")
        selected_attempt = choice["selected_attempt"]
        selected_receipt = choice["selected_receipt_sha256"]
        if selected_attempt is None:
            if selected_receipt is not None:
                raise BenchmarkError("frozen choice selection linkage differs")
        elif (type(selected_attempt) is not int or selected_attempt not in (1, 2)
              or selected_attempt > len(attempts)
              or not _HEX.fullmatch(selected_receipt or "")
              or selected_receipt != attempts[selected_attempt - 1]):
            raise BenchmarkError("frozen choice selection linkage differs")
    return value


def _validate_choice_attempt_links(root, manifest, tasks, inputs, choices):
    task_map = {task["task_id"]: task for task in tasks}
    result = {}
    for choice in choices["choices"]:
        identity = (choice["task_id"], choice["lane"])
        rows = _validated_attempt_rows(
            root, manifest, task_map[choice["task_id"]], choice["lane"], inputs)
        if choice["attempt_receipt_sha256"] != [row["receipt_sha256"] for row in rows]:
            raise BenchmarkError("attempt receipts changed after freeze")
        result[identity] = rows
    return result


def _freeze_locked(root):
    """Select candidates from public evidence only and seal the choice set once."""
    root, manifest, tasks, inputs = _load_run(root)
    path = root / "frozen" / "choices.json"
    if path.exists():
        choices = _validate_choices_receipt(_read_receipt(path), manifest, tasks)
        _validate_choice_attempt_links(root, manifest, tasks, inputs, choices)
        return choices
    choices = []
    for task in tasks:
        for lane in LANES:
            rows = _validated_attempt_rows(root, manifest, task, lane, inputs)
            if not rows or (not rows[-1]["public_evaluation"]["resolved"] and len(rows) < 2):
                raise BenchmarkError("unfinished public lane: " + lane + " / " + task["task_id"])
            valid = [row for row in rows if row["candidate_valid"]]
            selected = max(valid, key=lambda row: (row["public_evaluation"]["passed"], row["attempt"])) if valid else None
            choices.append({"task_id": task["task_id"], "lane": lane,
                            "first_attempt_receipt_sha256": rows[0]["receipt_sha256"],
                            "selected_attempt": selected["attempt"] if selected else None,
                            "selected_receipt_sha256": selected["receipt_sha256"] if selected else None,
                            "attempt_receipt_sha256": [row["receipt_sha256"] for row in rows]})
    return _validate_choices_receipt(_atomic_new(path, {"schema": "xnet.blind-repair50.choices.v1",
        "manifest_sha256": manifest["receipt_sha256"], "choices": choices,
        "choice_count": len(choices), "hidden_data_used": False, "model_calls": 0}),
        manifest, tasks)


def freeze(root):
    """Freeze under the same cross-process writer lease as inference."""
    root = Path(root).absolute()
    with _exclusive_file_lock(root / "benchmark.lock", timeout=3):
        return _freeze_locked(root)


def _hidden_cases(hidden_value, task_ids):
    rows = hidden_value.get("tasks") if type(hidden_value) is dict else None
    if type(rows) is not list or len(rows) != len(task_ids):
        raise BenchmarkError("held-out suite task count differs")
    result = {}
    for row in rows:
        if type(row) is not dict or set(row) != {"task_id", "hidden_cases"} or row["task_id"] in result:
            raise BenchmarkError("invalid held-out task row")
        cases = row["hidden_cases"]
        if (type(cases) is not list or len(cases) != 4
                or sum(case.get("case_type") == "F2P" for case in cases) != 2
                or sum(case.get("case_type") == "P2P" for case in cases) != 2):
            raise BenchmarkError("held-out cases require balanced F2P/P2P")
        if any(type(case) is not dict or case.get("hidden") is not True for case in cases):
            raise BenchmarkError("held-out visibility marker differs")
        result[row["task_id"]] = cases
    if set(result) != set(task_ids):
        raise BenchmarkError("held-out task IDs differ")
    return result


def _case_type_counts(report, expected_cases):
    """Count passed and failed F2P/P2P cases against a known denominator."""
    rows = report.get("cases", []) if type(report) is dict else []
    result = {}
    for case_type in ("F2P", "P2P"):
        total = sum(case.get("case_type") == case_type for case in expected_cases)
        passed = sum(row.get("case_type") == case_type and row.get("passed") is True
                     for row in rows if type(row) is dict)
        result[case_type] = {"passed": passed, "failed": total - passed, "total": total}
    return result


def _validate_score(value, task, *, label):
    _exact_object(value, {"resolved", "public_resolved", "hidden_resolved",
                          "hidden_report", "p2p_preserved", "case_counts"}, label)
    for name in ("resolved", "public_resolved", "hidden_resolved", "p2p_preserved"):
        if type(value[name]) is not bool:
            raise BenchmarkError(label + " boolean fields differ")
    if value["resolved"] != (value["public_resolved"] and value["hidden_resolved"]):
        raise BenchmarkError(label + " resolution linkage differs")
    counts = _exact_object(value["case_counts"], {"public", "hidden"}, label + " case counts")
    expected_totals = {"public": {kind: sum(case["case_type"] == kind for case in task["public_cases"])
                                  for kind in ("F2P", "P2P")},
                       "hidden": {"F2P": 2, "P2P": 2}}
    for visibility in ("public", "hidden"):
        section = _exact_object(counts[visibility], {"F2P", "P2P"}, label + " " + visibility)
        for case_type in ("F2P", "P2P"):
            row = _exact_object(section[case_type], {"passed", "failed", "total"},
                                label + " case count")
            if (any(type(row[name]) is not int or row[name] < 0
                    for name in ("passed", "failed", "total"))
                    or row["passed"] + row["failed"] != row["total"]
                    or row["total"] != expected_totals[visibility][case_type]):
                raise BenchmarkError(label + " case count differs")
    report = value["hidden_report"]
    if report is None:
        if value["hidden_resolved"] or value["p2p_preserved"]:
            raise BenchmarkError(label + " hidden report linkage differs")
    elif (type(report) is not dict
          or report.get("schema_version") != "xnet.swe-repair-evaluation.v1"
          or report.get("visibility") != "hidden"
          or type(report.get("resolved")) is not bool
          or report["resolved"] != value["hidden_resolved"]):
        raise BenchmarkError(label + " hidden report differs")
    return value


def _validate_grade_receipt(value, manifest, choices, tasks, hidden_sha256):
    fields = {"schema", "manifest_sha256", "choices_sha256", "hidden_suite_sha256",
              "model_calls", "candidate_execution", "scores", "benchmark_claim"}
    _validate_sealed(value, schema="xnet.blind-repair50.grade.v1", fields=fields,
                     label="grade record")
    if (value["manifest_sha256"] != manifest["receipt_sha256"]
            or value["choices_sha256"] != choices["receipt_sha256"]
            or value["hidden_suite_sha256"] != hidden_sha256
            or value["model_calls"] != 0 or value["candidate_execution"] is not False
            or value["benchmark_claim"] != _BENCHMARK_CLAIM):
        raise BenchmarkError("grade record linkage or invariant differs")
    task_map = {task["task_id"]: task for task in tasks}
    scores = value["scores"]
    if type(scores) is not list or len(scores) != len(choices["choices"]):
        raise BenchmarkError("grade record is incomplete")
    for score, choice in zip(scores, choices["choices"]):
        _exact_object(score, {"task_id", "lane", "first", "final", "first_attempt",
                              "selected_attempt"}, "grade score")
        if ((score["task_id"], score["lane"]) != (choice["task_id"], choice["lane"])
                or score["first_attempt"] != 1
                or score["selected_attempt"] != choice["selected_attempt"]):
            raise BenchmarkError("grade score selection linkage differs")
        task = task_map[score["task_id"]]
        _validate_score(score["first"], task, label="first-attempt grade")
        _validate_score(score["final"], task, label="selected grade")
    return value


def _grade_locked(root, hidden_suite):
    """Open committed held-out cases after freeze. Performs zero model calls."""
    root, manifest, tasks, inputs = _load_run(root)
    choices = _validate_choices_receipt(
        _read_receipt(root / "frozen" / "choices.json"), manifest, tasks)
    case_rows = _validate_choice_attempt_links(root, manifest, tasks, inputs, choices)
    path = root / "frozen" / "grade.json"
    hidden_value, hidden_raw = _load_json(Path(hidden_suite))
    if sha256(hidden_raw) != manifest["hidden_suite_sha256"]:
        raise BenchmarkError("held-out suite differs from precommitted SHA256")
    if path.exists():
        return _validate_grade_receipt(_read_receipt(path), manifest, choices, tasks,
                                       sha256(hidden_raw))
    task_map = {task["task_id"]: task for task in tasks}
    hidden = _hidden_cases(hidden_value, task_map)
    scores = []
    for choice in choices["choices"]:
        task = task_map[choice["task_id"]]
        rows = case_rows[(choice["task_id"], choice["lane"])]
        first = rows[0]
        selected = next((row for row in rows if row["receipt_sha256"] == choice["selected_receipt_sha256"]), None)
        if choice["selected_receipt_sha256"] is not None and selected is None:
            raise BenchmarkError("selected candidate changed after freeze")

        def score(row):
            public_counts = _case_type_counts(
                row["public_evaluation"] if row is not None else None, task["public_cases"])
            hidden_counts = _case_type_counts(None, hidden[task["task_id"]])
            if row is None or not row["candidate_valid"]:
                return {"resolved": False, "public_resolved": False, "hidden_resolved": False,
                        "hidden_report": None, "p2p_preserved": False,
                        "case_counts": {"public": public_counts, "hidden": hidden_counts}}
            report = evaluate_bundle(row["files"], task["entry_file"], task["entry_function"], hidden[task["task_id"]],
                allowed_files=task["files"], import_graph=declared_import_graph(task["files"]), timeout_seconds=3)
            p2p = [case for case in report["cases"] if case["case_type"] == "P2P"]
            hidden_counts = _case_type_counts(report, hidden[task["task_id"]])
            return {"resolved": bool(row["public_evaluation"]["resolved"] and report["resolved"]),
                    "public_resolved": bool(row["public_evaluation"]["resolved"]),
                    "hidden_resolved": bool(report["resolved"]), "hidden_report": report,
                    "p2p_preserved": bool(p2p and all(case["passed"] for case in p2p)),
                    "case_counts": {"public": public_counts, "hidden": hidden_counts}}
        scores.append({"task_id": task["task_id"], "lane": choice["lane"],
                       "first": score(first), "final": score(selected),
                       "first_attempt": first["attempt"],
                       "selected_attempt": choice["selected_attempt"]})
    return _validate_grade_receipt(_atomic_new(path, {"schema": "xnet.blind-repair50.grade.v1",
        "manifest_sha256": manifest["receipt_sha256"], "choices_sha256": choices["receipt_sha256"],
        "hidden_suite_sha256": sha256(hidden_raw), "model_calls": 0,
        "candidate_execution": False, "scores": scores,
        "benchmark_claim": _BENCHMARK_CLAIM}), manifest, choices, tasks, sha256(hidden_raw))


def grade(root, hidden_suite):
    """Grade under the run writer lease after the public freeze."""
    root = Path(root).absolute()
    with _exclusive_file_lock(root / "benchmark.lock", timeout=3):
        return _grade_locked(root, hidden_suite)


def _percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def _metric_stats(values, population):
    """Describe observed numeric values without turning unknowns into zeroes."""
    observed = [value for value in values if value is not None]
    return {"known_calls": len(observed), "unknown_calls": population - len(observed),
            "total": sum(observed) if observed else None,
            "mean": statistics.fmean(observed) if observed else None,
            "median": statistics.median(observed) if observed else None,
            "p95": _percentile(observed, .95)}


def _aggregate_case_counts(grades, phase):
    result = {
        visibility: {case_type: {"passed": 0, "failed": 0, "total": 0}
                     for case_type in ("F2P", "P2P")}
        for visibility in ("public", "hidden")}
    for grade_row in grades:
        counts = grade_row[phase]["case_counts"]
        for visibility in result:
            for case_type in result[visibility]:
                for field in ("passed", "failed", "total"):
                    result[visibility][case_type][field] += counts[visibility][case_type][field]
    return result


def _validate_release_pins(value):
    _exact_object(value, {"provider_profile_sha256", "model", "model_sha256",
                          "runtime_sha256", "environment_identity_sha256",
                          "cold_prompt_attested", "source_sha256"}, "release pin")
    _hash_pin(value["provider_profile_sha256"], "provider_profile_sha256")
    _hash_pin(value["model_sha256"], "model_sha256")
    _hash_pin(value["runtime_sha256"], "runtime_sha256")
    if value["environment_identity_sha256"] is not None:
        _hash_pin(value["environment_identity_sha256"], "environment_identity_sha256")
    if (type(value["cold_prompt_attested"]) is not bool
            or value["cold_prompt_attested"]
               != (value["environment_identity_sha256"] is not None)):
        raise BenchmarkError("release environment pin differs")
    if (type(value["model"]) is not str or not value["model"]
            or len(value["model"].encode("utf-8")) > 256
            or any(ord(character) < 32 for character in value["model"])):
        raise BenchmarkError("release model label differs")
    sources = _exact_object(value["source_sha256"], _SOURCE_FILES, "release source pin")
    for name, item in sources.items():
        _hash_pin(item, "release source pin " + name)
    return value


def _validate_summary_receipt(value, *, manifest=None, grade_record=None):
    fields = {"schema", "manifest_sha256", "grade_sha256", "task_count", "release_pins",
              "lanes", "paired", "full_to_raw_total_token_ratio", "success_checks",
              "leakage_violations", "initial_gate_passed",
              "confirmatory_repetition_required", "benchmark_claim"}
    _validate_sealed(value, schema="xnet.blind-repair50.summary.v1", fields=fields,
                     label="benchmark summary")
    _hash_pin(value["manifest_sha256"], "summary manifest_sha256")
    _hash_pin(value["grade_sha256"], "summary grade_sha256")
    task_count = _exact_int(value["task_count"], "summary task_count", minimum=1)
    pins = _validate_release_pins(value["release_pins"])
    if manifest is not None and (value["manifest_sha256"] != manifest["receipt_sha256"]
            or task_count != manifest["task_count"]
            or pins["provider_profile_sha256"] != manifest["provider_profile_sha256"]
            or pins["environment_identity_sha256"] != manifest["environment_identity_sha256"]
            or pins["cold_prompt_attested"] != manifest["cold_prompt_attested"]
            or pins["source_sha256"] != manifest["source_sha256"]):
        raise BenchmarkError("benchmark summary manifest linkage differs")
    if grade_record is not None and value["grade_sha256"] != grade_record["receipt_sha256"]:
        raise BenchmarkError("benchmark summary grade linkage differs")
    if (value["confirmatory_repetition_required"] is not True
            or value["benchmark_claim"] != _BENCHMARK_CLAIM
            or type(value["leakage_violations"]) is not int
            or value["leakage_violations"] < 0):
        raise BenchmarkError("benchmark summary invariant differs")
    lanes = _exact_object(value["lanes"], LANES, "summary lanes")
    lane_fields = {"denominator", "first_joint_solves", "final_joint_solves",
        "p2p_preserved_tasks", "case_counts", "calls", "retries", "invalid_candidates",
        "no_op_candidates", "outcome_counts", "observed_tokens", "known_token_counts",
        "unknown_token_counts", "timing", "median_generation_seconds",
        "p95_generation_seconds", "total_generation_seconds", "median_callback_seconds",
        "p95_callback_seconds", "total_callback_seconds", "median_admission_seconds",
        "p95_admission_seconds", "total_admission_seconds", "median_e2e_seconds",
        "p95_e2e_seconds", "total_e2e_seconds", "seconds_per_joint_solve",
        "tokens_per_joint_solve", "retrieved_cards", "retrieved_bytes", "retrieval",
        "throughput", "speculative"}
    token_fields = {"input_tokens", "output_tokens", "total_tokens", "cached_input_tokens"}
    for lane in LANES:
        row = _exact_object(lanes[lane], lane_fields, "lane summary")
        if (row["denominator"] != task_count
                or any(type(row[name]) is not int or not 0 <= row[name] <= task_count
                       for name in ("first_joint_solves", "final_joint_solves",
                                    "p2p_preserved_tasks"))
                or type(row["calls"]) is not int or not task_count <= row["calls"] <= task_count * 2
                or type(row["retries"]) is not int or row["retries"] != row["calls"] - task_count):
            raise BenchmarkError("lane summary completeness differs")
        observed = _exact_object(row["observed_tokens"], token_fields, "observed token summary")
        known = _exact_object(row["known_token_counts"], token_fields, "known token summary")
        unknown = _exact_object(row["unknown_token_counts"], token_fields, "unknown token summary")
        for name in token_fields:
            if (type(known[name]) is not int or type(unknown[name]) is not int
                    or known[name] + unknown[name] != row["calls"]
                    or (known[name] == 0) != (observed[name] is None)):
                raise BenchmarkError("lane token coverage differs")
    paired = _exact_object(value["paired"], {"full_vs_raw", "full_vs_retrieval"},
                           "paired summary")
    for name, row in paired.items():
        _exact_object(row, {"full_only", "other_only", "both_solved", "neither_solved", "net"},
                      "paired comparison")
        if (any(type(row[field]) is not int or row[field] < 0
                for field in ("full_only", "other_only", "both_solved", "neither_solved"))
                or sum(row[field] for field in
                       ("full_only", "other_only", "both_solved", "neither_solved")) != task_count
                or row["net"] != row["full_only"] - row["other_only"]):
            raise BenchmarkError("paired comparison differs")
    checks = value["success_checks"]
    expected_checks = {"full_minus_raw", "full_minus_retrieval", "p2p_preservation",
                       "candidate_execution", "hidden_or_retrieval_leakage",
                       "telemetry_complete", "median_time", "token_ratio"}
    _exact_object(checks, expected_checks, "summary success checks")
    if any(type(item) is not bool for item in checks.values()) or value["initial_gate_passed"] is not all(checks.values()):
        raise BenchmarkError("summary gate result differs")
    ratio = _portable_number(value["full_to_raw_total_token_ratio"],
                             "full_to_raw_total_token_ratio")
    if ratio is not None and not math.isfinite(ratio):
        raise BenchmarkError("summary token ratio differs")
    return value


def _summarize_locked(root):
    """Aggregate sealed grades and observed costs without rerunning inference."""
    root, manifest, tasks, inputs = _load_run(root)
    choices = _validate_choices_receipt(
        _read_receipt(root / "frozen" / "choices.json"), manifest, tasks)
    grade_record = _validate_grade_receipt(
        _read_receipt(root / "frozen" / "grade.json"), manifest, choices, tasks,
        manifest["hidden_suite_sha256"])
    case_rows = _validate_choice_attempt_links(root, manifest, tasks, inputs, choices)
    by_lane = {}
    for lane in LANES:
        grades = [row for row in grade_record["scores"] if row["lane"] == lane]
        attempts = [attempt for task in tasks
                    for attempt in case_rows[(task["task_id"], lane)]]
        reservations = [_read_receipt(_case_directory(root, lane, row["task_id"]) /
                        ("attempt-" + str(row["attempt"])) / "reservation.json")
                        for row in attempts]
        population = len(attempts)
        token_keys = ("input_tokens", "output_tokens", "total_tokens", "cached_input_tokens")
        token_values = {key: [row["generation"]["usage"].get(key) for row in attempts]
                        for key in token_keys}
        known = {key: sum(value is not None for value in values)
                 for key, values in token_values.items()}
        unknown = {key: population - count for key, count in known.items()}
        totals = {key: (sum(value for value in values if value is not None)
                        if known[key] else None)
                  for key, values in token_values.items()}
        provider_timing = _metric_stats(
            [row["generation"]["timing"]["total_seconds"] for row in attempts], population)
        callback_timing = _metric_stats(
            [row.get("callback_wall_seconds") for row in attempts], population)
        admission_timing = _metric_stats(
            [row.get("admission_seconds") for row in attempts], population)
        e2e_timing = _metric_stats([row.get("e2e_seconds") for row in attempts], population)
        timing = {"provider_generation_seconds": provider_timing,
                  "callback_seconds": callback_timing,
                  "admission_seconds": admission_timing,
                  "e2e_seconds": e2e_timing}
        outcome_names = {"schema-error": "schema_errors", "no-op": "no_ops",
                         "timeout": "timeouts", "error": "errors"}
        outcome_counts = {name: sum(row.get("admission_outcome") == outcome
                                    for row in attempts)
                          for outcome, name in outcome_names.items()}
        outcome_counts.update({"abstentions": None,
                               "known_calls": sum(row.get("admission_outcome") is not None
                                                  for row in attempts),
                               "unknown_calls": sum(row.get("admission_outcome") is None
                                                    for row in attempts),
                               "unknown_metrics": ["abstentions"]})
        retrieval = {
            "card_count": sum(len(row["context_evidence"]["cards"])
                              for row in reservations),
            "selected_card_bytes": sum(row["context_evidence"]["selected_card_bytes"]
                                       for row in reservations),
            "capsule_bytes": sum(card["capsule_bytes"] for row in reservations
                                 for card in row["context_evidence"]["cards"]),
            "verbose_card_bytes": sum(row["context_evidence"]["verbose_card_bytes"]
                                      for row in reservations),
        }
        throughput = {key: _metric_stats([
            row["generation"].get("throughput", {}).get(key) for row in attempts], population)
            for key in ("prompt_tokens_per_second", "decode_tokens_per_second")}
        speculative_keys = ("drafted_tokens", "accepted_tokens")
        speculative_values = {key: [row["generation"]["speculative"][key]
                                    for row in attempts] for key in speculative_keys}
        speculative_known = {key: sum(value is not None for value in values)
                             for key, values in speculative_values.items()}
        speculative_totals = {
            key: (sum(value for value in values if value is not None)
                  if speculative_known[key] else None)
            for key, values in speculative_values.items()}
        speculative_complete = all(speculative_known[key] == population
                                   for key in speculative_keys)
        drafted = speculative_totals["drafted_tokens"]
        speculative = {
            "observed_tokens": speculative_totals,
            "known_counts": speculative_known,
            "unknown_counts": {key: population - count
                               for key, count in speculative_known.items()},
            "acceptance_rate": (speculative_totals["accepted_tokens"] / drafted
                                if speculative_complete and drafted else None),
        }
        final_solves = sum(row["final"]["resolved"] for row in grades)
        by_lane[lane] = {"denominator": len(grades),
                         "first_joint_solves": sum(row["first"]["resolved"] for row in grades),
                         "final_joint_solves": final_solves,
                         "p2p_preserved_tasks": sum(row["final"]["p2p_preserved"] for row in grades),
                         "case_counts": {"first": _aggregate_case_counts(grades, "first"),
                                         "final": _aggregate_case_counts(grades, "final")},
                         "calls": population, "retries": sum(row["attempt"] == 2 for row in attempts),
                         "invalid_candidates": sum(not row["candidate_valid"] for row in attempts),
                         "no_op_candidates": sum(row["no_op"] for row in attempts),
                         "outcome_counts": outcome_counts,
                         "observed_tokens": totals, "known_token_counts": known,
                         "unknown_token_counts": unknown,
                         "timing": timing,
                         "median_generation_seconds": provider_timing["median"],
                         "p95_generation_seconds": provider_timing["p95"],
                         "total_generation_seconds": provider_timing["total"],
                         "median_callback_seconds": callback_timing["median"],
                         "p95_callback_seconds": callback_timing["p95"],
                         "total_callback_seconds": callback_timing["total"],
                         "median_admission_seconds": admission_timing["median"],
                         "p95_admission_seconds": admission_timing["p95"],
                         "total_admission_seconds": admission_timing["total"],
                         "median_e2e_seconds": e2e_timing["median"],
                         "p95_e2e_seconds": e2e_timing["p95"],
                         "total_e2e_seconds": e2e_timing["total"],
                         "seconds_per_joint_solve": (e2e_timing["total"] / final_solves
                             if final_solves and e2e_timing["known_calls"] == population else None),
                         "tokens_per_joint_solve": (totals["total_tokens"] / final_solves
                             if final_solves and known["total_tokens"] == population else None),
                         "retrieved_cards": retrieval["card_count"],
                         "retrieved_bytes": retrieval["selected_card_bytes"],
                         "retrieval": retrieval, "throughput": throughput,
                         "speculative": speculative}
    paired = {}
    grade_map = {(row["task_id"], row["lane"]): row["final"]["resolved"] for row in grade_record["scores"]}
    for other in ("raw", "retrieval"):
        wins = losses = ties_solved = ties_failed = 0
        for task in tasks:
            full = grade_map[(task["task_id"], "full-xnet")]
            baseline = grade_map[(task["task_id"], other)]
            if full and not baseline: wins += 1
            elif baseline and not full: losses += 1
            elif full: ties_solved += 1
            else: ties_failed += 1
        paired["full_vs_" + other] = {"full_only": wins, "other_only": losses,
            "both_solved": ties_solved, "neither_solved": ties_failed, "net": wins - losses}
    gate = inputs["protocol.json"]["success_gate"]
    full, raw, retrieval = by_lane["full-xnet"], by_lane["raw"], by_lane["retrieval"]
    telemetry_complete = all(
        by_lane[lane]["known_token_counts"]["total_tokens"] == by_lane[lane]["calls"]
        and len([row for task in tasks for row in case_rows[(task["task_id"], lane)]
            if row["generation"]["timing"]["total_seconds"] is not None]) == by_lane[lane]["calls"]
        for lane in LANES)
    token_ratio = (full["observed_tokens"]["total_tokens"] / raw["observed_tokens"]["total_tokens"]
                   if telemetry_complete and raw["observed_tokens"]["total_tokens"] else None)
    leakage_violations = 0
    for lane in LANES:
        for task in tasks:
            for row in case_rows[(task["task_id"], lane)]:
                reservation = _read_receipt(_case_directory(root, lane, task["task_id"]) /
                    ("attempt-" + str(row["attempt"])) / "reservation.json")
                serialized = canonical(reservation["messages"]).lower()
                if (reservation.get("hidden_data_used") is not False
                        or any(marker in serialized for marker in
                               (b'"hidden_cases"', b'"gold_patch"', b'"repaired_source"', b'"reference_patch"'))):
                    leakage_violations += 1
    checks = {
        "full_minus_raw": full["final_joint_solves"] - raw["final_joint_solves"] >= gate["full_minus_raw_minimum_solves"],
        "full_minus_retrieval": full["final_joint_solves"] - retrieval["final_joint_solves"] >= gate["full_minus_retrieval_minimum_solves"],
        "p2p_preservation": full["p2p_preserved_tasks"] >= gate["p2p_preservation_minimum_tasks"],
        "candidate_execution": manifest["candidate_execution"] is False and grade_record["candidate_execution"] is False,
        "hidden_or_retrieval_leakage": leakage_violations <= gate["maximum_hidden_or_retrieval_leaks"],
        "telemetry_complete": telemetry_complete,
        "median_time": full["median_generation_seconds"] is not None and
            full["median_generation_seconds"] <= gate["full_lane_median_task_seconds_maximum"],
        "token_ratio": token_ratio is not None and token_ratio <= gate["full_to_raw_total_token_ratio_maximum"]}
    profile = inputs["provider-profile.json"]
    release_pins = {"provider_profile_sha256": manifest["provider_profile_sha256"],
                    "model": profile["model"], "model_sha256": profile["model_sha256"],
                    "runtime_sha256": profile["runtime_sha256"],
                    "environment_identity_sha256": manifest["environment_identity_sha256"],
                    "cold_prompt_attested": manifest["cold_prompt_attested"],
                    "source_sha256": copy.deepcopy(manifest["source_sha256"])}
    summary = {"schema": "xnet.blind-repair50.summary.v1", "manifest_sha256": manifest["receipt_sha256"],
               "grade_sha256": grade_record["receipt_sha256"], "task_count": len(tasks),
               "release_pins": release_pins, "lanes": by_lane, "paired": paired,
               "full_to_raw_total_token_ratio": token_ratio, "success_checks": checks,
               "leakage_violations": leakage_violations,
               "initial_gate_passed": all(checks.values()),
               "confirmatory_repetition_required": True,
               "benchmark_claim": _BENCHMARK_CLAIM}
    path = root / "frozen" / "summary.json"
    if path.exists():
        current = _validate_summary_receipt(
            _read_receipt(path), manifest=manifest, grade_record=grade_record)
        if {k: v for k, v in current.items() if k != "receipt_sha256"} != summary:
            raise BenchmarkError("existing summary differs")
        return current
    return _validate_summary_receipt(
        _atomic_new(path, summary), manifest=manifest, grade_record=grade_record)


def summarize(root):
    """Summarize under the writer lease so receipts cannot change mid-read."""
    root = Path(root).absolute()
    with _exclusive_file_lock(root / "benchmark.lock", timeout=3):
        return _summarize_locked(root)


def release_note(summary, *, model_label, source_commit, model_sha256, runtime_sha256):
    """Render a factual Markdown block only from a sealed summary."""
    summary = _validate_summary_receipt(summary)
    pins = summary["release_pins"]
    _hash_pin(model_sha256, "model_sha256")
    _hash_pin(runtime_sha256, "runtime_sha256")
    if type(source_commit) is not str or _COMMIT.fullmatch(source_commit) is None:
        raise BenchmarkError("source_commit must be a lowercase 40-character Git commit")
    if (model_label != pins["model"] or model_sha256 != pins["model_sha256"]
            or runtime_sha256 != pins["runtime_sha256"]):
        raise BenchmarkError("release identity differs from the frozen provider profile")
    raw, rag, full = (summary["lanes"][name] for name in LANES)
    denominator = summary["task_count"]
    source_pin_sha256 = digest(pins["source_sha256"])
    verdict = "passed the preregistered initial gate" if summary["initial_gate_passed"] else "did not pass every preregistered initial gate"
    return ("## XNET Blind Repair 50\n\n"
        f"On the custom frozen XNET Blind Repair 50 set, {model_label} with full XNET solved "
        f"**{full['final_joint_solves']}/{denominator}**, compared with **{raw['final_joint_solves']}/{denominator}** raw and "
        f"**{rag['final_joint_solves']}/{denominator}** with retrieval only. The run {verdict}. "
        "This is a custom SWE-style benchmark, not an official SWE-bench result.\n\n"
        f"- Source commit (caller-attested): `{source_commit}`\n"
        f"- Source-pin manifest SHA-256: `{source_pin_sha256}`\n"
        f"- Model SHA-256: `{model_sha256}`\n"
        f"- Runtime SHA-256: `{runtime_sha256}`\n"
        f"- Cold-prompt environment attested: `{pins['cold_prompt_attested']}`; environment SHA-256: `{pins['environment_identity_sha256']}`\n"
        f"- Summary receipt SHA-256: `{summary['receipt_sha256']}`\n"
        f"- Raw tokens: `{raw['observed_tokens']['total_tokens']}`; full-XNET tokens: `{full['observed_tokens']['total_tokens']}`\n"
        f"- Raw median generation: `{raw['median_generation_seconds']}` s; full-XNET: `{full['median_generation_seconds']}` s\n"
        f"- Paired full-vs-raw net: `{summary['paired']['full_vs_raw']['net']}` tasks\n"
        "- Candidate code was interpreted by the bounded evaluator and never imported or executed by the host.\n"
        "- Held-out cases were opened only after all public candidates were frozen.\n")
