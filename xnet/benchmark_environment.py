"""Capture a sanitized llama.cpp benchmark environment receipt.

The receipt binds the model/runtime/profile, cache-isolation controls and
performance controls used for a cold-prompt comparison. It deliberately
omits local filesystem paths, usernames, device serials and credentials.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import re
from typing import Any, Mapping

from .local_provider import LocalProviderProfile
from .protocol import canonical, digest, sha256


SCHEMA = "xnet.blind-repair50.environment.v2"
MAX_ENVIRONMENT_INPUT_BYTES = 1024 * 1024
MAX_SERVER_CONTROL_BYTES = 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")
_CONTROL_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}\Z")


class BenchmarkEnvironmentError(ValueError):
    pass


def _read_bounded(path: str | Path, *, maximum: int, label: str) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    if not 1 <= len(raw) <= maximum:
        raise BenchmarkEnvironmentError(label + " exceeds bound")
    return raw


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkEnvironmentError("environment input contains a duplicate key")
        result[key] = value
    return result


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise BenchmarkEnvironmentError("environment input contains a non-finite number")
    return value


def _load_object(path: str | Path,
                 maximum: int = MAX_ENVIRONMENT_INPUT_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded(path, maximum=maximum, label="environment input")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=_finite_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                BenchmarkEnvironmentError("non-finite JSON number: " + token)),
        )
    except BenchmarkEnvironmentError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise BenchmarkEnvironmentError("environment input must be UTF-8 JSON") from exc
    if type(value) is not dict:
        raise BenchmarkEnvironmentError("environment input must be an object")
    return value, raw


def _hash(value: Any, name: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise BenchmarkEnvironmentError(name + " must be a lowercase SHA-256")
    return value


def _bounded_text(value: Any, name: str, maximum: int = 256) -> str:
    if type(value) is not str or not value or any(ord(character) < 32 for character in value):
        raise BenchmarkEnvironmentError(name + " is invalid")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise BenchmarkEnvironmentError(name + " is invalid") from exc
    if size > maximum:
        raise BenchmarkEnvironmentError(name + " is invalid")
    return value


def _runtime_profile(value: Any) -> str:
    if type(value) is not str or _RUNTIME_PROFILE.fullmatch(value) is None:
        raise BenchmarkEnvironmentError("runtime profile must be a bounded identifier")
    return value


def _hardware(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"system", "cpu", "logical_processors", "memory_bytes", "gpu", "backend", "os"}
    if type(value) is not dict or set(value) != fields:
        raise BenchmarkEnvironmentError("hardware fields differ from schema")
    for name in ("system", "cpu", "gpu", "backend", "os"):
        _bounded_text(value[name], "hardware " + name)
    for name in ("logical_processors", "memory_bytes"):
        if (type(value[name]) is not int
                or not 1 <= value[name] <= 2**63 - 1):
            raise BenchmarkEnvironmentError("hardware " + name + " is invalid")
    return dict(value)


def _inference_controls(value: Any, profile: LocalProviderProfile) -> dict[str, Any]:
    expected = {
        "context_tokens": profile.context_tokens,
        "parallel_slots": 1,
        "reasoning_budget": 0,
        "prompt_cache": "disabled",
        "cache_ram_mib": 0,
        "cache_idle_slots": False,
        "slot_prompt_similarity": 0.0,
        "cross_task_kv_reuse": False,
    }
    if type(value) is not dict or set(value) != set(expected):
        raise BenchmarkEnvironmentError("server cache or inference controls differ")
    exact_types = {
        "context_tokens": int,
        "parallel_slots": int,
        "reasoning_budget": int,
        "prompt_cache": str,
        "cache_ram_mib": int,
        "cache_idle_slots": bool,
        "cross_task_kv_reuse": bool,
    }
    if any(type(value[name]) is not exact_types[name] or value[name] != expected[name]
           for name in exact_types):
        raise BenchmarkEnvironmentError("server cache or inference controls differ")
    similarity = value["slot_prompt_similarity"]
    if (type(similarity) not in (int, float) or type(similarity) is bool
            or float(similarity) != 0.0):
        raise BenchmarkEnvironmentError("server cache or inference controls differ")
    return dict(expected)


def _performance_controls(value: Any, *, ngram_simple: bool) -> dict[str, Any]:
    fields = {
        "threads", "threads_batch", "batch_size", "ubatch_size",
        "cache_type_k", "cache_type_v", "flash_attention", "gpu_layers",
        "device", "speculative_decoding",
    }
    if type(value) is not dict or set(value) != fields:
        raise BenchmarkEnvironmentError("server performance controls differ from schema")
    integer_bounds = {
        "threads": (1, 1024),
        "threads_batch": (1, 1024),
        "batch_size": (1, 2**31 - 1),
        "ubatch_size": (1, 2**31 - 1),
        "gpu_layers": (0, 2**31 - 1),
    }
    normalized: dict[str, Any] = {}
    for name, (minimum, maximum) in integer_bounds.items():
        item = value[name]
        if type(item) is not int or not minimum <= item <= maximum:
            raise BenchmarkEnvironmentError("server performance control " + name + " is invalid")
        normalized[name] = item
    if normalized["ubatch_size"] > normalized["batch_size"]:
        raise BenchmarkEnvironmentError("server performance controls have ubatch_size above batch_size")
    for name in ("cache_type_k", "cache_type_v", "device"):
        item = value[name]
        if type(item) is not str or _CONTROL_TOKEN.fullmatch(item) is None:
            raise BenchmarkEnvironmentError("server performance control " + name + " is invalid")
        normalized[name] = item
    flash_attention = value["flash_attention"]
    if type(flash_attention) is not str or flash_attention not in {"on", "off", "auto"}:
        raise BenchmarkEnvironmentError("server performance control flash_attention is invalid")
    normalized["flash_attention"] = flash_attention
    speculative_decoding = value["speculative_decoding"]
    expected_speculation = "ngram-simple" if ngram_simple else "disabled"
    if type(speculative_decoding) is not str or speculative_decoding != expected_speculation:
        raise BenchmarkEnvironmentError("server performance controls disagree with ngram_simple")
    normalized["speculative_decoding"] = speculative_decoding
    return {name: normalized[name] for name in (
        "threads", "threads_batch", "batch_size", "ubatch_size",
        "cache_type_k", "cache_type_v", "flash_attention", "gpu_layers",
        "device", "speculative_decoding",
    )}


def capture_llama_environment(*, state_path: str | Path, profile: LocalProviderProfile,
                              server_control_path: str | Path,
                              hardware: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an alive caller-owned server state and return a sealed projection."""
    if type(profile) is not LocalProviderProfile:
        raise BenchmarkEnvironmentError("LocalProviderProfile required")
    state, state_raw = _load_object(state_path)
    if state.get("schema") != "adaptive-dojo.provider-process.v1" or state.get("status") != "healthy":
        raise BenchmarkEnvironmentError("healthy provider process state required")
    if (state.get("model_id") != profile.model
            or state.get("model_sha256") != profile.model_sha256
            or state.get("runtime_sha256") != profile.runtime_sha256):
        raise BenchmarkEnvironmentError("server identity differs from provider profile")
    if state.get("endpoint") != profile.base_url + "/chat/completions":
        raise BenchmarkEnvironmentError("server endpoint differs from provider profile")
    expected_controls = _inference_controls(state.get("inference_controls"), profile)
    if state.get("full_offload_confirmed") is not True:
        raise BenchmarkEnvironmentError("full accelerator offload was not confirmed")
    launch_hash = _hash(state.get("launch_config_sha256"), "launch_config_sha256")
    command_hash = _hash(state.get("command_sha256"), "command_sha256")
    runtime_profile = _runtime_profile(state.get("profile"))
    ngram_simple = state.get("ngram_simple")
    if type(ngram_simple) is not bool:
        raise BenchmarkEnvironmentError("ngram_simple must be boolean")
    performance_controls = _performance_controls(
        state.get("performance_controls"), ngram_simple=ngram_simple)
    control_raw = _read_bounded(server_control_path, maximum=MAX_SERVER_CONTROL_BYTES,
                                label="server control input")
    body = {
        "schema": SCHEMA,
        "provider_profile_sha256": profile.profile_sha256,
        "model": profile.model,
        "model_sha256": profile.model_sha256,
        "runtime_sha256": profile.runtime_sha256,
        "server_control_sha256": sha256(control_raw),
        "server_state_snapshot_sha256": sha256(state_raw),
        "launch_config_sha256": launch_hash,
        "command_sha256": command_hash,
        "runtime_profile": runtime_profile,
        "ngram_simple": ngram_simple,
        "full_offload_confirmed": True,
        "inference_controls": expected_controls,
        "performance_controls": performance_controls,
        "hardware": _hardware(hardware),
        "paths_disclosed": False,
    }
    return {**body, "environment_sha256": digest(body)}


def validate_environment(value: Mapping[str, Any], profile: LocalProviderProfile) -> dict[str, Any]:
    if type(profile) is not LocalProviderProfile:
        raise BenchmarkEnvironmentError("LocalProviderProfile required")
    if type(value) is not dict or set(value) != {
        "schema", "provider_profile_sha256", "model", "model_sha256", "runtime_sha256",
        "server_control_sha256", "server_state_snapshot_sha256", "launch_config_sha256",
        "command_sha256", "runtime_profile", "ngram_simple", "full_offload_confirmed",
        "inference_controls", "performance_controls", "hardware", "paths_disclosed",
        "environment_sha256",
    }:
        raise BenchmarkEnvironmentError("environment receipt fields differ from schema")
    if value["schema"] != SCHEMA:
        raise BenchmarkEnvironmentError("unsupported environment receipt schema")
    supplied = _hash(value["environment_sha256"], "environment_sha256")
    if (value["provider_profile_sha256"] != profile.profile_sha256
            or value["model"] != profile.model
            or value["model_sha256"] != profile.model_sha256
            or value["runtime_sha256"] != profile.runtime_sha256):
        raise BenchmarkEnvironmentError("environment identity differs from provider profile")
    for name in ("server_control_sha256", "server_state_snapshot_sha256",
                 "launch_config_sha256", "command_sha256"):
        _hash(value[name], name)
    controls = _inference_controls(value["inference_controls"], profile)
    runtime_profile = _runtime_profile(value["runtime_profile"])
    if type(value["ngram_simple"]) is not bool:
        raise BenchmarkEnvironmentError("ngram_simple must be boolean")
    performance_controls = _performance_controls(
        value["performance_controls"], ngram_simple=value["ngram_simple"])
    if value["full_offload_confirmed"] is not True or value["paths_disclosed"] is not False:
        raise BenchmarkEnvironmentError("environment safety or offload assertion differs")
    hardware = _hardware(value["hardware"])
    body = dict(value)
    body.pop("environment_sha256")
    if digest(body) != supplied:
        raise BenchmarkEnvironmentError("environment receipt hash mismatch")
    result = dict(value)
    result["runtime_profile"] = runtime_profile
    result["inference_controls"] = controls
    result["performance_controls"] = performance_controls
    result["hardware"] = hardware
    return result


def save_environment(path: str | Path, receipt: Mapping[str, Any],
                     profile: LocalProviderProfile) -> dict[str, Any]:
    value = validate_environment(receipt, profile)
    raw = canonical(value) + b"\n"
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as stream:
            stream.write(raw)
    except FileExistsError as exc:
        raise BenchmarkEnvironmentError("environment receipt already exists") from exc
    return {"path": str(target), "bytes": len(raw), "raw_sha256": sha256(raw),
            "environment_sha256": value["environment_sha256"]}
