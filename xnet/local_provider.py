"""Safe, receipt-bearing access to a local OpenAI-compatible HTTP server.

This module deliberately has a narrow trust boundary:

* only numeric loopback ``http://`` endpoints are accepted;
* profiles cannot contain credentials, headers, launch commands or downloads;
* requests and responses are bounded JSON documents;
* redirects, proxies and automatic retries are disabled; and
* generated text is returned as data and is never imported or executed.

``raw_*_body_sha256`` fields identify the exact HTTP body bytes sent and
received.  ``request_envelope_sha256`` additionally binds the method and URL;
it does not pretend to hash transport-generated HTTP headers.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PROFILE_SCHEMA = "xnet.local-provider-profile.v1"
RECEIPT_SCHEMA = "xnet.local-provider-http-receipt.v1"
MAX_PROFILE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 1 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 100_000
MAX_STRING_BYTES = 2 * 1024 * 1024
MAX_MESSAGES = 256
MAX_TIMEOUT_SECONDS = 600.0


class LocalProviderError(ValueError):
    """Invalid profile, request or provider response."""


class LocalProviderHTTPError(LocalProviderError):
    """HTTP or transport failure carrying any evidence that was available."""

    def __init__(self, message: str, receipt: Mapping[str, Any]):
        super().__init__(message)
        self.receipt = dict(receipt)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LocalProviderError("JSON contains duplicate object key: " + key)
        result[key] = value
    return result


def _validate_json_tree(value: Any, *, depth: int = 0,
                        counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES:
        raise LocalProviderError("JSON exceeds node limit")
    if depth > MAX_JSON_DEPTH:
        raise LocalProviderError("JSON exceeds nesting limit")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise LocalProviderError("JSON integer exceeds portable range")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise LocalProviderError("JSON number must be finite")
        return
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise LocalProviderError("JSON string exceeds byte limit")
        return
    if type(value) is list:
        for item in value:
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise LocalProviderError("JSON object keys must be strings")
            if len(key.encode("utf-8")) > 512:
                raise LocalProviderError("JSON object key exceeds byte limit")
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    raise LocalProviderError("value is not JSON data")


def _parse_json_bytes(raw: bytes, *, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LocalProviderError(label + " is not UTF-8 JSON") from error
    try:
        value = json.loads(text, object_pairs_hook=_pairs_no_duplicates,
                           parse_constant=lambda token: (_ for _ in ()).throw(
                               LocalProviderError("non-finite JSON number: " + token)))
    except LocalProviderError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise LocalProviderError(label + " is not valid JSON") from error
    _validate_json_tree(value)
    return value


def _validate_sha256(value: Any, field: str) -> str:
    if type(value) is not str or len(value) != 64:
        raise LocalProviderError(field + " must be a 64-character SHA-256")
    lowered = value.lower()
    if any(character not in "0123456789abcdef" for character in lowered):
        raise LocalProviderError(field + " must be hexadecimal")
    return lowered


def _validate_base_url(value: Any) -> str:
    if type(value) is not str or len(value) > 512:
        raise LocalProviderError("base_url must be a bounded string")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise LocalProviderError("base_url is malformed") from error
    if parsed.scheme != "http":
        raise LocalProviderError("base_url must use http")
    if parsed.username is not None or parsed.password is not None:
        raise LocalProviderError("base_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise LocalProviderError("base_url must not contain query or fragment")
    if parsed.hostname is None or port is None:
        raise LocalProviderError("base_url requires a numeric host and explicit port")
    if "%" in parsed.hostname:
        raise LocalProviderError("scoped IP addresses are not accepted")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise LocalProviderError("base_url host must be a numeric IP address") from error
    if not address.is_loopback:
        raise LocalProviderError("base_url host must be loopback")
    if parsed.path not in ("/v1", "/v1/"):
        raise LocalProviderError("base_url path must be /v1")
    host = "[" + address.compressed + "]" if address.version == 6 else address.compressed
    return "http://" + host + ":" + str(port) + "/v1"


def _bounded_text(value: Any, field: str, maximum: int = 256) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise LocalProviderError(field + " must be a nonempty bounded string")
    if any(ord(character) < 32 for character in value):
        raise LocalProviderError(field + " must not contain control characters")
    return value


def _exact_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise LocalProviderError(field + " is outside its exact integer range")
    return value


def _temperature(value: Any) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise LocalProviderError("temperature must be a finite number")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 2.0:
        raise LocalProviderError("temperature must be between 0 and 2")
    return number


@dataclass(frozen=True)
class LocalProviderProfile:
    """Pinned local model/runtime identity plus bounded generation defaults."""

    base_url: str
    model: str
    model_sha256: str
    runtime_sha256: str
    context_tokens: int
    max_output_tokens: int
    temperature: float
    seed: int
    schema: str = PROFILE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PROFILE_SCHEMA:
            raise LocalProviderError("unsupported profile schema")
        object.__setattr__(self, "base_url", _validate_base_url(self.base_url))
        object.__setattr__(self, "model", _bounded_text(self.model, "model"))
        object.__setattr__(self, "model_sha256",
                           _validate_sha256(self.model_sha256, "model_sha256"))
        object.__setattr__(self, "runtime_sha256",
                           _validate_sha256(self.runtime_sha256, "runtime_sha256"))
        context = _exact_int(self.context_tokens, "context_tokens", 256, 2**31 - 1)
        output = _exact_int(self.max_output_tokens, "max_output_tokens", 1, 2**31 - 1)
        if output > context:
            raise LocalProviderError("max_output_tokens must not exceed context_tokens")
        object.__setattr__(self, "temperature", _temperature(self.temperature))
        _exact_int(self.seed, "seed", -(2**31), 2**31 - 1)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "LocalProviderProfile":
        if type(value) is not dict:
            raise LocalProviderError("profile must be an exact JSON object")
        expected = {"schema", "base_url", "model", "model_sha256", "runtime_sha256",
                    "context_tokens", "max_output_tokens", "temperature", "seed"}
        if set(value) != expected:
            extra = sorted(set(value) - expected)
            missing = sorted(expected - set(value))
            raise LocalProviderError("profile fields differ; extra=" + repr(extra)
                                     + ", missing=" + repr(missing))
        return cls(**value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "base_url": self.base_url,
            "model": self.model,
            "model_sha256": self.model_sha256,
            "runtime_sha256": self.runtime_sha256,
            "context_tokens": self.context_tokens,
            "max_output_tokens": self.max_output_tokens,
            "temperature": self.temperature,
            "seed": self.seed,
        }

    @property
    def profile_sha256(self) -> str:
        return _sha256(_canonical_json_bytes(self.as_dict()))


def load_profile(path: str | os.PathLike[str]) -> LocalProviderProfile:
    profile_path = Path(path)
    raw = profile_path.read_bytes()
    if len(raw) > MAX_PROFILE_BYTES:
        raise LocalProviderError("profile exceeds byte limit")
    value = _parse_json_bytes(raw, label="profile")
    return LocalProviderProfile.from_mapping(value)


def save_profile(path: str | os.PathLike[str], profile: LocalProviderProfile) -> dict[str, Any]:
    """Create a profile without replacing an existing file."""
    if type(profile) is not LocalProviderProfile:
        raise LocalProviderError("profile must be LocalProviderProfile")
    profile_path = Path(path)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    raw = _canonical_json_bytes(profile.as_dict()) + b"\n"
    try:
        with profile_path.open("xb") as stream:
            stream.write(raw)
    except FileExistsError as error:
        raise LocalProviderError("profile already exists") from error
    return {"path": str(profile_path), "bytes": len(raw),
            "raw_profile_sha256": _sha256(raw),
            "canonical_profile_sha256": profile.profile_sha256}


def _timeout(value: Any) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise LocalProviderError("timeout_seconds must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0.05 <= result <= MAX_TIMEOUT_SECONDS:
        raise LocalProviderError("timeout_seconds is outside the bounded range")
    return result


def _endpoint(profile: LocalProviderProfile, operation: str) -> str:
    parsed = urlsplit(profile.base_url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    if operation == "health":
        return origin + "/health"
    if operation == "models":
        return profile.base_url + "/models"
    if operation == "chat":
        return profile.base_url + "/chat/completions"
    raise LocalProviderError("unknown endpoint operation")


def _http_json(method: str, url: str, body: bytes | None,
               timeout_seconds: float) -> tuple[Any, dict[str, Any]]:
    if method not in ("GET", "POST"):
        raise LocalProviderError("HTTP method is not allowed")
    request_body = b"" if body is None else body
    if len(request_body) > MAX_REQUEST_BYTES:
        raise LocalProviderError("request body exceeds byte limit")
    envelope = method.encode("ascii") + b"\n" + url.encode("ascii") + b"\n" + request_body
    base_receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "method": method,
        "url": url,
        "raw_request_body_bytes": len(request_body),
        "raw_request_body_sha256": _sha256(request_body),
        "request_envelope_sha256": _sha256(envelope),
        "raw_response_body_bytes": None,
        "raw_response_body_sha256": None,
        "http_status": None,
        "content_type": None,
        "client_elapsed_ms": None,
        "redirects_followed": 0,
        "retries": 0,
    }
    headers = {"Accept": "application/json", "Accept-Encoding": "identity",
               "User-Agent": "xnet-harness-local-provider/1"}
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = Request(url=url, data=body, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    started = time.perf_counter()
    try:
        response = opener.open(request, timeout=_timeout(timeout_seconds))
    except HTTPError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        raw = error.read(MAX_RESPONSE_BYTES + 1)
        receipt = dict(base_receipt)
        receipt.update({"http_status": error.code,
                        "content_type": error.headers.get("Content-Type"),
                        "client_elapsed_ms": elapsed_ms,
                        "raw_response_body_bytes": len(raw),
                        "raw_response_body_sha256": _sha256(raw)})
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LocalProviderHTTPError("HTTP error body exceeds byte limit", receipt) from error
        raise LocalProviderHTTPError("provider returned HTTP " + str(error.code), receipt) from error
    except (URLError, TimeoutError, OSError) as error:
        receipt = dict(base_receipt)
        receipt["client_elapsed_ms"] = (time.perf_counter() - started) * 1000.0
        raise LocalProviderHTTPError("provider transport failed", receipt) from error
    with response:
        encoding = response.headers.get("Content-Encoding")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        receipt = dict(base_receipt)
        receipt.update({"http_status": response.status,
                        "content_type": response.headers.get("Content-Type"),
                        "client_elapsed_ms": (time.perf_counter() - started) * 1000.0,
                        "raw_response_body_bytes": len(raw),
                        "raw_response_body_sha256": _sha256(raw)})
    if encoding not in (None, "", "identity"):
        raise LocalProviderHTTPError("encoded HTTP responses are not accepted", receipt)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise LocalProviderHTTPError("response body exceeds byte limit", receipt)
    try:
        parsed = _parse_json_bytes(raw, label="provider response")
    except LocalProviderError as error:
        raise LocalProviderHTTPError(str(error), receipt) from error
    if type(parsed) is not dict:
        raise LocalProviderHTTPError("provider response must be a JSON object", receipt)
    return parsed, receipt


def _path_get(value: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = value
    for component in path:
        if type(current) is not dict or component not in current:
            return None
        current = current[component]
    return current


def _metric(response: Mapping[str, Any], paths: Sequence[tuple[str, ...]],
            *, integer: bool = False) -> tuple[int | float | None, str]:
    found: list[tuple[int | float, str]] = []
    for path in paths:
        value = _path_get(response, path)
        if value is None:
            continue
        valid = type(value) is int if integer else type(value) in (int, float)
        if not valid or type(value) is bool or value < 0 or (not integer and not math.isfinite(float(value))):
            raise LocalProviderError("invalid provider metric at " + ".".join(path))
        found.append((value, ".".join(path)))
    if not found:
        return None, "unknown"
    if any(item[0] != found[0][0] for item in found[1:]):
        raise LocalProviderError("conflicting provider metrics: "
                                 + ", ".join(item[1] for item in found))
    return found[0]


def normalize_response_metrics(response: Mapping[str, Any]) -> dict[str, Any]:
    """Return common counters/timings with explicit nulls for unknown values."""
    if type(response) is not dict:
        raise LocalProviderError("response must be an exact JSON object")
    specs = {
        "input_tokens": (("usage", "input_tokens"), ("usage", "prompt_tokens"),
                         ("timings", "prompt_n")),
        "output_tokens": (("usage", "output_tokens"), ("usage", "completion_tokens"),
                          ("timings", "predicted_n"), ("tokens_predicted",)),
        "total_tokens": (("usage", "total_tokens"),),
        "cached_input_tokens": (("usage", "prompt_tokens_details", "cached_tokens"),),
        "speculative_drafted_tokens": (("timings", "draft_n"),
                                       ("timings", "drafted_tokens")),
        "speculative_accepted_tokens": (("timings", "draft_n_accepted"),
                                        ("timings", "accepted_tokens")),
    }
    timing_specs = {
        "prompt_ms": (("timings", "prompt_ms"),),
        "decode_ms": (("timings", "decode_ms"), ("timings", "predicted_ms")),
        "time_to_first_token_ms": (("timings", "time_to_first_token_ms"),
                                   ("timings", "ttft_ms")),
        "prompt_tokens_per_second": (("timings", "prompt_per_second"),),
        "decode_tokens_per_second": (("timings", "decode_per_second"),
                                     ("timings", "predicted_per_second")),
    }
    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for name, paths in specs.items():
        values[name], sources[name] = _metric(response, paths, integer=True)
    for name, paths in timing_specs.items():
        values[name], sources[name] = _metric(response, paths, integer=False)
    if (values["total_tokens"] is None and values["input_tokens"] is not None
            and values["output_tokens"] is not None):
        values["total_tokens"] = values["input_tokens"] + values["output_tokens"]
        sources["total_tokens"] = "derived:input_tokens+output_tokens"
    if (values["total_tokens"] is not None and values["input_tokens"] is not None
            and values["output_tokens"] is not None
            and values["total_tokens"] != values["input_tokens"] + values["output_tokens"]):
        raise LocalProviderError("total_tokens conflicts with input plus output tokens")
    if (values["cached_input_tokens"] is not None and values["input_tokens"] is not None
            and values["cached_input_tokens"] > values["input_tokens"]):
        raise LocalProviderError("cached_input_tokens exceeds input_tokens")
    if (values["speculative_accepted_tokens"] is not None
            and values["speculative_drafted_tokens"] is not None
            and values["speculative_accepted_tokens"] > values["speculative_drafted_tokens"]):
        raise LocalProviderError("accepted speculative tokens exceed drafted tokens")
    return {"schema": "xnet.local-provider-metrics.v1", "values": values,
            "sources": sources, "unknown": sorted(name for name, value in values.items()
                                                 if value is None)}


def _validate_messages(messages: Any) -> list[dict[str, str]]:
    if type(messages) not in (list, tuple) or not 1 <= len(messages) <= MAX_MESSAGES:
        raise LocalProviderError("messages must be a bounded nonempty sequence")
    result: list[dict[str, str]] = []
    for message in messages:
        if type(message) is not dict or set(message) != {"role", "content"}:
            raise LocalProviderError("each message must contain only role and content")
        role = message["role"]
        content = message["content"]
        if role not in ("system", "user", "assistant"):
            raise LocalProviderError("message role is not allowed")
        if type(content) is not str:
            raise LocalProviderError("message content must be text")
        result.append({"role": role, "content": content})
    _validate_json_tree(result)
    return result


def chat_completion(profile: LocalProviderProfile, messages: Any,
                    *, timeout_seconds: float = 120.0) -> dict[str, Any]:
    """Make one bounded call and return the candidate text as inert data."""
    if type(profile) is not LocalProviderProfile:
        raise LocalProviderError("profile must be LocalProviderProfile")
    payload = {
        "model": profile.model,
        "messages": _validate_messages(messages),
        "max_tokens": profile.max_output_tokens,
        "temperature": profile.temperature,
        "seed": profile.seed,
        "stream": False,
    }
    body = _canonical_json_bytes(payload)
    if len(body) > MAX_REQUEST_BYTES:
        raise LocalProviderError("request body exceeds byte limit")
    response, receipt = _http_json("POST", _endpoint(profile, "chat"), body,
                                   timeout_seconds)
    choices = response.get("choices")
    if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
        raise LocalProviderHTTPError("response must contain exactly one choice", receipt)
    message = choices[0].get("message")
    if type(message) is not dict or type(message.get("content")) is not str:
        raise LocalProviderHTTPError("choice must contain textual message content", receipt)
    try:
        metrics = normalize_response_metrics(response)
    except LocalProviderError as error:
        raise LocalProviderHTTPError(str(error), receipt) from error
    return {
        "schema": "xnet.local-provider-generation.v1",
        "profile_sha256": profile.profile_sha256,
        "model": profile.model,
        "model_sha256": profile.model_sha256,
        "runtime_sha256": profile.runtime_sha256,
        "provider_request": payload,
        "candidate_text": message["content"],
        "finish_reason": choices[0].get("finish_reason"),
        "metrics": metrics,
        "provider_response": response,
        "http_receipt": receipt,
        "candidate_authority": "data-only",
    }


def _safe_probe(profile: LocalProviderProfile, operation: str,
                timeout_seconds: float) -> dict[str, Any]:
    try:
        response, receipt = _http_json("GET", _endpoint(profile, operation), None,
                                       timeout_seconds)
        return {"ok": True, "response": response, "http_receipt": receipt,
                "error": None}
    except LocalProviderHTTPError as error:
        return {"ok": False, "response": None, "http_receipt": error.receipt,
                "error": str(error)}


def doctor_profile(profile: LocalProviderProfile,
                   *, timeout_seconds: float = 5.0) -> dict[str, Any]:
    """Read-only health and model-list probes; never starts or changes a server."""
    health = _safe_probe(profile, "health", timeout_seconds)
    models = _safe_probe(profile, "models", timeout_seconds)
    configured_model_present: bool | None = None
    if models["ok"]:
        data = models["response"].get("data")
        if type(data) is list and all(type(item) is dict for item in data):
            identifiers = [item.get("id") for item in data if type(item.get("id")) is str]
            configured_model_present = profile.model in identifiers
    return {
        "schema": "xnet.local-provider-doctor.v1",
        "profile_sha256": profile.profile_sha256,
        "base_url": profile.base_url,
        "model": profile.model,
        "health": health,
        "models": models,
        "configured_model_present": configured_model_present,
        "ok": health["ok"] and models["ok"] and configured_model_present is True,
        "actions_performed": ["GET /health", "GET /v1/models"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Standalone init/doctor layer for later attachment to ``xnet.cli``."""
    parser = argparse.ArgumentParser(prog="python -m xnet.local_provider")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="create a pinned local provider profile")
    initialize.add_argument("--path", required=True)
    initialize.add_argument("--base-url", required=True)
    initialize.add_argument("--model", required=True)
    initialize.add_argument("--model-sha256", required=True)
    initialize.add_argument("--runtime-sha256", required=True)
    initialize.add_argument("--context-tokens", required=True, type=int)
    initialize.add_argument("--max-output-tokens", required=True, type=int)
    initialize.add_argument("--temperature", type=float, default=0.0)
    initialize.add_argument("--seed", type=int, default=0)
    doctor = commands.add_parser("doctor", help="read-only health and model-list probes")
    doctor.add_argument("--profile", required=True)
    doctor.add_argument("--timeout-seconds", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            profile = LocalProviderProfile(
                base_url=args.base_url,
                model=args.model,
                model_sha256=args.model_sha256,
                runtime_sha256=args.runtime_sha256,
                context_tokens=args.context_tokens,
                max_output_tokens=args.max_output_tokens,
                temperature=args.temperature,
                seed=args.seed,
            )
            result = {"schema": "xnet.local-provider-init.v1",
                      "profile": profile.as_dict(), "write": save_profile(args.path, profile)}
        else:
            result = doctor_profile(load_profile(args.profile),
                                    timeout_seconds=args.timeout_seconds)
    except (LocalProviderError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
