"""Source-pinned learning callbacks borrowing one declared loopback endpoint.

This XNET adapter does not import, replace or own any Kimi runner. The caller
provides a PRIVATE LOCAL Ledger/root, signed scope and existing server. Exact
request and response bodies are retained before admission. A reserved request
without a response requires reconciliation and is never dispatched again.
Endpoint aliases and artifact pins are declarations, not weight attestation.
"""
from __future__ import annotations

import copy
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import types
from urllib.parse import urlsplit

from adapters.kimi.learning_prompt import learning_message_evidence, render_learning_messages
from xnet.brains import _exclusive_file_lock
from xnet.context_callable_identity_v2 import code_sha256
from xnet.generation_usage import generation_usage_projection, normalize_generation_usage
from xnet.learning_dataset import _public_value, _task
from xnet.learning_wing import build_proposal_request
from xnet.ledger import Ledger
from xnet.protocol import canonical, digest, make_event, sha256
from xnet.relay_log import _no_links
from xnet.scope import ScopeAuthority

PATH = "/v1/chat/completions"
METHOD = "learning-generate"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
_LABEL = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class LearningTransportError(ValueError):
    pass


class PendingLearningTransport(LearningTransportError):
    """A durable nonce exists without known raw response bytes."""

    def __init__(self, nonce, request_sha256):
        super().__init__("reserved learning transport requires reconciliation; no redispatch")
        self.nonce, self.request_sha256 = nonce, request_sha256


class _HTTPRejected(LearningTransportError):
    def __init__(self, status, raw):
        super().__init__("loopback HTTP status " + str(status))
        self.status, self.raw = status, raw


def _label(value):
    if type(value) is not str or not _LABEL.fullmatch(value):
        raise LearningTransportError("exact bounded label required")
    return value


def _hash(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise LearningTransportError("exact SHA256 pin required")
    return value


def _integer(value, label, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise LearningTransportError(label + " exceeds exact integer bounds")
    return value


def _endpoint(value):
    if type(value) is not str or any(ord(char) < 33 for char in value):
        raise LearningTransportError("numeric HTTP loopback endpoint required")
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        address = ipaddress.ip_address(host or "")
    except (TypeError, ValueError) as exc:
        raise LearningTransportError("numeric HTTP loopback endpoint required") from exc
    if (parsed.scheme != "http" or not address.is_loopback or port is None
            or not 1 <= port <= 65535 or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment or "%" in host):
        raise LearningTransportError("numeric HTTP loopback endpoint with explicit port required")
    netloc = "[" + str(address) + "]" if address.version == 6 else str(address)
    return "http://" + netloc + ":" + str(port)


def _object(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RESPONSE_BYTES:
        raise LearningTransportError("bounded exact response bytes required")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LearningTransportError("duplicate JSON response field")
            result[key] = value
        return result
    def invalid(value):
        raise LearningTransportError("nonfinite JSON response value")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise LearningTransportError("UTF-8 response object required") from exc
    if type(result) is not dict:
        raise LearningTransportError("response object required")
    return result


def build_repair_messages(request):
    """Render only explicit public task, base files and public feedback."""
    _task(request["task"])
    _public_value(request["public_feedback"])
    _public_value(request["base_files"])
    if (type(request["base_files"]) is not dict or set(request["base_files"]) != set(request["task"]["files"])
            or any(type(value) is not str for value in request["base_files"].values())
            or type(request["contract"]) is not str or len(request["contract"].encode()) > 16384):
        raise LearningTransportError("bounded public repair source/contract required")
    public = {key: request[key] for key in ("task", "base_files", "public_feedback")}
    return [{"role": "system", "content": request["contract"]},
            {"role": "user", "content": canonical(public).decode("utf-8")}]


def build_proposal_messages(request):
    expected = build_proposal_request(request["failure_feed"])
    if any(request.get(key) != value for key, value in expected.items()):
        raise LearningTransportError("proposal differs from fixed public failure feed")
    return [{"role": "system", "content": expected["system"]},
            {"role": "user", "content": expected["prompt"]}]


def loopback_chat_transport(endpoint, path, payload_bytes, timeout_seconds):
    """POST exact bytes with stdlib HTTP; no proxy, redirect or process action."""
    endpoint = _endpoint(endpoint)
    if path != PATH or type(payload_bytes) is not bytes or not 1 <= len(payload_bytes) <= MAX_REQUEST_BYTES:
        raise LearningTransportError("fixed bounded chat request required")
    parts = urlsplit(endpoint)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout_seconds)
    try:
        connection.request("POST", PATH, body=payload_bytes,
                           headers={"Content-Type": "application/json", "Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        # Preserve the returned body even for an HTTP rejection. Admission will
        # reject an error object, and an uncertain socket never gets retried.
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LearningTransportError("response exceeds byte budget")
        if response.status != 200:
            raise _HTTPRejected(response.status, raw)
        return raw
    finally:
        connection.close()


def _callable_identity(callback, artifacts):
    fn = getattr(callback, "__func__", callback)
    if not isinstance(fn, types.FunctionType):
        raise LearningTransportError("source-defined function or bound callback required")
    path = str(Path(fn.__code__.co_filename).absolute())
    if os.path.normcase(path) not in {os.path.normcase(row["path"]) for row in artifacts}:
        raise LearningTransportError("callback source must be selected by exact artifact pin")
    return {"path": path, "qualname": fn.__qualname__, "code_sha256": code_sha256(fn.__code__)}


def transport_source_artifacts():
    """Current adapter/dependency source rows for a newly reviewed run identity."""
    root = Path(__file__).resolve().parents[2]
    names = ["adapters/kimi/learning_transport.py", "adapters/kimi/learning_prompt.py",
             "xnet/generation_usage.py", "xnet/learning_dataset.py", "xnet/learning_wing.py",
             "xnet/context_callable_identity_v2.py", "xnet/brains.py", "xnet/ledger.py",
             "xnet/protocol.py", "xnet/relay_log.py", "xnet/scope.py", "xnet/repair_loop.py"]
    return [{"path": str((root / name).absolute()), "sha256": sha256((root / name).read_bytes())}
            for name in names]


class BorrowedLearningTransport:
    """Callable repair/proposal peer, with durable private raw transport evidence.

    ``transport(endpoint, path, payload_bytes, timeout_seconds) -> bytes`` can
    be a caller's source-pinned recording fixture. Both it and ``base_builder``
    must be selected by ``callback_artifacts``. Internal dependencies are pinned
    automatically. The fixed signed scope method is ``learning-generate``.
    """

    def __init__(self, ledger, root, *, base_url, served_model, model_id, model_sha256,
                 scope_authority, scope_id, base_builder=build_repair_messages,
                 callback_artifacts=(), temperature=0, seed=0, max_output_tokens=650,
                 timeout_seconds=120, transport=loopback_chat_transport):
        if not isinstance(ledger, Ledger) or type(scope_authority) is not ScopeAuthority:
            raise LearningTransportError("caller private Ledger and signed ScopeAuthority required")
        self.ledger, self.root = ledger, Path(root).absolute()
        self.scope_authority, self.scope_id = scope_authority, _label(scope_id)
        self.base_url, self.served_model = _endpoint(base_url), _label(served_model)
        self.model_id, self.model_sha256 = _label(model_id), _hash(model_sha256)
        self.max_output_tokens = _integer(max_output_tokens, "output budget", 1, 650)
        self.timeout_seconds = _integer(timeout_seconds, "timeout", 1, 3600)
        self.seed = _integer(seed, "seed", 0, 2**31 - 1)
        if type(temperature) not in (int, float) or not math.isfinite(temperature) or not 0 <= temperature <= 2:
            raise LearningTransportError("finite bounded temperature required")
        self.temperature, self.base_builder, self.transport = temperature, base_builder, transport
        if type(callback_artifacts) not in (list, tuple) or len(callback_artifacts) > 32:
            raise LearningTransportError("bounded selected callback source rows required")
        rows = transport_source_artifacts() + copy.deepcopy(list(callback_artifacts))
        merged = {}
        for row in rows:
            if type(row) is not dict or set(row) != {"path", "sha256"} or type(row["path"]) is not str:
                raise LearningTransportError("exact artifact path/hash required")
            path = Path(row["path"])
            if not path.is_absolute():
                raise LearningTransportError("absolute artifact path required")
            _hash(row["sha256"])
            key = os.path.normcase(str(path))
            if key in merged and merged[key] != row:
                raise LearningTransportError("conflicting source pin")
            merged[key] = row
        self.callback_artifacts = sorted(merged.values(), key=lambda row: row["path"])
        self._binding = self._identity()
        self._binding_sha256 = digest(self._binding)
        _no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        with self._lock():
            manifest = self.root / "manifest.json"
            if manifest.exists():
                if self._read_record(manifest) != self._binding:
                    raise LearningTransportError("transport resume identity changed; use a fresh root")
            else:
                if any(path.name != "transport.lock" for path in self.root.iterdir()):
                    raise LearningTransportError("nonempty uninitialized transport root")
                self._write_record(manifest, self._binding)

    def _identity(self):
        for row in self.callback_artifacts:
            path = Path(row["path"])
            _no_links(path, regular_file=True)
            if sha256(path.read_bytes()) != row["sha256"]:
                raise LearningTransportError("selected callback source drift")
        return {"schema": "xnet.kimi-learning-transport.v1", "root": str(self.root),
                "ledger_root": str(self.ledger.data_dir.absolute()),
                "authority_root": str(self.scope_authority.data_dir.absolute()),
                "scope_id": self.scope_id, "base_url": self.base_url, "path": PATH, "method": METHOD,
                "model_id": self.model_id, "model_sha256": self.model_sha256, "served_model": self.served_model,
                "decoding": {"temperature": self.temperature, "seed": self.seed,
                             "max_output_tokens": self.max_output_tokens, "stream": False},
                "timeout_seconds": self.timeout_seconds, "artifacts": copy.deepcopy(self.callback_artifacts),
                "base_builder": _callable_identity(self.base_builder, self.callback_artifacts),
                "transport": _callable_identity(self.transport, self.callback_artifacts),
                "server_owner": "caller", "artifact_identity_authenticated": False,
                "visibility": "private", "cloud_export": False}

    def _assert_identity(self):
        _no_links(self.root)
        if (digest(self._binding) != self._binding_sha256 or self._identity() != self._binding
                or self._read_record(self.root / "manifest.json") != self._binding):
            raise LearningTransportError("transport binding drift")

    def identity(self):
        self._assert_identity()
        return copy.deepcopy(self._binding) | {"binding_sha256": self._binding_sha256}

    def _lock(self):
        _no_links(self.root / "transport.lock")
        return _exclusive_file_lock(self.root / "transport.lock", timeout=1)

    @staticmethod
    def _write_bytes(path, raw):
        _no_links(path, regular_file=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())

    @classmethod
    def _write_record(cls, path, body):
        cls._write_bytes(path, canonical({"body": body, "sha256": digest(body)}))

    @staticmethod
    def _read_record(path):
        _no_links(path, regular_file=True)
        raw = path.read_bytes()
        value = _object(raw)
        if set(value) != {"body", "sha256"} or digest(value["body"]) != value["sha256"]:
            raise LearningTransportError("private transport record hash mismatch")
        return value["body"]

    def _seal(self, raw, source):
        return self.ledger.put_evidence(raw, source=source, scope_id=self.scope_id,
                    metadata={"visibility": "private", "cloud_export": False, "learner_input": False,
                              "authority": "none", "transport_binding_sha256": self._binding_sha256})

    def _payload(self, request, kind):
        if type(request) is not dict or request.get("model_id") != self.model_id or request.get("model_sha256") != self.model_sha256:
            raise LearningTransportError("request model declaration differs from frozen transport")
        budget = _integer(request.get("max_output_tokens", self.max_output_tokens), "request output budget", 1, self.max_output_tokens)
        if kind == "repair":
            _task(request["task"])
            _public_value(request["public_feedback"])
            if request.get("hidden_cases_used", False) is not False:
                raise LearningTransportError("hidden inputs refused")
            nonce = _label(request.get("nonce"))
            policy = request.get("learning_public_context_policy")
            if policy is not None:
                for artifact in policy.get("preparer_artifacts", []):
                    path = Path(artifact["path"])
                    _no_links(path, regular_file=True)
                    if sha256(path.read_bytes()) != artifact["sha256"]:
                        raise LearningTransportError("public preparer artifact drift")
            messages = render_learning_messages(request, self.base_builder)
            evidence = learning_message_evidence(request, messages)
        else:
            nonce = _label(request.get("reservation_id"))
            messages = build_proposal_messages(request)
            evidence = {"schema": "xnet.kimi-learning-proposal-message-evidence.v1", "nonce": nonce,
                        "messages_sha256": digest(messages), "failure_feed_sha256": request["failure_feed_sha256"],
                        "source_only": True, "work_performed": False}
        payload = {"model": self.served_model, "messages": messages, "temperature": self.temperature,
                   "seed": self.seed, "max_tokens": budget, "stream": False}
        raw = canonical(payload)
        if len(raw) > MAX_REQUEST_BYTES:
            raise LearningTransportError("outbound learning payload exceeds byte budget")
        # Reparse the actual bytes sent; delivery evidence is checked against
        # this payload, never a separate renderer-only projection.
        actual = _object(raw)
        if set(actual) != {"model", "messages", "temperature", "seed", "max_tokens", "stream"} or actual != payload:
            raise LearningTransportError("outbound payload differs from exact fixed schema")
        if kind == "repair" and learning_message_evidence(request, actual["messages"]) != evidence:
            raise LearningTransportError("public context absent from outbound messages")
        return nonce, raw, evidence

    def _reservation(self, directory):
        value = self._read_record(directory / "reservation.json")
        fields = {"schema", "nonce", "kind", "binding_sha256", "request_sha256", "payload_sha256",
                  "scope_manifest_sha256", "message_evidence"}
        if (type(value) is not dict or set(value) != fields
                or value["schema"] != "xnet.kimi-learning-transport-reservation.v1"
                or value["nonce"] != directory.name or value["kind"] not in ("repair", "proposal")
                or value["binding_sha256"] != self._binding_sha256):
            raise LearningTransportError("private reservation binding differs")
        for key in ("request_sha256", "payload_sha256", "scope_manifest_sha256"):
            _hash(value[key])
            self.ledger.get_evidence(value[key])
        request = _object(self.ledger.get_evidence(value["request_sha256"]))
        nonce_field = "nonce" if value["kind"] == "repair" else "reservation_id"
        if request.get(nonce_field) != value["nonce"]:
            raise LearningTransportError("private request nonce differs")
        return value

    def _admit(self, raw, reservation):
        response = _object(raw)
        if response.get("model") != self.served_model:
            raise LearningTransportError("response served model differs from declared alias")
        for key, expected in (("model_id", self.model_id), ("model_sha256", self.model_sha256)):
            if key in response and response[key] != expected:
                raise LearningTransportError("response model declaration mismatch")
        choices = response.get("choices")
        if (type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict
                or choices[0].get("index") != 0 or type(choices[0].get("index")) is not int
                or choices[0].get("finish_reason") not in ("stop", "length")):
            raise LearningTransportError("single completed assistant choice required")
        message = choices[0].get("message")
        if type(message) is not dict or set(message) != {"role", "content"} or message["role"] != "assistant" or type(message["content"]) is not str:
            raise LearningTransportError("exact text-only assistant message required")
        text = message["content"]
        maximum = 16384 if reservation["kind"] == "proposal" else 32768
        if len(text.encode("utf-8")) > maximum:
            raise LearningTransportError("assistant text exceeds byte budget")
        usage = normalize_generation_usage(response.get("usage"))
        payload = _object(self.ledger.get_evidence(reservation["payload_sha256"]))
        if usage["output_tokens"] > payload["max_tokens"]:
            raise LearningTransportError("reported output tokens exceed frozen budget")
        result = {"text": text, "usage": usage}
        if reservation["kind"] == "repair":
            result.update(model_id=self.model_id, model_sha256=self.model_sha256)
        return result, generation_usage_projection(response["usage"])

    def _complete(self, directory, reservation, raw):
        response_pin = self._seal(raw, "learning-transport-response-raw")
        self._assert_identity()  # returned bytes already saved before this check
        if (directory / "http-rejected.json").exists():
            rejected = self._read_record(directory / "http-rejected.json")
            if rejected["response_raw_sha256"] != response_pin:
                raise LearningTransportError("rejected HTTP response evidence changed")
            raise LearningTransportError("preserved response was rejected by HTTP status")
        result, usage_evidence = self._admit(raw, reservation)
        body = {"schema": "xnet.kimi-learning-transport-result.v1", "nonce": reservation["nonce"],
                "reservation_sha256": digest(reservation), "payload_sha256": reservation["payload_sha256"],
                "response_raw_sha256": response_pin, "usage_evidence": usage_evidence,
                "result": result, "artifact_identity_authenticated": False}
        completed = directory / "completed.json"
        if completed.exists():
            if self._read_record(completed) != body:
                raise LearningTransportError("conflicting immutable transport completion")
        else:
            self._write_record(completed, body)
        self._seal(canonical(body), "learning-transport-completed")
        return copy.deepcopy(result)

    def _run(self, request, kind):
        with self._lock():
            self._assert_identity()
            nonce, raw, messages_evidence = self._payload(copy.deepcopy(request), kind)
            directory = self.root / "attempts" / nonce
            path = directory / "reservation.json"
            if path.exists():
                saved = self._reservation(directory)
                if (saved["request_sha256"] != digest(request) or saved["payload_sha256"] != sha256(raw)
                        or saved["kind"] != kind or saved["message_evidence"] != messages_evidence):
                    raise LearningTransportError("nonce already belongs to a different exact request")
                response = directory / "response.raw"
                if not response.exists():
                    raise PendingLearningTransport(nonce, saved["payload_sha256"])
                _no_links(response, regular_file=True)
                return self._complete(directory, saved, response.read_bytes())
            scope = self.scope_authority.gate(self.scope_id, self.base_url + PATH, METHOD, network=True)
            reservation = {"schema": "xnet.kimi-learning-transport-reservation.v1", "nonce": nonce, "kind": kind,
                           "binding_sha256": self._binding_sha256, "request_sha256": self._seal(canonical(request), "learning-transport-request"),
                           "payload_sha256": self._seal(raw, "learning-transport-payload"),
                           "scope_manifest_sha256": self._seal(canonical(scope), "learning-transport-scope"),
                           "message_evidence": messages_evidence}
            self._write_record(path, reservation)  # durable BEFORE any dispatch
            self._assert_identity()
            # Recheck live signed admission after committing the reservation.
            current = self.scope_authority.gate(self.scope_id, self.base_url + PATH, METHOD, network=True)
            if digest(current) != reservation["scope_manifest_sha256"]:
                raise LearningTransportError("scope changed before dispatch")
            try:
                response = self.transport(self.base_url, PATH, raw, self.timeout_seconds)
            except _HTTPRejected as exc:
                self._write_bytes(directory / "response.raw", exc.raw)
                self._write_record(directory / "http-rejected.json", {
                    "status": exc.status, "response_raw_sha256": self._seal(exc.raw, "learning-transport-response-raw")})
                raise
            if type(response) is not bytes or not 1 <= len(response) <= MAX_RESPONSE_BYTES:
                raise LearningTransportError("transport returned unbounded or non-byte evidence")
            self._write_bytes(directory / "response.raw", response)
            return self._complete(directory, reservation, response)

    def generate(self, request):
        return self._run(request, "repair")

    def propose(self, request):
        return self._run(request, "proposal")

    def evidence(self, nonce):
        """Private detached receipt; contains hashes, never response replacement."""
        with self._lock():
            self._assert_identity()
            directory = self.root / "attempts" / _label(nonce)
            reservation = self._reservation(directory)
            completed = directory / "completed.json"
            return {"reservation": reservation,
                    "completed": self._read_record(completed) if completed.exists() else None}

    def reconcile(self, nonce, raw_response, *, evidence_sha256, justification):
        """Accept caller-confirmed raw bytes without issuing a transport call.

        ``evidence_sha256`` must already address these exact bytes in the
        caller's private Ledger. The audit justification confirms the operator
        established this response belongs to the reserved request. It is a
        caller assertion, not provider authentication.
        """
        with self._lock():
            self._assert_identity()
            nonce, evidence_sha256 = _label(nonce), _hash(evidence_sha256)
            if (type(justification) is not str or not 12 <= len(justification) <= 2048
                    or any(ord(char) < 32 for char in justification)):
                raise LearningTransportError("bounded explicit reconciliation justification required")
            _object(raw_response)
            if sha256(raw_response) != evidence_sha256 or self.ledger.get_evidence(evidence_sha256) != raw_response:
                raise LearningTransportError("reconciliation differs from confirmed raw evidence")
            directory = self.root / "attempts" / nonce
            reservation = self._reservation(directory)
            if reservation["nonce"] != nonce or reservation["binding_sha256"] != self._binding_sha256:
                raise LearningTransportError("reconciliation reservation binding differs")
            original = _object(self.ledger.get_evidence(reservation["request_sha256"]))
            rendered_nonce, payload, messages = self._payload(original, reservation["kind"])
            if (rendered_nonce != nonce or sha256(payload) != reservation["payload_sha256"]
                    or messages != reservation["message_evidence"]):
                raise LearningTransportError("reconciliation outbound request evidence differs")
            self._admit(raw_response, reservation)
            response_path = directory / "response.raw"
            if response_path.exists():
                _no_links(response_path, regular_file=True)
                if response_path.read_bytes() != raw_response:
                    raise LearningTransportError("completed raw response cannot be replaced")
            body = {"schema": "xnet.kimi-learning-transport-reconciliation.v1", "nonce": nonce,
                    "reservation_sha256": digest(reservation), "response_raw_sha256": evidence_sha256,
                    "justification": justification, "dispatch_repeated": False}
            audit_path = directory / "reconciliation.json"
            if audit_path.exists():
                if self._read_record(audit_path).get("body") != body:
                    raise LearningTransportError("conflicting reconciliation audit")
            else:
                event = make_event("learning-transport-" + nonce, self.scope_id, "learning-transport-reconciled",
                    {"record_sha256": self._seal(canonical(body), "learning-transport-reconciliation")},
                    source="learning-transport")
                self._write_record(audit_path, {"body": body, "event": event})
            stored = self._read_record(audit_path)
            # Support crash recovery between the audit file and event append.
            if set(stored) != {"body", "event"} or stored["body"] != body:
                raise LearningTransportError("reconciliation audit binding mismatch")
            self.ledger.append(stored["event"])
            if not response_path.exists():
                self._write_bytes(response_path, raw_response)
            return self._complete(directory, reservation, raw_response)
