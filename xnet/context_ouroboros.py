"""Bounded, signed context handoffs between fresh Jcode sessions.

The context Ouroboros is deliberately provider neutral.  It prepares and
verifies a compact replay capsule; a Jcode adapter is responsible for starting
the fresh session described by the emitted handoff manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .protocol import HEX64, canonical, digest, sha256


CAPSULE_SCHEMA = "xnet.context-capsule.v1"
HANDOFF_SCHEMA = "xnet.jcode-context-handoff.v1"
ADAPTER_CONTRACT = "xnet.jcode-fresh-session-adapter.v1"
LEGS = ("SWIM", "BIKE", "RUN")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_FORBIDDEN_KEYS = {
    "gold_patch",
    "test_patch",
    "solution",
    "solution_patch",
    "reference_patch",
    "expected_patch",
    "evaluator_private",
    "private_evaluator",
}
_FORBIDDEN_PATH_PARTS = {"evaluator-private", "evaluator_private"}
_FORBIDDEN_FILE_NAMES = {
    "gold.patch",
    "test.patch",
    "gold_patch",
    "test_patch",
    "gold-patch.diff",
    "test-patch.diff",
}


class ContextOuroborosError(ValueError):
    """Raised when a context capsule cannot be admitted safely."""


class JcodeHandoffAdapter(Protocol):
    """Contract for an external adapter that starts a fresh Jcode session.

    The core does not invoke Jcode or claim that a handoff ran.  An adapter
    receives a verified manifest and must return a result bound to the target
    session and capsule hashes.
    """

    def start_fresh_session(self, manifest: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class ContextPolicy:
    """Limits for one replay capsule and its source slices."""

    max_chars: int = 12_000
    max_estimated_tokens: int = 3_000
    max_slice_chars: int = 2_000
    max_lines_per_slice: int = 160
    max_slices: int = 12
    max_cycles: int = 6
    max_list_items: int = 12

    def validate(self) -> "ContextPolicy":
        integer_limits = (
            self.max_chars,
            self.max_estimated_tokens,
            self.max_slice_chars,
            self.max_lines_per_slice,
            self.max_slices,
            self.max_cycles,
            self.max_list_items,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_limits):
            raise ContextOuroborosError("context policy limits must be integers")
        if not 512 <= self.max_chars <= 131_072:
            raise ContextOuroborosError("max_chars must be 512..131072")
        if not 128 <= self.max_estimated_tokens <= 32_768:
            raise ContextOuroborosError("max_estimated_tokens must be 128..32768")
        if not 64 <= self.max_slice_chars <= self.max_chars:
            raise ContextOuroborosError("max_slice_chars must be 64..max_chars")
        if not 1 <= self.max_lines_per_slice <= 2_000:
            raise ContextOuroborosError("max_lines_per_slice must be 1..2000")
        if not 1 <= self.max_slices <= 64:
            raise ContextOuroborosError("max_slices must be 1..64")
        if not 1 <= self.max_cycles <= 32:
            raise ContextOuroborosError("max_cycles must be 1..32")
        if not 1 <= self.max_list_items <= 64:
            raise ContextOuroborosError("max_list_items must be 1..64")
        return self


@dataclass(frozen=True)
class SourceRequest:
    """A line-range request; the implementation never reads past ``end_line``."""

    path: Path
    start_line: int
    end_line: int


def estimated_tokens(value: Any) -> int:
    """Return a conservative tokenizer-independent estimate for JSON context."""

    raw = canonical(value)
    # Byte/4 is common for code and prose.  Whitespace-separated units protect
    # against unusually short token runs while retaining deterministic behavior.
    units = len(re.findall(rb"\S+", raw))
    return max(1, (len(raw) + 3) // 4, units)


def _validate_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ContextOuroborosError(f"invalid {name}")
    return value


def _portable(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int) and not isinstance(value, bool) and -(2**63) <= value <= 2**63 - 1:
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _portable(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContextOuroborosError(f"non-string field at {path}")
            normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
            if normalized in _FORBIDDEN_KEYS:
                raise ContextOuroborosError(f"evaluator-private field rejected: {key}")
            _portable(item, f"{path}.{key}")
        return
    raise ContextOuroborosError(f"non-portable value at {path}")


def _clean_text(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise ContextOuroborosError(f"{field} must be text")
    value = value.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ContextOuroborosError(f"{field} contains non-portable Unicode")
    return value.strip()


def _excerpt(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    marker = f"\n...[bounded sha256={sha256(text.encode('utf-8'))}]...\n"
    if limit <= len(marker) + 8:
        return marker[:limit], True
    remaining = limit - len(marker)
    left = (remaining + 1) // 2
    right = remaining - left
    return text[:left] + marker + (text[-right:] if right else ""), True


def _inside(path: Path, roots: Sequence[Path]) -> tuple[Path, str]:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ContextOuroborosError(f"source is not a regular file: {path}")
    for root in roots:
        candidate = root.expanduser().resolve(strict=True)
        try:
            relative = resolved.relative_to(candidate)
        except ValueError:
            continue
        parts = {part.lower() for part in relative.parts}
        lowered_name = relative.name.lower()
        if (
            parts & _FORBIDDEN_PATH_PARTS
            or lowered_name in _FORBIDDEN_FILE_NAMES
            or lowered_name.endswith((".gold.patch", ".test.patch"))
        ):
            raise ContextOuroborosError("evaluator-private source path rejected")
        return resolved, relative.as_posix()
    raise ContextOuroborosError(f"source path is outside allowed roots: {path}")


def _read_slice(request: SourceRequest, roots: Sequence[Path], policy: ContextPolicy) -> dict[str, Any]:
    if request.start_line < 1 or request.end_line < request.start_line:
        raise ContextOuroborosError("source line range must be positive and ordered")
    if request.end_line - request.start_line + 1 > policy.max_lines_per_slice:
        raise ContextOuroborosError("source line range exceeds max_lines_per_slice")
    path, source_id = _inside(Path(request.path), roots)
    selected: list[str] = []
    actual_end = request.start_line - 1
    # Stream only through the requested range and stop.  This avoids the
    # context-overflow failure mode caused by reading entire source files.
    with path.open("r", encoding="utf-8", errors="strict", newline=None) as source:
        for line_number, line in enumerate(source, start=1):
            if line_number < request.start_line:
                continue
            if line_number > request.end_line:
                break
            selected.append(line)
            actual_end = line_number
    if not selected:
        raise ContextOuroborosError(f"source range produced no lines: {source_id}")
    full_text = "".join(selected).rstrip("\n")
    text, truncated = _excerpt(full_text, policy.max_slice_chars)
    return {
        "source_id": source_id,
        "start_line": request.start_line,
        "end_line": actual_end,
        "requested_end_line": request.end_line,
        "selected_sha256": sha256(full_text.encode("utf-8")),
        "text": text,
        "text_truncated": truncated,
    }


def _measure(context: Mapping[str, Any]) -> tuple[int, int]:
    raw = canonical(context)
    return len(raw.decode("utf-8")), estimated_tokens(context)


def _replace_largest_text(context: dict[str, Any]) -> bool:
    candidates: list[tuple[int, tuple[Any, ...]]] = []
    for field in ("objective", "concise_state", "work_summary"):
        text = context[field]
        if isinstance(text, str) and len(text) > 24:
            candidates.append((len(text), (field,)))
    for index, item in enumerate(context["next_actions"]):
        if len(item) > 24:
            candidates.append((len(item), ("next_actions", index)))
    for index, item in enumerate(context["contradictions"]):
        text = item["statement"]
        if len(text) > 24:
            candidates.append((len(text), ("contradictions", index, "statement")))
    for index, item in enumerate(context["source_snippets"]):
        text = item["text"]
        if len(text) > 24:
            candidates.append((len(text), ("source_snippets", index, "text")))
    if not candidates:
        return False
    _, location = max(candidates, key=lambda row: (row[0], repr(row[1])))
    target: Any = context
    for part in location[:-1]:
        target = target[part]
    old = target[location[-1]]
    new_limit = max(24, int(len(old) * 0.72))
    target[location[-1]], _ = _excerpt(old, new_limit)
    if location[0] == "source_snippets":
        context["source_snippets"][location[1]]["text_truncated"] = True
    return True


def _normalize_contradictions(items: Sequence[Any], limit: int) -> tuple[list[dict[str, Any]], str, int]:
    normalized: list[dict[str, Any]] = []
    for item in items:
        _portable(item)
        if isinstance(item, str):
            statement = _clean_text(item, "contradiction")
            evidence_hashes: list[str] = []
        elif isinstance(item, dict):
            statement = _clean_text(str(item.get("statement", "")), "contradiction statement")
            evidence_hashes = list(item.get("evidence_hashes", []))
            if any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in evidence_hashes):
                raise ContextOuroborosError("contradiction evidence hash is invalid")
        else:
            raise ContextOuroborosError("contradictions must be text or objects")
        if not statement:
            raise ContextOuroborosError("contradiction statement may not be empty")
        normalized.append({"statement": statement, "evidence_hashes": sorted(set(evidence_hashes))})
    unique = {digest(item): item for item in normalized}
    ordered = [unique[key] for key in sorted(unique)]
    rollup = digest(ordered)
    omitted = max(0, len(ordered) - limit)
    return ordered[-limit:], rollup, omitted


def validate_triathlon_receipts(receipts: Sequence[Mapping[str, Any]], key: bytes) -> dict[str, Any]:
    """Validate signed SWIM -> BIKE -> RUN groups and fresh-cycle restarts."""

    if not receipts or len(receipts) % len(LEGS):
        raise ContextOuroborosError("triathlon receipts must contain complete SWIM/BIKE/RUN cycles")
    previous_hash = "0" * 64
    first_cycle = receipts[0].get("cycle_index") if isinstance(receipts[0], Mapping) else None
    if not isinstance(first_cycle, int) or isinstance(first_cycle, bool) or first_cycle < 1:
        raise ContextOuroborosError("invalid first receipt cycle_index")
    previous_cycle = first_cycle - 1
    previous_session = ""
    group_identity: tuple[Any, ...] | None = None
    previous_output = ""
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, Mapping):
            raise ContextOuroborosError("triathlon receipt must be an object")
        expected_leg = LEGS[index % len(LEGS)]
        if receipt.get("leg") != expected_leg:
            raise ContextOuroborosError("invalid triathlon leg transition")
        cycle = receipt.get("cycle_index")
        if not isinstance(cycle, int) or isinstance(cycle, bool) or cycle < 1:
            raise ContextOuroborosError("invalid receipt cycle_index")
        if expected_leg == "SWIM":
            if cycle != previous_cycle + 1:
                raise ContextOuroborosError("fresh cycle must increment at SWIM")
            if previous_session and receipt.get("parent_session_id") != previous_session:
                raise ContextOuroborosError("fresh-cycle parent session mismatch")
            previous_cycle = cycle
            previous_hash = "0" * 64
            previous_output = ""
            group_identity = (
                receipt.get("session_id"),
                receipt.get("parent_session_id"),
                receipt.get("provider_id"),
                receipt.get("model_id"),
                canonical(receipt.get("budget")),
            )
        elif cycle != previous_cycle:
            raise ContextOuroborosError("triathlon legs crossed cycle boundary")
        for field in ("session_id", "parent_session_id", "provider_id", "model_id", "input_sha256", "output_sha256"):
            if not isinstance(receipt.get(field), str) or not receipt[field]:
                raise ContextOuroborosError(f"receipt missing {field}")
        if not HEX64.fullmatch(receipt["input_sha256"]) or not HEX64.fullmatch(receipt["output_sha256"]):
            raise ContextOuroborosError("receipt input/output hash is invalid")
        if not isinstance(receipt.get("budget"), Mapping):
            raise ContextOuroborosError("receipt budget is missing")
        if receipt.get("schema_version") != "xnet.context-triathlon-receipt.v1":
            raise ContextOuroborosError("unsupported triathlon receipt")
        if receipt.get("ephemeral_session") is not True or receipt.get("leg_exit_required_after_persist") is not True:
            raise ContextOuroborosError("triathlon leg does not enforce ephemeral exit")
        identity = (
            receipt.get("session_id"),
            receipt.get("parent_session_id"),
            receipt.get("provider_id"),
            receipt.get("model_id"),
            canonical(receipt.get("budget")),
        )
        if identity != group_identity:
            raise ContextOuroborosError("triathlon identity changed within a cycle")
        if previous_output and receipt["input_sha256"] != previous_output:
            raise ContextOuroborosError("triathlon output/input continuity mismatch")
        if receipt.get("prev_receipt_sha256") != previous_hash:
            raise ContextOuroborosError("triathlon receipt chain mismatch")
        supplied_hash = receipt.get("receipt_sha256", "")
        supplied_signature = receipt.get("receipt_hmac_sha256", "")
        unsigned = {k: v for k, v in receipt.items() if k not in {"receipt_sha256", "receipt_hmac_sha256"}}
        expected_hash = digest(unsigned)
        if not isinstance(supplied_hash, str) or not hmac.compare_digest(supplied_hash, expected_hash):
            raise ContextOuroborosError("triathlon receipt hash mismatch")
        expected_signature = hmac.new(key, canonical({**unsigned, "receipt_sha256": expected_hash}), hashlib.sha256).hexdigest()
        if not isinstance(supplied_signature, str) or not hmac.compare_digest(supplied_signature, expected_signature):
            raise ContextOuroborosError("triathlon receipt signature mismatch")
        previous_hash = expected_hash
        previous_output = receipt["output_sha256"]
        if expected_leg == "RUN":
            previous_session = receipt["session_id"]
    return {"intact": True, "cycles": previous_cycle, "head": previous_hash, "session_id": previous_session}


class ContextOuroboros:
    """Create, persist, replay, and verify bounded Jcode context capsules."""

    def __init__(
        self,
        *,
        store_root: Path,
        allowed_roots: Sequence[Path],
        signing_key: bytes,
        task_id: str,
        scope_id: str,
        evaluator_continuity: Mapping[str, Any],
        policy: ContextPolicy | None = None,
    ) -> None:
        self.policy = (policy or ContextPolicy()).validate()
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ContextOuroborosError("signing key must contain at least 32 bytes")
        self.key = signing_key
        self.task_id = _validate_identifier("task_id", task_id)
        self.scope_id = _validate_identifier("scope_id", scope_id)
        if not allowed_roots:
            raise ContextOuroborosError("at least one allowed source root is required")
        self.allowed_roots = tuple(Path(root) for root in allowed_roots)
        for root in self.allowed_roots:
            if not root.expanduser().resolve(strict=True).is_dir():
                raise ContextOuroborosError(f"allowed root is not a directory: {root}")
        self.store_root = Path(store_root).expanduser().absolute()
        if self.store_root.name.lower() != "xnet":
            raise ContextOuroborosError("store_root must name a designated XNET directory")
        self.store_root.mkdir(parents=True, exist_ok=True)
        self.context_root = self.store_root / "context-ouroboros"
        self.cas_root = self.context_root / "cas" / "sha256"
        self.receipt_root = self.context_root / "receipts" / "sha256"
        self.manifest_root = self.context_root / "jcode-handoffs"
        self.cas_root.mkdir(parents=True, exist_ok=True)
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        self.manifest_root.mkdir(parents=True, exist_ok=True)
        continuity = dict(evaluator_continuity)
        _portable(continuity)
        if continuity.get("task_id") != self.task_id:
            raise ContextOuroborosError("evaluator continuity must bind the same task_id")
        self.evaluator_continuity = continuity
        self.evaluator_continuity_sha256 = digest(continuity)

    @property
    def budget(self) -> dict[str, int]:
        return {
            "max_chars": self.policy.max_chars,
            "max_estimated_tokens": self.policy.max_estimated_tokens,
            "max_slice_chars": self.policy.max_slice_chars,
            "max_lines_per_slice": self.policy.max_lines_per_slice,
            "max_slices": self.policy.max_slices,
            "max_cycles": self.policy.max_cycles,
        }

    def _fit_context(
        self,
        *,
        objective: str,
        concise_state: Any,
        work_output: str,
        next_actions: Sequence[str],
        contradictions: Sequence[Any],
        snippets: list[dict[str, Any]],
        original_input_sha256: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        _portable(concise_state)
        state_text = canonical(concise_state).decode("utf-8") if not isinstance(concise_state, str) else _clean_text(concise_state, "concise_state")
        actions = [_clean_text(item, "next action") for item in next_actions]
        if any(not item for item in actions):
            raise ContextOuroborosError("next action may not be empty")
        action_rollup = digest(actions)
        omitted_actions = max(0, len(actions) - self.policy.max_list_items)
        actions = actions[: self.policy.max_list_items]
        normalized_contradictions, contradiction_rollup, omitted_contradictions = _normalize_contradictions(
            contradictions, self.policy.max_list_items
        )
        context: dict[str, Any] = {
            "objective": _clean_text(objective, "objective"),
            "concise_state": state_text,
            "work_summary": _clean_text(work_output, "work_output"),
            "next_actions": actions,
            "next_action_rollup_sha256": action_rollup,
            "omitted_next_actions": omitted_actions,
            "contradictions": normalized_contradictions,
            "contradiction_rollup_sha256": contradiction_rollup,
            "omitted_contradictions": omitted_contradictions,
            "source_snippets": snippets,
            "original_input_sha256": original_input_sha256,
        }
        original_chars, original_tokens = _measure(context)
        compacted = False
        for _ in range(256):
            chars, tokens = _measure(context)
            if chars <= self.policy.max_chars and tokens <= self.policy.max_estimated_tokens:
                break
            compacted = True
            if not _replace_largest_text(context):
                raise ContextOuroborosError("context metadata alone exceeds configured budget")
        else:
            raise ContextOuroborosError("context could not be compacted within bounded iterations")
        used_chars, used_tokens = _measure(context)
        if used_chars > self.policy.max_chars or used_tokens > self.policy.max_estimated_tokens:
            raise ContextOuroborosError("bounded context invariant failed")
        return context, {
            **self.budget,
            "original_chars": original_chars,
            "original_estimated_tokens": original_tokens,
            "used_chars": used_chars,
            "used_estimated_tokens": used_tokens,
            "compacted": compacted,
        }

    def _session_id(
        self,
        *,
        parent_session_id: str,
        provider_id: str,
        model_id: str,
        cycle_index: int,
        input_sha256: str,
    ) -> str:
        seed = {
            "task_id": self.task_id,
            "parent_session_id": parent_session_id,
            "provider_id": provider_id,
            "model_id": model_id,
            "cycle_index": cycle_index,
            "input_sha256": input_sha256,
        }
        return "jcode-" + digest(seed)[:32]

    def _receipt(
        self,
        *,
        leg: str,
        cycle_index: int,
        session_id: str,
        parent_session_id: str,
        provider_id: str,
        model_id: str,
        budget: Mapping[str, Any],
        input_sha256: str,
        output_sha256: str,
        previous_hash: str,
    ) -> dict[str, Any]:
        if leg not in LEGS:
            raise ContextOuroborosError("invalid triathlon leg")
        unsigned = {
            "schema_version": "xnet.context-triathlon-receipt.v1",
            "leg": leg,
            "cycle_index": cycle_index,
            "session_id": session_id,
            "parent_session_id": parent_session_id,
            "provider_id": provider_id,
            "model_id": model_id,
            "ephemeral_session": True,
            "leg_exit_required_after_persist": True,
            "budget": dict(budget),
            "input_sha256": input_sha256,
            "output_sha256": output_sha256,
            "prev_receipt_sha256": previous_hash,
        }
        receipt_hash = digest(unsigned)
        signed = {**unsigned, "receipt_sha256": receipt_hash}
        return {**signed, "receipt_hmac_sha256": hmac.new(self.key, canonical(signed), hashlib.sha256).hexdigest()}

    def _build(
        self,
        *,
        objective: str,
        concise_state: Any,
        source_requests: Sequence[SourceRequest],
        parent_session_id: str,
        lineage: Sequence[str],
        cycle_index: int,
        provider_id: str,
        model_id: str,
        handoff_reason: str,
        work_output: str,
        next_actions: Sequence[str],
        contradictions: Sequence[Any],
        prior_capsule_sha256: str | None,
    ) -> dict[str, Any]:
        if cycle_index > self.policy.max_cycles:
            raise ContextOuroborosError("maximum context cycles reached; fail closed")
        parent_session_id = _validate_identifier("parent_session_id", parent_session_id)
        provider_id = _validate_identifier("provider_id", provider_id)
        model_id = _validate_identifier("model_id", model_id)
        handoff_reason = _clean_text(handoff_reason, "handoff_reason")
        if not handoff_reason or len(handoff_reason) > 512:
            raise ContextOuroborosError("handoff_reason must contain 1..512 characters")
        if len(source_requests) > self.policy.max_slices:
            raise ContextOuroborosError("source request count exceeds max_slices")
        if len(lineage) != cycle_index or lineage[-1] != parent_session_id or len(set(lineage)) != len(lineage):
            raise ContextOuroborosError("invalid or cyclic Jcode session lineage")
        snippets = [_read_slice(request, self.allowed_roots, self.policy) for request in source_requests]
        intake = {
            "task_id": self.task_id,
            "scope_id": self.scope_id,
            "objective": objective,
            "concise_state": concise_state,
            "work_output": work_output,
            "next_actions": list(next_actions),
            "contradictions": list(contradictions),
            "source_slices": [
                {key: value for key, value in item.items() if key != "text"}
                for item in snippets
            ],
            "parent_session_id": parent_session_id,
            "cycle_index": cycle_index,
            "prior_capsule_sha256": prior_capsule_sha256,
            "evaluator_continuity_sha256": self.evaluator_continuity_sha256,
        }
        _portable(intake)
        input_sha256 = digest(intake)
        context, budget = self._fit_context(
            objective=objective,
            concise_state=concise_state,
            work_output=work_output,
            next_actions=next_actions,
            contradictions=contradictions,
            snippets=snippets,
            original_input_sha256=input_sha256,
        )
        context_sha256 = digest(context)
        session_id = self._session_id(
            parent_session_id=parent_session_id,
            provider_id=provider_id,
            model_id=model_id,
            cycle_index=cycle_index,
            input_sha256=input_sha256,
        )
        if session_id in lineage:
            raise ContextOuroborosError("Jcode handoff would create a session cycle")
        swim_output = digest({"source_snippets": snippets, "input_sha256": input_sha256})
        bike_output = context_sha256
        run_output = digest(
            {
                "context_sha256": context_sha256,
                "session_id": session_id,
                "evaluator_continuity_sha256": self.evaluator_continuity_sha256,
            }
        )
        receipts: list[dict[str, Any]] = []
        previous = "0" * 64
        for leg, leg_input, leg_output in (
            ("SWIM", input_sha256, swim_output),
            ("BIKE", swim_output, bike_output),
            ("RUN", bike_output, run_output),
        ):
            receipt = self._receipt(
                leg=leg,
                cycle_index=cycle_index,
                session_id=session_id,
                parent_session_id=parent_session_id,
                provider_id=provider_id,
                model_id=model_id,
                budget=budget,
                input_sha256=leg_input,
                output_sha256=leg_output,
                previous_hash=previous,
            )
            receipts.append(receipt)
            previous = receipt["receipt_sha256"]
        body = {
            "schema_version": CAPSULE_SCHEMA,
            "leg": "RUN",
            "status": "closed",
            "task_id": self.task_id,
            "scope_id": self.scope_id,
            "cycle_index": cycle_index,
            "session_id": session_id,
            "parent_session_id": parent_session_id,
            "lineage": list(lineage),
            "provider_id": provider_id,
            "model_id": model_id,
            "ephemeral_session": True,
            "history_dependency": "verified-replay-context-only",
            "handoff_reason": handoff_reason,
            "budget": budget,
            "input_sha256": input_sha256,
            "output_sha256": run_output,
            "prior_capsule_sha256": prior_capsule_sha256,
            "evaluator_continuity": self.evaluator_continuity,
            "evaluator_continuity_sha256": self.evaluator_continuity_sha256,
            "replay_context": context,
            "replay_context_sha256": context_sha256,
            "triathlon_receipts": receipts,
            "lifecycle_events": [
                {
                    "event": "exit",
                    "session_id": parent_session_id,
                    "output_sha256": run_output,
                    "adapter_state": "required-after-persist",
                },
                {
                    "event": "handoff",
                    "session_id": session_id,
                    "parent_session_id": parent_session_id,
                    "input_sha256": input_sha256,
                    "output_sha256": run_output,
                    "adapter_state": "signed-capsule-ready",
                },
                {
                    "event": "restart",
                    "session_id": session_id,
                    "parent_session_id": parent_session_id,
                    "replay_context_sha256": context_sha256,
                    "adapter_state": "fresh-session-required",
                },
            ],
        }
        _portable(body)
        capsule_hash = digest(body)
        capsule = {
            "body": body,
            "capsule_sha256": capsule_hash,
            "capsule_hmac_sha256": hmac.new(self.key, canonical({"body": body, "capsule_sha256": capsule_hash}), hashlib.sha256).hexdigest(),
        }
        return capsule

    def _persist(self, capsule: Mapping[str, Any]) -> tuple[Path, Path, dict[str, Any]]:
        capsule_hash = str(capsule["capsule_sha256"])
        body = capsule["body"]
        receipt_pointers: list[dict[str, str]] = []
        for receipt in body["triathlon_receipts"]:
            receipt_hash = receipt["receipt_sha256"]
            receipt_raw = canonical(receipt) + b"\n"
            receipt_path = self.receipt_root / receipt_hash[:2] / f"{receipt_hash}.json"
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            if receipt_path.exists():
                if receipt_path.read_bytes() != receipt_raw:
                    raise ContextOuroborosError("content-addressed triathlon receipt conflict")
            else:
                receipt_path.write_bytes(receipt_raw)
            receipt_pointers.append(
                {
                    "leg": receipt["leg"],
                    "receipt_sha256": receipt_hash,
                    "receipt_path": receipt_path.relative_to(self.store_root).as_posix(),
                }
            )
        raw = canonical(capsule) + b"\n"
        destination = self.cas_root / capsule_hash[:2] / f"{capsule_hash}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.read_bytes() != raw:
                raise ContextOuroborosError("content-addressed capsule conflict")
        else:
            descriptor, temporary = tempfile.mkstemp(prefix=".capsule-", dir=destination.parent)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, destination)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        relative_capsule = destination.relative_to(self.store_root).as_posix()
        manifest_unsigned = {
            "schema_version": HANDOFF_SCHEMA,
            "adapter_contract": ADAPTER_CONTRACT,
            "execution_status": "not-executed",
            "action": "start-fresh-jcode-session",
            "leg": body["leg"],
            "session_id": body["session_id"],
            "parent_session_id": body["parent_session_id"],
            "lineage": body["lineage"],
            "provider_id": body["provider_id"],
            "model_id": body["model_id"],
            "ephemeral_session": True,
            "history_dependency": "verified-replay-context-only",
            "handoff_reason": body["handoff_reason"],
            "budget": body["budget"],
            "input_sha256": body["input_sha256"],
            "output_sha256": body["output_sha256"],
            "evaluator_continuity": body["evaluator_continuity"],
            "evaluator_continuity_sha256": body["evaluator_continuity_sha256"],
            "capsule_sha256": capsule_hash,
            "capsule_path": relative_capsule,
            "triathlon_receipts": receipt_pointers,
            "adapter_requirements": {
                "fresh_session_required": True,
                "source_session_exit_after_persist": True,
                "old_in_process_history_forbidden": True,
                "verify_capsule_before_replay": True,
                "bind_result_to_session_id": True,
                "bind_result_to_output_sha256": True,
                "network_required": False,
            },
        }
        manifest_hash = digest(manifest_unsigned)
        manifest_signed = {**manifest_unsigned, "manifest_sha256": manifest_hash}
        manifest = {
            **manifest_signed,
            "manifest_hmac_sha256": hmac.new(self.key, canonical(manifest_signed), hashlib.sha256).hexdigest(),
        }
        manifest_raw = canonical(manifest) + b"\n"
        manifest_path = self.manifest_root / f"{body['cycle_index']:02d}-{capsule_hash}.json"
        if manifest_path.exists() and manifest_path.read_bytes() != manifest_raw:
            raise ContextOuroborosError("Jcode handoff manifest conflict")
        manifest_path.write_bytes(manifest_raw)
        # Replay from disk immediately; no in-memory object is trusted at close.
        verified = self.verify_file(destination)
        if verified["capsule_sha256"] != capsule_hash:
            raise ContextOuroborosError("persisted capsule replay mismatch")
        return destination, manifest_path, manifest

    def start(
        self,
        *,
        objective: str,
        concise_state: Any,
        source_session_id: str,
        provider_id: str,
        model_id: str,
        source_requests: Sequence[SourceRequest] = (),
        work_output: str = "",
        next_actions: Sequence[str] = (),
        contradictions: Sequence[Any] = (),
        handoff_reason: str | None = None,
    ) -> dict[str, Any]:
        reason = handoff_reason or "bounded-context-continuation"
        capsule = self._build(
            objective=objective,
            concise_state=concise_state,
            source_requests=source_requests,
            parent_session_id=source_session_id,
            lineage=[source_session_id],
            cycle_index=1,
            provider_id=provider_id,
            model_id=model_id,
            handoff_reason=reason,
            work_output=work_output,
            next_actions=next_actions,
            contradictions=contradictions,
            prior_capsule_sha256=None,
        )
        capsule_path, manifest_path, manifest = self._persist(capsule)
        return {
            "capsule": capsule,
            "capsule_path": str(capsule_path),
            "handoff_manifest": manifest,
            "handoff_manifest_path": str(manifest_path),
            "cycles": 1,
            "compacted": capsule["body"]["budget"]["compacted"],
        }

    def handoff(
        self,
        previous_capsule: Path,
        *,
        work_output: str,
        concise_state: Any | None = None,
        objective: str | None = None,
        provider_id: str | None = None,
        model_id: str | None = None,
        source_requests: Sequence[SourceRequest] = (),
        next_actions: Sequence[str] = (),
        contradictions: Sequence[Any] = (),
        handoff_reason: str = "context-window-renewal",
    ) -> dict[str, Any]:
        previous = self.verify_file(previous_capsule)
        body = previous["body"]
        if body["task_id"] != self.task_id or body["scope_id"] != self.scope_id:
            raise ContextOuroborosError("previous capsule task/scope mismatch")
        if body["evaluator_continuity_sha256"] != self.evaluator_continuity_sha256:
            raise ContextOuroborosError("evaluator continuity changed across handoff")
        cycle_index = body["cycle_index"] + 1
        if cycle_index > self.policy.max_cycles:
            raise ContextOuroborosError("maximum context cycles reached; fail closed")
        parent = body["session_id"]
        lineage = [*body["lineage"], parent]
        prior_context = body["replay_context"]
        inherited_contradictions = list(prior_context["contradictions"])
        capsule = self._build(
            objective=objective if objective is not None else prior_context["objective"],
            concise_state=concise_state if concise_state is not None else prior_context["concise_state"],
            source_requests=source_requests,
            parent_session_id=parent,
            lineage=lineage,
            cycle_index=cycle_index,
            provider_id=provider_id or body["provider_id"],
            model_id=model_id or body["model_id"],
            handoff_reason=handoff_reason,
            work_output=work_output,
            next_actions=next_actions,
            contradictions=[*inherited_contradictions, *contradictions],
            prior_capsule_sha256=previous["capsule_sha256"],
        )
        capsule_path, manifest_path, manifest = self._persist(capsule)
        return {
            "capsule": capsule,
            "capsule_path": str(capsule_path),
            "handoff_manifest": manifest,
            "handoff_manifest_path": str(manifest_path),
            "cycles": cycle_index,
            "compacted": capsule["body"]["budget"]["compacted"],
        }

    def verify_file(self, path: Path) -> dict[str, Any]:
        candidate = Path(path).expanduser().resolve(strict=True)
        try:
            candidate.relative_to(self.context_root.resolve(strict=True))
        except ValueError as exc:
            raise ContextOuroborosError("capsule path is outside the designated context store") from exc
        try:
            capsule = json.loads(candidate.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ContextOuroborosError("capsule is not canonical JSON") from exc
        return self.verify_capsule(capsule)

    def verify_manifest_file(self, path: Path) -> dict[str, Any]:
        candidate = Path(path).expanduser().resolve(strict=True)
        try:
            candidate.relative_to(self.manifest_root.resolve(strict=True))
        except ValueError as exc:
            raise ContextOuroborosError("handoff manifest is outside the designated manifest store") from exc
        try:
            manifest = json.loads(candidate.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ContextOuroborosError("handoff manifest is not JSON") from exc
        if not isinstance(manifest, dict):
            raise ContextOuroborosError("handoff manifest must be an object")
        _portable(manifest)
        supplied_signature = manifest.get("manifest_hmac_sha256", "")
        supplied_hash = manifest.get("manifest_sha256", "")
        unsigned = {key: value for key, value in manifest.items() if key not in {"manifest_sha256", "manifest_hmac_sha256"}}
        expected_hash = digest(unsigned)
        if not isinstance(supplied_hash, str) or not hmac.compare_digest(supplied_hash, expected_hash):
            raise ContextOuroborosError("handoff manifest hash mismatch")
        signed = {**unsigned, "manifest_sha256": expected_hash}
        expected_signature = hmac.new(self.key, canonical(signed), hashlib.sha256).hexdigest()
        if not isinstance(supplied_signature, str) or not hmac.compare_digest(supplied_signature, expected_signature):
            raise ContextOuroborosError("handoff manifest signature mismatch")
        if manifest.get("schema_version") != HANDOFF_SCHEMA or manifest.get("adapter_contract") != ADAPTER_CONTRACT:
            raise ContextOuroborosError("unsupported Jcode handoff manifest")
        if manifest.get("execution_status") != "not-executed" or manifest.get("ephemeral_session") is not True:
            raise ContextOuroborosError("handoff manifest overstates execution or persistence")
        capsule_path = self.store_root / str(manifest.get("capsule_path", ""))
        capsule = self.verify_file(capsule_path)
        if capsule["capsule_sha256"] != manifest.get("capsule_sha256"):
            raise ContextOuroborosError("handoff manifest capsule binding mismatch")
        body = capsule["body"]
        for field in ("session_id", "parent_session_id", "provider_id", "model_id", "input_sha256", "output_sha256"):
            if manifest.get(field) != body.get(field):
                raise ContextOuroborosError(f"handoff manifest {field} binding mismatch")
        pointers = manifest.get("triathlon_receipts")
        if not isinstance(pointers, list) or len(pointers) != len(LEGS):
            raise ContextOuroborosError("handoff manifest receipt pointers are incomplete")
        for pointer, receipt in zip(pointers, body["triathlon_receipts"], strict=True):
            if pointer.get("leg") != receipt["leg"] or pointer.get("receipt_sha256") != receipt["receipt_sha256"]:
                raise ContextOuroborosError("handoff manifest receipt binding mismatch")
            receipt_path = (self.store_root / str(pointer.get("receipt_path", ""))).resolve(strict=True)
            try:
                receipt_path.relative_to(self.receipt_root.resolve(strict=True))
            except ValueError as exc:
                raise ContextOuroborosError("triathlon receipt path escaped the receipt store") from exc
            persisted_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if canonical(persisted_receipt) != canonical(receipt):
                raise ContextOuroborosError("persisted triathlon receipt mismatch")
        return manifest

    def verify_capsule(self, capsule: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(capsule, Mapping) or set(capsule) != {"body", "capsule_sha256", "capsule_hmac_sha256"}:
            raise ContextOuroborosError("invalid capsule envelope")
        body = capsule.get("body")
        if not isinstance(body, dict):
            raise ContextOuroborosError("capsule body must be an object")
        _portable(body)
        if body.get("schema_version") != CAPSULE_SCHEMA or body.get("leg") != "RUN" or body.get("status") != "closed":
            raise ContextOuroborosError("unsupported or incomplete capsule")
        if body.get("ephemeral_session") is not True or body.get("history_dependency") != "verified-replay-context-only":
            raise ContextOuroborosError("capsule does not enforce ephemeral replay")
        supplied_hash = capsule.get("capsule_sha256", "")
        expected_hash = digest(body)
        if not isinstance(supplied_hash, str) or not hmac.compare_digest(supplied_hash, expected_hash):
            raise ContextOuroborosError("capsule hash mismatch")
        signed = {"body": body, "capsule_sha256": expected_hash}
        expected_signature = hmac.new(self.key, canonical(signed), hashlib.sha256).hexdigest()
        supplied_signature = capsule.get("capsule_hmac_sha256", "")
        if not isinstance(supplied_signature, str) or not hmac.compare_digest(supplied_signature, expected_signature):
            raise ContextOuroborosError("capsule signature mismatch")
        if body.get("task_id") != self.task_id or body.get("scope_id") != self.scope_id:
            raise ContextOuroborosError("capsule task/scope binding mismatch")
        if digest(body.get("evaluator_continuity")) != body.get("evaluator_continuity_sha256"):
            raise ContextOuroborosError("evaluator continuity hash mismatch")
        if body.get("evaluator_continuity_sha256") != self.evaluator_continuity_sha256:
            raise ContextOuroborosError("evaluator continuity does not match this loop")
        context = body.get("replay_context")
        if not isinstance(context, dict) or digest(context) != body.get("replay_context_sha256"):
            raise ContextOuroborosError("replay context hash mismatch")
        chars, tokens = _measure(context)
        budget = body.get("budget")
        if not isinstance(budget, dict):
            raise ContextOuroborosError("capsule budget missing")
        for field in ("used_chars", "used_estimated_tokens", "max_chars", "max_estimated_tokens"):
            if not isinstance(budget.get(field), int) or isinstance(budget[field], bool) or budget[field] < 0:
                raise ContextOuroborosError(f"invalid capsule budget field: {field}")
        if chars != budget.get("used_chars") or tokens != budget.get("used_estimated_tokens"):
            raise ContextOuroborosError("capsule budget measurement mismatch")
        if chars > budget.get("max_chars", -1) or tokens > budget.get("max_estimated_tokens", -1):
            raise ContextOuroborosError("capsule exceeds replay budget")
        if chars > self.policy.max_chars or tokens > self.policy.max_estimated_tokens:
            raise ContextOuroborosError("capsule exceeds the verifier's local replay policy")
        cycle = body.get("cycle_index")
        lineage = body.get("lineage")
        if not isinstance(cycle, int) or isinstance(cycle, bool) or not 1 <= cycle <= self.policy.max_cycles:
            raise ContextOuroborosError("capsule cycle is outside policy")
        if not isinstance(lineage, list) or len(lineage) != cycle or len(set(lineage)) != len(lineage):
            raise ContextOuroborosError("capsule lineage is invalid or cyclic")
        if lineage[-1] != body.get("parent_session_id") or body.get("session_id") in lineage:
            raise ContextOuroborosError("capsule session lineage does not close safely")
        checked = validate_triathlon_receipts(body.get("triathlon_receipts", []), self.key)
        if checked["cycles"] != cycle or checked["session_id"] != body.get("session_id"):
            raise ContextOuroborosError("triathlon receipt lineage mismatch")
        if body["triathlon_receipts"][-1]["output_sha256"] != body.get("output_sha256"):
            raise ContextOuroborosError("RUN receipt does not bind capsule output")
        for receipt in body["triathlon_receipts"]:
            for field in ("session_id", "parent_session_id", "provider_id", "model_id"):
                if receipt[field] != body[field]:
                    raise ContextOuroborosError(f"triathlon receipt {field} does not match capsule")
        lifecycle = body.get("lifecycle_events")
        if not isinstance(lifecycle, list) or [row.get("event") for row in lifecycle if isinstance(row, dict)] != ["exit", "handoff", "restart"]:
            raise ContextOuroborosError("ephemeral session lifecycle is incomplete")
        if lifecycle[0].get("session_id") != body["parent_session_id"]:
            raise ContextOuroborosError("exit event is not bound to the source session")
        if any(row.get("session_id") != body["session_id"] for row in lifecycle[1:]):
            raise ContextOuroborosError("handoff/restart event is not bound to the fresh session")
        return dict(capsule)


def _load_key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) < 32:
        raise ContextOuroborosError("key file must contain at least 32 bytes")
    return key


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="Create or verify bounded XNET Jcode context capsules")
    subcommands = command.add_subparsers(dest="command", required=True)
    start = subcommands.add_parser("start", help="create a first fresh-session handoff from a JSON spec")
    start.add_argument("--spec", type=Path, required=True)
    start.add_argument("--key-file", type=Path, required=True)
    start.add_argument("--store-root", type=Path, required=True)
    start.add_argument("--allowed-root", type=Path, action="append", required=True)
    verify = subcommands.add_parser("verify", help="verify a persisted capsule against a JSON spec")
    verify.add_argument("--spec", type=Path, required=True)
    verify.add_argument("--key-file", type=Path, required=True)
    verify.add_argument("--store-root", type=Path, required=True)
    verify.add_argument("--allowed-root", type=Path, action="append", required=True)
    verify.add_argument("capsule", type=Path)
    return command


def _loop_from_spec(args: argparse.Namespace, spec: Mapping[str, Any]) -> ContextOuroboros:
    raw_policy = spec.get("policy", {})
    if not isinstance(raw_policy, dict):
        raise ContextOuroborosError("spec policy must be an object")
    return ContextOuroboros(
        store_root=args.store_root,
        allowed_roots=args.allowed_root,
        signing_key=_load_key(args.key_file),
        task_id=spec["task_id"],
        scope_id=spec["scope_id"],
        evaluator_continuity=spec["evaluator_continuity"],
        policy=ContextPolicy(**raw_policy),
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        spec = json.loads(args.spec.read_text(encoding="utf-8"))
        if not isinstance(spec, dict):
            raise ContextOuroborosError("spec must be an object")
        loop = _loop_from_spec(args, spec)
        if args.command == "verify":
            verified = loop.verify_file(args.capsule)
            result = {
                "valid": True,
                "capsule_sha256": verified["capsule_sha256"],
                "session_id": verified["body"]["session_id"],
                "cycle_index": verified["body"]["cycle_index"],
            }
        else:
            requests = [
                SourceRequest(Path(item["path"]), int(item["start_line"]), int(item["end_line"]))
                for item in spec.get("source_requests", [])
            ]
            created = loop.start(
                objective=spec["objective"],
                concise_state=spec.get("concise_state", {}),
                source_session_id=spec["source_session_id"],
                provider_id=spec["provider_id"],
                model_id=spec["model_id"],
                source_requests=requests,
                work_output=spec.get("work_output", ""),
                next_actions=spec.get("next_actions", []),
                contradictions=spec.get("contradictions", []),
                handoff_reason=spec.get("handoff_reason"),
            )
            result = {
                "capsule_path": created["capsule_path"],
                "capsule_sha256": created["capsule"]["capsule_sha256"],
                "handoff_manifest_path": created["handoff_manifest_path"],
                "session_id": created["capsule"]["body"]["session_id"],
                "compacted": created["compacted"],
            }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ContextOuroborosError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"XNET Context Ouroboros error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
