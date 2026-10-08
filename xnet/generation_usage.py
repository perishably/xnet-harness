"""Explicit token-counter peer for caller-owned generation callbacks.

No transport, model, ledger or sealed-attempt mutation occurs here. Save the
provider's original response first, then apply this adapter before sealing a
new RepairLoop output. Missing counters are unknown, never zero.
"""
from __future__ import annotations

import copy
from typing import Callable

from .protocol import digest


class GenerationUsageError(ValueError):
    pass


ALIASES = {
    "input_tokens": ("input_tokens", "prompt_tokens"),
    "output_tokens": ("output_tokens", "completion_tokens"),
}


def _counter(value, field):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise GenerationUsageError(field + " must be a nonnegative exact portable integer")
    return value


def normalize_generation_usage(usage: dict) -> dict:
    """Copy usage and add canonical input/output counters; aliases must agree.

Provider metadata and original alias fields remain in the returned copy.
Both counters are mandatory. If a total is supplied it must equal their sum.
No counter is estimated from text, timings, the total, or an absent field.
"""
    if type(usage) is not dict:
        raise GenerationUsageError("usage must be an exact dictionary")
    normalized = copy.deepcopy(usage)
    for canonical_name, aliases in ALIASES.items():
        present = [alias for alias in aliases if alias in usage]
        if not present:
            raise GenerationUsageError("missing " + canonical_name + " evidence")
        values = [_counter(usage[alias], alias) for alias in present]
        if len(set(values)) != 1:
            raise GenerationUsageError("conflicting " + canonical_name + " aliases")
        normalized[canonical_name] = values[0]
    total = normalized["input_tokens"] + normalized["output_tokens"]
    if total > 2**63 - 1:
        raise GenerationUsageError("token total exceeds portable integer range")
    if "total_tokens" in usage and _counter(usage["total_tokens"], "total_tokens") != total:
        raise GenerationUsageError("total_tokens differs from input plus output")
    return normalized


def generation_usage_projection(usage: dict) -> dict:
    """Detached audit projection; hashes are canonical parsed-usage hashes.

These hashes do not pretend to identify the original HTTP response bytes.
The transport's separate raw-response digest remains the primary evidence.
"""
    normalized = normalize_generation_usage(usage)
    return {
        "schema": "xnet.generation-usage-projection.v1",
        "raw_usage_canonical_sha256": digest(usage),
        "normalized_usage_canonical_sha256": digest(normalized),
        "alias_sources": {key: [name for name in aliases if name in usage]
                          for key, aliases in ALIASES.items()},
        "normalized_usage": normalized,
        "estimated_counters": False,
    }


def generation_usage_callback(generate: Callable) -> Callable:
    """Opt-in composition for a newly pinned caller; never wraps old attempts.

The caller saves raw provider evidence within ``generate`` before it returns.
RepairLoop still checks model identity, its exact output contract and budgets.
"""
    if not callable(generate):
        raise GenerationUsageError("generate must be callable")

    def normalized_generate(request):
        result = generate(request)
        if type(result) is not dict or "usage" not in result:
            raise GenerationUsageError("generation result must contain usage")
        normalized = copy.deepcopy(result)
        normalized["usage"] = normalize_generation_usage(result["usage"])
        return normalized

    return normalized_generate
