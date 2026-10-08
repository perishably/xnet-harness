"""Finite authored repair practice; public tasks and host grading stay separate.

These small fixtures are not repository benchmarks or semantic novelty proof.
Source is inert data for the existing bounded AST evaluator. A caller must keep
``private_selection`` results out of every model request and public export.
The separation here is a data API, not a filesystem or process access boundary.
"""
from __future__ import annotations

import copy
from pathlib import Path
import unicodedata

from .protocol import canonical, digest, sha256
from .swe_repair_suite import public_task


SCHEMA = "xnet.dojo-curriculum.v1"
SELECTION_SCHEMA = "xnet.dojo-selection.v1"
VERSION = "authored-repairs-20261006-v1"
SPLITS = ("practice", "validation", "unseen")


class DojoCurriculumError(ValueError):
    pass


def content_identity(task):
    """Match learning_dataset's label-free exact/normalized content identities."""
    value = copy.deepcopy(task)
    value.pop("task_id")
    for case in value["public_cases"]:
        case.pop("case_id")

    def normalize(item):
        if type(item) is str:
            return " ".join(unicodedata.normalize("NFKC", item).casefold().split())
        if type(item) is list:
            return [normalize(part) for part in item]
        if type(item) is dict:
            return {key: normalize(part) for key, part in item.items()}
        return item

    return {"content_sha256": digest(value), "normalized_content_sha256": digest(normalize(value))}


def _pins():
    root = Path(__file__).parent
    return {name: sha256((root / name).read_bytes()) for name in
            ("dojo_curriculum.py", "protocol.py", "swe_repair_suite.py")}


def _specs():
    # Each tuple: family, near-duplicate group, signature, contract, faulty/fixed
    # helper source, and independently authored F2P/P2P input/expectation pairs.
    # Variants change the public examples, never their declared family/group.
    return [
        ("capped-total", "capped-total", "run(values, cap)",
         "Return min(sum(values), cap). values and cap are nonnegative integers.",
         "def compute(values, cap):\n    return sum(values)\n",
         "def compute(values, cap):\n    return min(sum(values), cap)\n",
         [([[4, 7], 8], 8), ([[9, 8], 10], 10), ([[2, 5], 4], 4)],
         [([[2, 3], 9], 5), ([[], 7], 0), ([[1, 2], 3], 3)]),
        ("ceiling-packs", "ceiling-packs", "run(amount, size)",
         "Return the least integer number of size-unit packs covering nonnegative amount; size is positive.",
         "def compute(amount, size):\n    return amount // size\n",
         "def compute(amount, size):\n    return (amount + size - 1) // size\n",
         [([7, 3], 3), ([1, 4], 1), ([11, 5], 3)],
         [([6, 3], 2), ([0, 4], 0), ([15, 5], 3)]),
        ("expiry-boundary", "expiry-boundary", "run(rows, now)",
         "rows are [quantity, expiry] pairs. Sum quantities only when expiry is strictly greater than now.",
         "def compute(rows, now):\n    return sum(q for q, expiry in rows if expiry >= now)\n",
         "def compute(rows, now):\n    return sum(q for q, expiry in rows if expiry > now)\n",
         [([[[4, 5]], 5], 0), ([[[2, 7], [3, 8]], 7], 3), ([[[9, 0]], 0], 0)],
         [([[[4, 6]], 5], 4), ([[], 9], 0), ([[[2, 1], [3, 7]], 5], 3)]),
        ("coupon-threshold", "coupon-threshold", "run(total, minimum, discount)",
         "Apply discount when total is at least minimum and clamp the result to zero. Inputs are nonnegative cents.",
         "def compute(total, minimum, discount):\n    return max(0, total - discount) if total > minimum else total\n",
         "def compute(total, minimum, discount):\n    return max(0, total - discount) if total >= minimum else total\n",
         [([100, 100, 20], 80), ([40, 40, 60], 0), ([7, 7, 3], 4)],
         [([120, 100, 20], 100), ([50, 100, 20], 50), ([0, 4, 9], 0)]),
        ("remaining-credit", "remaining-credit", "run(lines, credits, requested)",
         "Return min(requested, max(0, sum(lines)-sum(credits))). Inputs are nonnegative cents.",
         "def compute(lines, credits, requested):\n    return min(requested, max(0, sum(lines)))\n",
         "def compute(lines, credits, requested):\n    return min(requested, max(0, sum(lines) - sum(credits)))\n",
         [([[100], [40], 80], 60), ([[30, 20], [60], 10], 0), ([[80, 40], [30, 20], 100], 70)],
         [([[100], [], 80], 80), ([[], [], 10], 0), ([[100], [20], 10], 10)]),
        ("stable-unique", "stable-membership", "run(values)",
         "Return each integer's first occurrence in input order, without duplicates.",
         "def compute(values):\n    return sorted(set(values))\n",
         "def compute(values):\n    result = []\n    for value in values:\n        if value not in result:\n            result.append(value)\n    return result\n",
         [([[3, 1, 3, 2]], [3, 1, 2]), ([[8, 2, 8]], [8, 2]), ([[4, -1]], [4, -1])],
         [([[1, 2, 2, 3]], [1, 2, 3]), ([[]], []), ([[7, 7]], [7])]),
        ("prefix-before-stop", "prefix-before-stop", "run(values, stop)",
         "Return the prefix strictly before the first occurrence of stop; return all values when stop is absent.",
         "def compute(values, stop):\n    return [value for value in values if value != stop]\n",
         "def compute(values, stop):\n    result = []\n    for value in values:\n        if value == stop:\n            break\n        result.append(value)\n    return result\n",
         [([[1, 0, 2], 0], [1]), ([[9, 2], 9], []), ([[4, 7, 8], 7], [4])],
         [([[1, 2, 0], 0], [1, 2]), ([[], 4], []), ([[1, 2], 8], [1, 2])]),
        ("longest-positive-run", "longest-positive-run", "run(values)",
         "Return the length of the longest contiguous run of strictly positive integers; empty input returns zero.",
         "def compute(values):\n    return sum(1 for value in values if value > 0)\n",
         "def compute(values):\n    longest = 0\n    current = 0\n    for value in values:\n        current = current + 1 if value > 0 else 0\n        longest = max(longest, current)\n    return longest\n",
         [([[1, 0, 2]], 1), ([[1, 2, -1, 3]], 2), ([[2, 0, 3, 4, 0, 5]], 2)],
         [([[1, 2, 3]], 3), ([[]], 0), ([[-1, 0]], 0)]),
        ("grouped-totals", "grouped-totals", "run(rows)",
         "rows are [string-key, integer-amount] pairs. Return a dictionary summing all amounts for each key.",
         "def compute(rows):\n    result = {}\n    for key, amount in rows:\n        result[key] = amount\n    return result\n",
         "def compute(rows):\n    result = {}\n    for key, amount in rows:\n        result[key] = result.get(key, 0) + amount\n    return result\n",
         [([[["a", 2], ["a", 3]]], {"a": 5}), ([[["x", 4], ["y", 2], ["x", -1]]], {"x": 3, "y": 2}), ([[["k", 1], ["k", 2], ["k", 3]]], {"k": 6})],
         [([[["a", 2], ["b", 3]]], {"a": 2, "b": 3}), ([[]], {}), ([[["x", -2]]], {"x": -2})]),
        ("strict-overlap", "strict-overlap", "run(left, right)",
         "left/right are [start,end] integer half-open intervals with start<end. Return whether their intersection has positive length; touching is false.",
         "def compute(left, right):\n    return left[0] <= right[1] and right[0] <= left[1]\n",
         "def compute(left, right):\n    return left[0] < right[1] and right[0] < left[1]\n",
         [([[1, 3], [3, 7]], False), ([[4, 8], [1, 4]], False), ([[-2, 0], [0, 1]], False)],
         [([[1, 4], [2, 5]], True), ([[1, 2], [4, 5]], False), ([[1, 5], [2, 3]], True)]),
        ("ordered-intersection", "stable-membership", "run(left, right)",
         "Return distinct integer values present in both lists, in first-occurrence order from left.",
         "def compute(left, right):\n    return sorted(set(left) & set(right))\n",
         "def compute(left, right):\n    result = []\n    for value in left:\n        if value in right and value not in result:\n            result.append(value)\n    return result\n",
         [([[4, 1, 4, 2], [1, 4]], [4, 1]), ([[8, 3], [3, 8]], [8, 3]), ([[5, -2], [-2, 5]], [5, -2])],
         [([[1, 2, 2], [2, 1]], [1, 2]), ([[], [1]], []), ([[3, 2], [2]], [2])]),
        ("complete-windows", "complete-windows", "run(values, width)",
         "For positive width, return sums of every complete contiguous width-element window, in order; no complete window returns [].",
         "def compute(values, width):\n    return [sum(values[i:i + width]) for i in range(max(0, len(values) - width))]\n",
         "def compute(values, width):\n    return [sum(values[i:i + width]) for i in range(max(0, len(values) - width + 1))]\n",
         [([[1, 2, 3], 2], [3, 5]), ([[4, 5], 2], [9]), ([[2, 3, 4], 1], [2, 3, 4])],
         [([[1], 2], []), ([[], 1], []), ([[1, 2], 3], [])]),
    ]


def _originals():
    tasks, references, identities = [], {}, {}
    for family, cluster, signature, requirements, faulty, fixed, failures, passes in _specs():
        parameters = signature[4:-1]
        api = "from helpers import compute\ndef run(" + parameters + "):\n    return compute(" + parameters + ")\n"
        for variant in range(2):
            task_id = "dojo--" + family + "--v" + str(variant + 1)
            def cases(pairs, kind, hidden):
                return [{"args": copy.deepcopy(args), "kwargs": {}, "expected": copy.deepcopy(expected),
                         "case_type": kind, "case_id": task_id + "-" + ("h" if hidden else "p") + kind + str(i),
                         "name": "run", "hidden": hidden} for i, (args, expected) in enumerate(pairs)]
            public = cases([failures[variant]], "F2P", False) + cases([passes[variant]], "P2P", False)
            hidden = cases([item for i, item in enumerate(failures) if i != variant], "F2P", True)
            hidden += cases([item for i, item in enumerate(passes) if i != variant], "P2P", True)
            task = {"task_id": task_id, "category": "local-authored-repair", "issue":
                    "Repair " + family + "; public example variant " + str(variant + 1) + ". Preserve the declared API.",
                    "files": {"helpers.py": faulty, "api.py": api}, "entry_file": "api.py", "entry_function": "run",
                    "editable_files": ["helpers.py", "api.py"], "api_contract": {"signature": signature,
                    "requirements": requirements, "dependencies": "Only supplied local modules and Python builtins.",
                    "replacement_limit_bytes": 8192}, "public_cases": public, "hidden_cases": hidden,
                    "fixture_version": VERSION, "case_rationale": "Authored contract cases, not model-generated grades."}
            tasks.append(task)
            references[task_id] = {"helpers.py": fixed, "api.py": api}
            identities[task_id] = {"family_id": family, "near_duplicate_id": cluster}
    return tasks, references, identities


def build_dojo_curriculum():
    """Return a detached public catalog with stable finite identities."""
    tasks, _, identities = _originals()
    rows = []
    for task in tasks:
        view = public_task(task)
        rows.append({"task_id": task["task_id"], **identities[task["task_id"]], "public_task": view,
                     "public_task_sha256": digest(view), **content_identity(view)})
    body = {"schema": SCHEMA, "version": VERSION, "rows": rows, "source_pins": _pins(),
            "public_only": True, "finite": True, "weights_updated": False,
            "semantic_novelty_proven": False,
            "cluster_basis": "Conservative authored families/groups; no semantic similarity proof."}
    return copy.deepcopy({**body, "curriculum_sha256": digest(body)})


def verify_dojo_curriculum(curriculum, *, expected_sha256=None):
    rebuilt = build_dojo_curriculum()
    if expected_sha256 is not None and (type(expected_sha256) is not str or len(expected_sha256) != 64 or
            any(char not in "0123456789abcdef" for char in expected_sha256)):
        raise DojoCurriculumError("retained curriculum pin must be an exact SHA256")
    if expected_sha256 is not None and rebuilt["curriculum_sha256"] != expected_sha256:
        raise DojoCurriculumError("curriculum differs from retained source/content pin")
    if type(curriculum) is not dict or canonical(curriculum) != canonical(rebuilt):
        raise DojoCurriculumError("curriculum content, source or conservative identity changed")
    return copy.deepcopy(rebuilt)


def make_selection(curriculum, splits):
    catalog = verify_dojo_curriculum(curriculum)
    if type(splits) is not dict or set(splits) != set(SPLITS):
        raise DojoCurriculumError("exact practice/validation/unseen selection required")
    rows = {row["task_id"]: row for row in catalog["rows"]}
    seen, families, clusters = set(), {}, {}
    for split in SPLITS:
        if type(splits[split]) is not list or not 2 <= len(splits[split]) <= 50:
            raise DojoCurriculumError("each split requires two to fifty stable tasks")
        for task_id in splits[split]:
            if type(task_id) is not str or task_id not in rows or task_id in seen:
                raise DojoCurriculumError("unknown, duplicate or renamed curriculum task")
            seen.add(task_id)
            for key, used in (("family_id", families), ("near_duplicate_id", clusters)):
                identity = rows[task_id][key]
                if identity in used and used[identity] != split:
                    raise DojoCurriculumError("family/near-duplicate group crosses selection splits")
                used[identity] = split
    body = {"schema": SELECTION_SCHEMA, "curriculum_sha256": catalog["curriculum_sha256"],
            "splits": copy.deepcopy(splits)}
    return {**body, "selection_sha256": digest(body)}


def verify_selection(selection, *, curriculum=None):
    catalog = build_dojo_curriculum() if curriculum is None else verify_dojo_curriculum(curriculum)
    if type(selection) is not dict or set(selection) != {"schema", "curriculum_sha256", "splits", "selection_sha256"}:
        raise DojoCurriculumError("exact pinned public selection required")
    rebuilt = make_selection(catalog, selection["splits"])
    if canonical(rebuilt) != canonical(selection):
        raise DojoCurriculumError("selection differs from pinned curriculum")
    return rebuilt


def private_selection(selection):
    """Host-only LearningEpoch constructor inputs; never forward to a model."""
    selected = verify_selection(selection)
    tasks, references, _ = _originals()
    ids = {task_id for values in selected["splits"].values() for task_id in values}
    tasks = [task for task in tasks if task["task_id"] in ids]
    references = {task_id: references[task_id] for task_id in sorted(ids)}
    return copy.deepcopy({"tasks": tasks, "references": references,
        "full_tasks_sha256": digest({task["task_id"]: task for task in tasks}),
        "references_sha256": digest(references)})
