"""Bounded grading for local multi-file repair fixtures.

Candidate modules never enter Python's import system. A trusted linker removes
only declared top-level ``from module import name`` AST nodes and binds finite
values or the existing interpreter's function references. For revision grading,
freeze ``allowed_files`` and ``import_graph`` from the original task bundle.
The fixed host worker bounds elapsed time in addition to the shared AST budget.
This is a restricted language evaluator, not an operating-system sandbox.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __package__ in (None, ""):
    # Fixed host code only. No candidate path or source enters the import system.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from xnet import repair_evaluator as _base

MAX_FILES = 4
MAX_BUNDLE_SOURCE = 65536
MAX_BUNDLE_NODES = 8000
_SCHEMA = "xnet.swe-repair-evaluation.v1"
CandidateRejected = _base.CandidateRejected
EvaluationLimit = _base.EvaluationLimit

# Only fixed evaluator text may cross into retry input. Exception arguments
# can contain candidate-controlled strings, identifiers or source fragments.
_PUBLIC_ERROR_TYPES = set(_base._EXCEPTIONS) | {
    "CandidateRejected", "EvaluationLimit", "NameError", "SyntaxError",
    "UnicodeError", "RecursionError", "RuntimeError",
}
_PUBLIC_ERROR_REASONS = frozenset("""
require 2..4 declared Python modules
file names must be flat declared module.py names
candidate file set differs from declared task files
candidate source is not text
candidate module source exceeds limit
candidate bundle source exceeds limit
constant sign requires a number
module constants must be finite literal values
candidate syntax is invalid
candidate module AST exceeds limit
only flat absolute local from-imports are allowed
invalid or duplicate imported name
constants require a single literal name assignment
constant annotations require a finite builtin type
invalid or duplicate constant name
duplicate module name
modules may contain only functions, literal constants, and declared imports
cyclic module import graph is unsupported
import refers to an undeclared task module
import refers to an undeclared module export
entrypoint must be a declared file and function
candidate bundle AST exceeds limit
candidate imports differ from the declared task graph
entrypoint function is unavailable
unsupported value type
candidate source exceeds limit or is not text
candidate AST exceeds limit
forbidden name
cannot replace a builtin
cannot shadow a builtin parameter
unsupported function arguments
only undecorated module functions are allowed
only finite method calls are allowed; attribute reads are forbidden
indirect calls are forbidden
keyword unpacking is forbidden
async comprehensions are forbidden
exception causes are unsupported
module may contain only functions and a docstring
require 1..16 uniquely named functions
call target is not a permitted function
exception requires at most one simple argument
method is unavailable for this value type
string formatting is unsupported
unsupported assignment
raise requires a permitted exception
unsupported statement
dict unpacking unsupported
unsupported expression
result must be JSON-compatible
loop control outside loop
aggregate value size limit exceeded
value nesting limit exceeded
integer size limit exceeded
nonfinite number
string size limit exceeded
container size limit exceeded
cyclic value
operation budget exceeded
argument limit exceeded
call depth exceeded
range limit exceeded
iterator limit exceeded
string conversion exceeds limit
joined string exceeds limit
replacement exceeds limit
sequence repetition exceeds limit
exponent or shift limit exceeded
power exceeds integer limit
call argument limit exceeded
comprehension limit exceeded
too many positional arguments
invalid keyword argument
missing argument
isinstance arguments
isinstance supports finite builtin types
unsupported iterator keywords
sorted arguments
sort arguments
assignment requires list or dict
unpacking size mismatch
fixed evaluator subprocess exceeded timeout
fixed evaluator subprocess failed
invalid evaluator response
unexpected evaluator response
model enum or artifact pin mismatch
unexpected generation envelope
usage must be portable metadata
""".strip().splitlines())
_PUBLIC_AST_NAMES = frozenset(name for name, value in vars(ast).items()
                             if isinstance(value, type) and issubclass(value, ast.AST))


def repair_capability_contract():
    """Fixed host capabilities, independent of task, candidate and grading data."""
    methods = ";".join(kind.__name__ + "=" + ",".join(sorted(names))
                       for kind, names in _base._METHODS.items())
    return ("Evaluator syntax: module functions/literal constants/frozen local from-imports; "
            "assign,return,if,for,while,break,continue,pass,raise,assert; "
            "None/bool/int/float/str/list/tuple/set/dict literals,index/slice,"
            "arithmetic/bitwise/bool/comparison,conditional expressions,"
            "list/set/dict/generator comprehensions,lambda. Builtins=" + ",".join(sorted(_base._BUILTINS)) +
            ". Direct methods=" + methods +
            ". No classes,try,yield,async,decorators,nested def,f-strings,dict/keyword unpacking,"
            "variable-argument definitions or attribute reads. Values/calls/loops are bounded.")


def _public_error(error, error_type=None):
    """Return a bounded enum and static message, never arbitrary error text."""
    reason = error if type(error) is str and len(error) <= 300 else ""
    prefix, separator, suffix = reason.partition(": ")
    if separator and prefix in _PUBLIC_ERROR_TYPES:
        error_type, reason = prefix, suffix
    if reason == "PATCH_WAS_A_NO_OP":
        return {"error_code": "PATCH_WAS_A_NO_OP", "error_message": "PATCH_WAS_A_NO_OP: no implementation change"}
    if reason in _PUBLIC_ERROR_REASONS:
        return {"error_code": re.sub(r"[^A-Z0-9]+", "_", reason.upper()).strip("_")[:96],
                "error_message": reason[:200]}
    if reason.startswith("unsupported syntax: ") and reason[20:] in _PUBLIC_AST_NAMES:
        return {"error_code": "UNSUPPORTED_SYNTAX", "error_message": reason}
    messages = {"NameError": "A candidate name is unavailable.",
                "IndexError": "An index operation failed.", "KeyError": "A key operation failed.",
                "TypeError": "An operation received incompatible types or arguments.",
                "ZeroDivisionError": "A division operation used zero.",
                "EvaluationLimit": "The evaluator resource budget was exceeded.",
                "CandidateRejected": "The candidate uses an unsupported operation.",
                "ValueError": "An operation received an invalid value.",
                "OverflowError": "A numeric operation exceeded its range.",
                "AssertionError": "A candidate assertion failed."}
    kind = error_type if error_type in _PUBLIC_ERROR_TYPES else "EvaluationError"
    return {"error_code": re.sub(r"(?<!^)(?=[A-Z])", "_", kind).upper(),
            "error_message": messages.get(kind, "The evaluator could not complete this operation.")}


def _name(value):
    return (type(value) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", value) is not None
            and "__" not in value and value not in _base._FORBIDDEN_NAMES
            and value not in _base._BUILTINS)


def _file_names(files):
    if type(files) is not dict or not 2 <= len(files) <= MAX_FILES:
        raise CandidateRejected("require 2..4 declared Python modules")
    for path in files:
        if type(path) is not str or not path.endswith(".py") or not _name(path[:-3]):
            raise CandidateRejected("file names must be flat declared module.py names")
    return set(files)


def _sources(files, allowed_files=None):
    names = _file_names(files)
    if allowed_files is not None:
        if type(allowed_files) is dict:
            declared = set(allowed_files)
        elif type(allowed_files) in (list, tuple):
            declared = set(allowed_files)
        else:
            raise ValueError("allowed_files must be a dict or list of declared names")
        _file_names({name: "" for name in declared})
        if names != declared:
            raise CandidateRejected("candidate file set differs from declared task files")
    total = 0
    for source in files.values():
        if type(source) is not str:
            raise CandidateRejected("candidate source is not text")
        size = len(source.encode("utf-8"))
        if size > _base.MAX_SOURCE:
            raise CandidateRejected("candidate module source exceeds limit")
        total += size
    if total > MAX_BUNDLE_SOURCE:
        raise CandidateRejected("candidate bundle source exceeds limit")


def bundle_hashes(files):
    """Hash the complete named bundle, preserving exact source text."""
    _sources(files)
    file_hashes = {path: hashlib.sha256(files[path].encode("utf-8")).hexdigest()
                   for path in sorted(files)}
    canonical = json.dumps(files, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {"file_sha256": file_hashes, "bundle_sha256": hashlib.sha256(canonical).hexdigest()}


def _literal(node):
    """Decode a bounded constant AST without evaluating candidate expressions."""
    if isinstance(node, ast.Constant):
        return _base._bounded(node.value)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [_literal(item) for item in node.elts]
        return _base._bounded({ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(node)](values))
    if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
        return _base._bounded({_literal(key): _literal(value) for key, value in zip(node.keys, node.values)})
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _literal(node.operand)
        if type(value) not in (int, float):
            raise CandidateRejected("constant sign requires a number")
        return _base._bounded(value if isinstance(node.op, ast.UAdd) else -value)
    raise CandidateRejected("module constants must be finite literal values")


def _module(source):
    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise CandidateRejected("candidate syntax is invalid") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > 4000:
        raise CandidateRejected("candidate module AST exceeds limit")
    imports, constants, exports, body = [], {}, set(), []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.level or not _name(node.module):
                raise CandidateRejected("only flat absolute local from-imports are allowed")
            for alias in node.names:
                local = alias.asname or alias.name
                if not _name(alias.name) or not _name(local) or local in exports:
                    raise CandidateRejected("invalid or duplicate imported name")
                imports.append({"module": node.module, "name": alias.name, "asname": alias.asname})
                exports.add(local)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name) or node.value is None:
                raise CandidateRejected("constants require a single literal name assignment")
            if isinstance(node, ast.AnnAssign) and not (isinstance(node.annotation, ast.Name)
                                                       and node.annotation.id in _base._TYPES):
                raise CandidateRejected("constant annotations require a finite builtin type")
            name = targets[0].id
            if not _name(name) or name in exports:
                raise CandidateRejected("invalid or duplicate constant name")
            _literal(node.value)
            constants[name] = node.value
            exports.add(name)
        elif isinstance(node, ast.FunctionDef):
            if node.name in exports:
                raise CandidateRejected("duplicate module name")
            exports.add(node.name)
            body.append(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            body.append(node)
        else:
            raise CandidateRejected("modules may contain only functions, literal constants, and declared imports")
    # Validate the unchanged function AST through the established language
    # checker. Import and constant nodes were individually admitted above.
    if any(isinstance(node, ast.FunctionDef) for node in body):
        filtered = ast.Module(body=body, type_ignores=[])
        checked = _base._parse(ast.unparse(filtered))
    else:
        checked = ast.Module(body=body, type_ignores=[])
    return {"tree": checked, "imports": imports, "constants": constants,
            "exports": {node.name for node in checked.body if isinstance(node, ast.FunctionDef)} | set(constants),
            "node_count": len(nodes)}


def declared_import_graph(files):
    """Freeze exact import names and aliases from trusted original task files."""
    _sources(files)
    modules = {path: _module(source) for path, source in files.items()}
    _link_order(modules)
    return {path: modules[path]["imports"] for path in sorted(modules)}


def _link_order(modules):
    order, visiting, done = [], set(), set()

    def visit(path):
        if path in visiting:
            raise CandidateRejected("cyclic module import graph is unsupported")
        if path in done:
            return
        visiting.add(path)
        for item in modules[path]["imports"]:
            dependency = item["module"] + ".py"
            if dependency not in modules:
                raise CandidateRejected("import refers to an undeclared task module")
            if item["name"] not in modules[dependency]["exports"]:
                raise CandidateRejected("import refers to an undeclared module export")
            visit(dependency)
        visiting.remove(path)
        done.add(path)
        order.append(path)

    for path in sorted(modules):
        visit(path)
    return order


def _prepare(files, entry_file, entry_function, allowed_files=None, import_graph=None):
    _sources(files, allowed_files)
    if entry_file not in files or not _name(entry_function):
        raise CandidateRejected("entrypoint must be a declared file and function")
    modules = {path: _module(source) for path, source in files.items()}
    if sum(module["node_count"] for module in modules.values()) > MAX_BUNDLE_NODES:
        raise CandidateRejected("candidate bundle AST exceeds limit")
    actual_graph = {path: modules[path]["imports"] for path in sorted(modules)}
    if import_graph is not None and actual_graph != import_graph:
        raise CandidateRejected("candidate imports differ from the declared task graph")
    order = _link_order(modules)
    if entry_function not in {node.name for node in modules[entry_file]["tree"].body
                             if isinstance(node, ast.FunctionDef)}:
        raise CandidateRejected("entrypoint function is unavailable")
    return modules, order


def _cases(cases, entry_function):
    if type(cases) is not list:
        raise ValueError("cases must be a list")
    normalized = []
    for case in cases:
        if type(case) is not dict or type(case.get("hidden")) is not bool:
            raise ValueError("every case requires an explicit hidden boolean")
        item = dict(case)
        item.setdefault("name", entry_function)
        if item["name"] != entry_function:
            raise ValueError("case name must match the declared entrypoint")
        item["hidden"] = True
        normalized.append(item)
    _base._cases(normalized)
    ids = [case.get("case_id") for case in cases if "case_id" in case]
    if len(set(ids)) != len(ids):
        raise ValueError("case IDs must be unique")
    return [dict(item, hidden=original["hidden"]) for item, original in zip(normalized, cases)]


def _report(status, cases, rows, hashes=None, error=None):
    result = _base._report(status, cases, rows, error)
    result["schema_version"] = _SCHEMA
    result["candidate_execution"] = "bounded-ast-interpreter-with-fixed-local-linker"
    result["import_execution"] = False
    result["visibility"] = ("hidden" if all(case["hidden"] for case in cases) else
                            "public" if all(not case["hidden"] for case in cases) else "mixed")
    result.update(hashes or {})
    return result


def _exact_result(value, expected):
    """Keep every JSON type distinct, including bool/int/float at any depth."""
    if type(value) is not type(expected):
        return False
    if type(value) in (list, tuple):
        return len(value) == len(expected) and all(_exact_result(left, right) for left, right in zip(value, expected))
    if type(value) is dict:
        return value.keys() == expected.keys() and all(_exact_result(value[key], expected[key]) for key in value)
    return value == expected


def _evaluate_bundle(files, entry_file, entry_function, cases, *, allowed_files=None, import_graph=None):
    cases = _cases(cases, entry_function)
    hashes = None
    try:
        hashes = bundle_hashes(files)
        modules, order = _prepare(files, entry_file, entry_function, allowed_files, import_graph)
    except (CandidateRejected, UnicodeError, TypeError, ValueError, RecursionError) as exc:
        return _report("rejected", cases, [], hashes, exc)
    rows = []
    for index, case in enumerate(cases):
        row = {"index": index, "name": entry_function, "case_type": case["case_type"],
               "hidden": case["hidden"], "passed": False}
        if "case_id" in case:
            row["case_id"] = case["case_id"]
        # One interpreter owns every invocation's step and depth counters.
        interpreter = _base._Interpreter(ast.Module(body=[], type_ignores=[]))
        environments = {}
        try:
            for path in order:
                module = modules[path]
                env = dict(interpreter.globals)
                env.update({name: _literal(node) for name, node in module["constants"].items()})
                for node in module["tree"].body:
                    if isinstance(node, ast.FunctionDef):
                        env[node.name] = _base._Callable(node=node, env=env)
                for item in module["imports"]:
                    env[item["asname"] or item["name"]] = environments[item["module"] + ".py"][item["name"]]
                environments[path] = env
            payload = json.loads(json.dumps({"args": case["args"], "kwargs": case["kwargs"]}, allow_nan=False))
            value = interpreter.invoke(environments[entry_file][entry_function], payload["args"], payload["kwargs"])
            _base._json_value(value)
            row["passed"] = "expected" in case and _exact_result(value, case["expected"])
            row["status"] = "passed" if row["passed"] else "wrong-answer"
        except Exception as exc:
            row["error_type"] = type(exc).__name__
            row["error"] = str(exc)[:200]
            row["passed"] = type(exc) in set(_base._EXCEPTIONS.values()) and case.get("raises") == type(exc).__name__
            row["status"] = "passed" if row["passed"] else "error"
        except (_base._Break, _base._Continue):
            row.update(status="error", error_type="CandidateRejected", error="loop control outside loop")
        row["steps"] = interpreter.steps
        rows.append(row)
    return _report("evaluated", cases, rows, hashes)


def evaluate_bundle(files, entry_file, entry_function, cases, *, allowed_files=None,
                    import_graph=None, timeout_seconds=3):
    """Grade a complete revision in a fixed isolated host worker.

    Pass the original task's file names and ``declared_import_graph`` when
    grading repairs. Hidden cases stay host-side; use ``public_feedback`` for
    any report delivered to a candidate worker.
    """
    cases = _cases(cases, entry_function)
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60:
        raise ValueError("timeout_seconds must be in (0,60]")
    if type(allowed_files) is dict:
        allowed_files = list(allowed_files)
    try:
        raw = json.dumps({"files": files, "entry_file": entry_file, "entry_function": entry_function,
                          "cases": cases, "allowed_files": allowed_files, "import_graph": import_graph},
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ValueError("evaluation input must be portable JSON") from exc
    if len(raw) > _base.MAX_INPUT:
        raise ValueError("evaluation input exceeds limit")
    hashes = None
    try:
        hashes = bundle_hashes(files)
    except (CandidateRejected, UnicodeError):
        pass
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    try:
        with tempfile.TemporaryDirectory(prefix="xnet-swe-repair-eval-") as directory:
            process = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker"],
                                     input=raw, capture_output=True, cwd=directory, env=environment,
                                     timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return _report("timed-out", cases, [], hashes, "fixed evaluator subprocess exceeded timeout")
    if process.returncode or len(process.stdout) > _base.MAX_OUTPUT or len(process.stderr) > 65536:
        return _report("worker-error", cases, [], hashes, "fixed evaluator subprocess failed")
    try:
        result = json.loads(process.stdout)
    except (ValueError, UnicodeError):
        return _report("worker-error", cases, [], hashes, "invalid evaluator response")
    if type(result) is not dict or result.get("schema_version") != _SCHEMA:
        return _report("worker-error", cases, [], hashes, "unexpected evaluator response")
    return result


def public_feedback(report):
    """Return observations from a public-only report; reject hidden reports."""
    if type(report) is not dict or report.get("schema_version") != _SCHEMA:
        raise ValueError("unexpected evaluation report")
    if report.get("visibility") != "public" or any(row.get("hidden") is not False for row in report["cases"]):
        raise ValueError("feedback requires a public-only evaluation")
    fields = {"case_id", "case_type", "name", "passed", "status", "steps", "error_type"}
    rows = []
    for row in report["cases"]:
        clean = {key: value for key, value in row.items() if key in fields}
        if "error" in row or "error_type" in row:
            kind = row.get("error_type")
            clean["error_type"] = kind if type(kind) is str and kind in _PUBLIC_ERROR_TYPES else "EvaluationError"
            clean.update(_public_error(row.get("error"), clean["error_type"]))
        rows.append(clean)
    result = {"schema_version": "xnet.swe-public-feedback.v1", "status": report["status"],
            "resolved": report["status"] == "evaluated" and bool(rows) and all(row["passed"] for row in rows),
            "passed": sum(row["passed"] for row in rows), "total": report["total"], "cases": rows}
    if "error" in report:
        result.update(_public_error(report["error"]))
        result["error"] = result["error_message"]  # compatibility, with the same safe bound
    return result


def validate_baseline(task, *, timeout_seconds=3):
    """Require every public/hidden F2P to fail and every P2P to pass."""
    files = task["files"]
    graph = declared_import_graph(files)
    options = {"allowed_files": files, "import_graph": graph, "timeout_seconds": timeout_seconds}
    reports = {name: evaluate_bundle(files, task["entry_file"], task["entry_function"], task[name + "_cases"], **options)
               for name in ("public", "hidden")}
    valid = True
    for visibility, report in reports.items():
        originals = task[visibility + "_cases"]
        valid = valid and all(case["hidden"] is (visibility == "hidden") for case in originals)
        valid = valid and report["status"] == "evaluated" and len(report["cases"]) == report["total"]
        valid = valid and all(row["passed"] is (row["case_type"] == "P2P") for row in report["cases"])
        valid = valid and all(report[group]["total"] > 0 for group in ("fail_to_pass", "pass_to_pass"))
    return {"schema_version": "xnet.swe-baseline-validation.v1", "valid": bool(valid),
            "public": reports["public"], "hidden": reports["hidden"], **bundle_hashes(files)}


def _main():
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("Use evaluate_bundle(); only --worker is a valid internal entrypoint")
    raw = sys.stdin.buffer.read(_base.MAX_INPUT + 1)
    if len(raw) > _base.MAX_INPUT:
        raise SystemExit(2)
    value = json.loads(raw)
    if type(value) is not dict or set(value) != {"files", "entry_file", "entry_function", "cases", "allowed_files", "import_graph"}:
        raise SystemExit(2)
    result = _evaluate_bundle(value["files"], value["entry_file"], value["entry_function"], value["cases"],
                              allowed_files=value["allowed_files"], import_graph=value["import_graph"])
    output = json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(output) > _base.MAX_OUTPUT:
        raise SystemExit(2)
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    _main()
