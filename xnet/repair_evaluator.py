"""Bounded local repair evaluation, using an AST interpreter rather than exec.

Candidate code has values and finite pure operations, never Python objects that
provide filesystem/network/process access. A fixed isolated Python subprocess
also bounds elapsed time. This is a restricted language evaluator, not an OS
sandbox for arbitrary Python.
"""
from __future__ import annotations

import ast
import json
import math
import operator
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_SOURCE = 32768
MAX_INPUT = 2 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_ITEMS = 10000
MAX_STRING = 65536
MAX_BITS = 256
MAX_STEPS = 100000
MAX_DEPTH = 32
_EXCEPTIONS = {name: value for name, value in {
    "ValueError": ValueError, "TypeError": TypeError, "IndexError": IndexError,
    "KeyError": KeyError, "ZeroDivisionError": ZeroDivisionError,
    "OverflowError": OverflowError, "AssertionError": AssertionError,
}.items()}
_TYPES = {"int": int, "float": float, "str": str, "bool": bool,
          "list": list, "tuple": tuple, "dict": dict, "set": set}
_BUILTINS = set(_TYPES) | set(_EXCEPTIONS) | {
    "len", "range", "enumerate", "zip", "sum", "min", "max", "abs", "round",
    "sorted", "reversed", "all", "any", "isinstance", "divmod", "ord", "chr",
}
_METHODS = {
    str: {"strip", "lstrip", "rstrip", "split", "rsplit", "splitlines", "join", "lower",
          "upper", "casefold", "isdigit", "isalpha", "isalnum", "isspace", "replace",
          "startswith", "endswith", "find", "rfind", "index", "count", "capitalize", "title"},
    list: {"append", "extend", "insert", "pop", "remove", "index", "count", "sort", "reverse", "copy"},
    tuple: {"index", "count"},
    dict: {"get", "items", "values", "keys", "setdefault", "update", "pop", "copy"},
    set: {"add", "discard", "remove", "union", "intersection", "difference", "issubset", "issuperset", "copy"},
}
_ALL_METHODS = set().union(*_METHODS.values())
_FORBIDDEN_NAMES = {"eval", "exec", "compile", "open", "input", "print", "globals", "locals",
                    "vars", "getattr", "setattr", "delattr", "hasattr", "type", "object", "super",
                    "help", "dir", "memoryview", "breakpoint", "exit", "quit", "builtins"}
_NODES = {
    ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Return, ast.Assign,
    ast.AugAssign, ast.AnnAssign, ast.If, ast.For, ast.While, ast.Break, ast.Continue,
    ast.Pass, ast.Expr, ast.Raise, ast.Assert, ast.Name, ast.Constant, ast.List,
    ast.Tuple, ast.Set, ast.Dict, ast.Subscript, ast.Slice, ast.BinOp, ast.UnaryOp,
    ast.BoolOp, ast.Compare, ast.IfExp, ast.Call, ast.Attribute, ast.keyword,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.comprehension,
    ast.Starred, ast.Lambda, ast.Load, ast.Store, ast.Add, ast.Sub, ast.Mult,
    ast.Div, ast.FloorDiv, ast.Mod, ast.Pow, ast.LShift, ast.RShift, ast.BitOr,
    ast.BitAnd, ast.BitXor, ast.USub, ast.UAdd, ast.Not, ast.Invert, ast.And,
    ast.Or, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is,
    ast.IsNot, ast.In, ast.NotIn,
}
_BINARY = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
           ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
           ast.Pow: operator.pow, ast.LShift: operator.lshift, ast.RShift: operator.rshift,
           ast.BitOr: operator.or_, ast.BitAnd: operator.and_, ast.BitXor: operator.xor}
_COMPARE = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
            ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
            ast.Is: operator.is_, ast.IsNot: operator.is_not,
            ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b}


class CandidateRejected(ValueError):
    pass


class EvaluationLimit(CandidateRejected):
    pass


class _Return(BaseException):
    def __init__(self, value):
        self.value = value


class _Break(BaseException):
    pass


class _Continue(BaseException):
    pass


class _Callable:
    def __init__(self, name=None, node=None, env=None):
        self.name, self.node, self.env = name, node, env


def _bounded(value, depth=0, seen=None, budget=None):
    budget = [0] if budget is None else budget
    budget[0] += len(value.encode("utf-8")) if type(value) is str else 32
    if budget[0] > 1024 * 1024:
        raise EvaluationLimit("aggregate value size limit exceeded")
    if depth > MAX_DEPTH:
        raise EvaluationLimit("value nesting limit exceeded")
    kind = type(value)
    if value is None or kind is bool:
        return value
    if kind is int:
        if value.bit_length() > MAX_BITS:
            raise EvaluationLimit("integer size limit exceeded")
    elif kind is float:
        if not math.isfinite(value):
            raise EvaluationLimit("nonfinite number")
    elif kind is str:
        if len(value) > MAX_STRING or len(value.encode("utf-8")) > MAX_STRING:
            raise EvaluationLimit("string size limit exceeded")
    elif kind in (list, tuple, set, dict):
        if len(value) > MAX_ITEMS:
            raise EvaluationLimit("container size limit exceeded")
        seen = set() if seen is None else seen
        if id(value) in seen:
            raise EvaluationLimit("cyclic value")
        seen.add(id(value))
        for item in (list(value.keys()) + list(value.values()) if kind is dict else value):
            _bounded(item, depth + 1, seen, budget)
        seen.remove(id(value))
    elif isinstance(value, (_Callable, slice)):
        return value
    else:
        raise CandidateRejected("unsupported value type")
    return value


def _parse(source):
    if type(source) is not str or len(source.encode("utf-8")) > MAX_SOURCE:
        raise CandidateRejected("candidate source exceeds limit or is not text")
    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise CandidateRejected("candidate syntax is invalid") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > 4000:
        raise CandidateRejected("candidate AST exceeds limit")
    parents = {id(child): node for node in nodes for child in ast.iter_child_nodes(node)}
    for node in nodes:
        if type(node) not in _NODES:
            raise CandidateRejected("unsupported syntax: " + type(node).__name__)
        for name in ([node.id] if isinstance(node, ast.Name) else
                     [node.arg] if isinstance(node, ast.arg) else
                     [node.name] if isinstance(node, ast.FunctionDef) else []):
            if "__" in name or name in _FORBIDDEN_NAMES:
                raise CandidateRejected("forbidden name")
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in _BUILTINS:
            raise CandidateRejected("cannot replace a builtin")
        if isinstance(node, ast.arg) and node.arg in _BUILTINS:
            raise CandidateRejected("cannot shadow a builtin parameter")
        if isinstance(node, (ast.FunctionDef, ast.Lambda)):
            if node.args.vararg or node.args.kwarg or len(node.args.args) + len(node.args.posonlyargs) + len(node.args.kwonlyargs) > 16:
                raise CandidateRejected("unsupported function arguments")
        if isinstance(node, ast.FunctionDef):
            if node.decorator_list or node.name in _BUILTINS or not isinstance(parents.get(id(node)), ast.Module):
                raise CandidateRejected("only undecorated module functions are allowed")
        if isinstance(node, ast.Attribute):
            parent = parents.get(id(node))
            if node.attr not in _ALL_METHODS or not isinstance(parent, ast.Call) or parent.func is not node:
                raise CandidateRejected("only finite method calls are allowed; attribute reads are forbidden")
        if isinstance(node, ast.Call) and not isinstance(node.func, (ast.Name, ast.Attribute, ast.Lambda)):
            raise CandidateRejected("indirect calls are forbidden")
        if isinstance(node, ast.keyword) and node.arg is None:
            raise CandidateRejected("keyword unpacking is forbidden")
        if isinstance(node, ast.comprehension) and node.is_async:
            raise CandidateRejected("async comprehensions are forbidden")
        if isinstance(node, ast.Raise) and node.cause is not None:
            raise CandidateRejected("exception causes are unsupported")
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) and not (
                isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and type(node.value.value) is str):
            raise CandidateRejected("module may contain only functions and a docstring")
    names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
    if not names or len(names) > 16 or len(set(names)) != len(names):
        raise CandidateRejected("require 1..16 uniquely named functions")
    return tree


class _Interpreter:
    def __init__(self, tree):
        self.steps = 0
        self.depth = 0
        self.globals = {name: _Callable(name=name) for name in _BUILTINS}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self.globals[node.name] = _Callable(node=node, env=self.globals)

    def tick(self):
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise EvaluationLimit("operation budget exceeded")

    def invoke(self, fn, args, kwargs):
        self.tick()
        if not isinstance(fn, _Callable):
            raise CandidateRejected("call target is not a permitted function")
        if len(args) > MAX_ITEMS or len(kwargs) > 16:
            raise EvaluationLimit("argument limit exceeded")
        if fn.name is not None:
            return self.builtin(fn.name, args, kwargs)
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                raise EvaluationLimit("call depth exceeded")
            node = fn.node
            positional = node.args.posonlyargs + node.args.args
            if len(args) > len(positional):
                raise TypeError("too many positional arguments")
            local = dict(fn.env)
            bound = {parameter.arg: value for parameter, value in zip(positional, args)}
            valid = {parameter.arg for parameter in positional + node.args.kwonlyargs}
            for name, value in kwargs.items():
                if name not in valid or name in bound or name in {p.arg for p in node.args.posonlyargs}:
                    raise TypeError("invalid keyword argument")
                bound[name] = value
            defaults = {parameter.arg: default for parameter, default in zip(positional[-len(node.args.defaults):], node.args.defaults)} if node.args.defaults else {}
            defaults.update({parameter.arg: default for parameter, default in zip(node.args.kwonlyargs, node.args.kw_defaults) if default is not None})
            for parameter in positional + node.args.kwonlyargs:
                if parameter.arg not in bound:
                    if parameter.arg not in defaults:
                        raise TypeError("missing argument")
                    bound[parameter.arg] = self.expr(defaults[parameter.arg], fn.env)
            local.update(bound)
            if isinstance(node, ast.Lambda):
                return self.expr(node.body, local)
            try:
                self.block(node.body, local)
            except _Return as result:
                return _bounded(result.value)
            return None
        finally:
            self.depth -= 1

    def builtin(self, name, args, kwargs):
        if name in _EXCEPTIONS:
            if kwargs or len(args) > 1 or any(type(arg) not in (str, int, float, bool) for arg in args):
                raise CandidateRejected("exception requires at most one simple argument")
            return _EXCEPTIONS[name](*args)
        if name == "isinstance":
            if kwargs or len(args) != 2:
                raise TypeError("isinstance arguments")
            requested = args[1] if type(args[1]) is tuple else (args[1],)
            if any(not isinstance(item, _Callable) or item.name not in _TYPES for item in requested):
                raise TypeError("isinstance supports finite builtin types")
            return isinstance(args[0], tuple(_TYPES[item.name] for item in requested))
        if name in {"range", "enumerate", "zip", "reversed"}:
            if kwargs and not (name == "enumerate" and set(kwargs) <= {"start"}):
                raise TypeError("unsupported iterator keywords")
            operation = {"range": range, "enumerate": enumerate, "zip": zip, "reversed": reversed}[name]
            iterator = operation(*args, **kwargs)
            if name == "range" and len(iterator) > MAX_ITEMS:
                raise EvaluationLimit("range limit exceeded")
            result = []
            for item in iterator:
                self.tick()
                if len(result) >= MAX_ITEMS:
                    raise EvaluationLimit("iterator limit exceeded")
                result.append(item)
            return _bounded(result)
        if name == "sorted":
            if len(args) != 1 or set(kwargs) - {"key", "reverse"}:
                raise TypeError("sorted arguments")
            key = kwargs.get("key")
            result = sorted(args[0], key=(lambda item: self.invoke(key, [item], {})) if key is not None else None,
                            reverse=kwargs.get("reverse", False))
            return _bounded(result)
        operations = {**_TYPES, "len": len, "sum": sum, "min": min, "max": max,
                      "abs": abs, "round": round, "all": all, "any": any,
                      "divmod": divmod, "ord": ord, "chr": chr}
        if name in {"min", "max"} and "key" in kwargs:
            kwargs = dict(kwargs)
            key = kwargs.pop("key")
            if key is not None:
                kwargs["key"] = lambda item: self.invoke(key, [item], {})
        if name == "str" and args and type(args[0]) in (list, tuple, dict, set):
            if len(repr(args[0])) > MAX_STRING:
                raise EvaluationLimit("string conversion exceeds limit")
        return _bounded(operations[name](*args, **kwargs))

    def method(self, receiver, name, args, kwargs):
        kind = type(receiver)
        if name not in _METHODS.get(kind, set()):
            raise CandidateRejected("method is unavailable for this value type")
        if kind is str and name == "join" and args:
            if sum(len(value) for value in args[0]) + len(receiver) * max(0, len(args[0]) - 1) > MAX_STRING:
                raise EvaluationLimit("joined string exceeds limit")
        if kind is str and name == "replace" and len(args) >= 2:
            old, new = args[:2]
            count = receiver.count(old) if len(args) < 3 or args[2] < 0 else min(receiver.count(old), args[2])
            if len(receiver) + count * (len(new) - len(old)) > MAX_STRING:
                raise EvaluationLimit("replacement exceeds limit")
        if kind is list and name == "sort":
            if args or set(kwargs) - {"key", "reverse"}:
                raise TypeError("sort arguments")
            key = kwargs.get("key")
            receiver.sort(key=(lambda item: self.invoke(key, [item], {})) if key is not None else None,
                          reverse=kwargs.get("reverse", False))
            result = None
        else:
            # Selection is from a fixed host table and exact builtin type; no
            # candidate-provided class or general attribute lookup is possible.
            operation = getattr(kind, name)
            result = operation(receiver, *args, **kwargs)
        if kind is dict and name in {"items", "keys", "values"}:
            result = list(result)
        _bounded(receiver)
        return _bounded(result)

    def binary(self, op, left, right):
        if isinstance(op, ast.Mod) and type(left) is str:
            raise CandidateRejected("string formatting is unsupported")
        if isinstance(op, ast.Mult):
            sequence, times = (left, right) if type(right) is int else (right, left)
            if type(sequence) in (str, list, tuple) and type(times) is int:
                if len(sequence) * max(times, 0) > (MAX_STRING if type(sequence) is str else MAX_ITEMS):
                    raise EvaluationLimit("sequence repetition exceeds limit")
        if isinstance(op, (ast.Pow, ast.LShift, ast.RShift)):
            if type(right) not in (int, float) or abs(right) > MAX_BITS:
                raise EvaluationLimit("exponent or shift limit exceeded")
            if isinstance(op, ast.Pow) and type(left) is int and right > 0 and max(1, left.bit_length()) * right > MAX_BITS:
                raise EvaluationLimit("power exceeds integer limit")
        return _bounded(_BINARY[type(op)](left, right))

    def assign(self, target, value, env):
        self.tick()
        _bounded(value)
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            if len(target.elts) != len(value):
                raise ValueError("unpacking size mismatch")
            for child, item in zip(target.elts, value):
                self.assign(child, item, env)
        elif isinstance(target, ast.Subscript):
            container = self.expr(target.value, env)
            if type(container) not in (list, dict):
                raise TypeError("assignment requires list or dict")
            container[self.expr(target.slice, env)] = value
            _bounded(container)
        else:
            raise CandidateRejected("unsupported assignment")

    def block(self, statements, env):
        for node in statements:
            self.tick()
            if isinstance(node, ast.Return):
                raise _Return(self.expr(node.value, env) if node.value is not None else None)
            if isinstance(node, ast.Assign):
                value = self.expr(node.value, env)
                for target in node.targets:
                    self.assign(target, value, env)
            elif isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    self.assign(node.target, self.expr(node.value, env), env)
            elif isinstance(node, ast.AugAssign):
                self.assign(node.target, self.binary(node.op, self.expr(node.target, env), self.expr(node.value, env)), env)
            elif isinstance(node, ast.Expr):
                self.expr(node.value, env)
            elif isinstance(node, ast.If):
                self.block(node.body if self.expr(node.test, env) else node.orelse, env)
            elif isinstance(node, (ast.For, ast.While)):
                broken = False
                iterator = iter(self.expr(node.iter, env)) if isinstance(node, ast.For) else None
                while True:
                    self.tick()
                    if iterator is not None:
                        try:
                            value = next(iterator)
                        except StopIteration:
                            break
                        self.assign(node.target, value, env)
                    elif not self.expr(node.test, env):
                        break
                    try:
                        self.block(node.body, env)
                    except _Continue:
                        continue
                    except _Break:
                        broken = True
                        break
                if not broken:
                    self.block(node.orelse, env)
            elif isinstance(node, ast.Break):
                raise _Break()
            elif isinstance(node, ast.Continue):
                raise _Continue()
            elif isinstance(node, ast.Raise):
                error = self.expr(node.exc, env) if node.exc is not None else None
                if isinstance(error, _Callable) and error.name in _EXCEPTIONS:
                    error = _EXCEPTIONS[error.name]()
                if type(error) not in set(_EXCEPTIONS.values()):
                    raise CandidateRejected("raise requires a permitted exception")
                raise error
            elif isinstance(node, ast.Assert):
                if not self.expr(node.test, env):
                    raise AssertionError(self.expr(node.msg, env) if node.msg else "assertion failed")
            elif not isinstance(node, ast.Pass):
                raise CandidateRejected("unsupported statement")

    def expr(self, node, env):
        self.tick()
        if isinstance(node, ast.Constant):
            return _bounded(node.value)
        if isinstance(node, ast.Name):
            if node.id not in env:
                raise NameError("unknown candidate name: " + node.id)
            return env[node.id]
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [self.expr(item, env) for item in node.elts]
            return _bounded({ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(node)](values))
        if isinstance(node, ast.Dict):
            if any(key is None for key in node.keys):
                raise CandidateRejected("dict unpacking unsupported")
            return _bounded({self.expr(key, env): self.expr(value, env) for key, value in zip(node.keys, node.values)})
        if isinstance(node, ast.Subscript):
            return _bounded(self.expr(node.value, env)[self.expr(node.slice, env)])
        if isinstance(node, ast.Slice):
            return slice(*(self.expr(part, env) if part is not None else None for part in (node.lower, node.upper, node.step)))
        if isinstance(node, ast.BinOp):
            return self.binary(node.op, self.expr(node.left, env), self.expr(node.right, env))
        if isinstance(node, ast.UnaryOp):
            return _bounded({ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Not: operator.not_, ast.Invert: operator.invert}[type(node.op)](self.expr(node.operand, env)))
        if isinstance(node, ast.BoolOp):
            for child in node.values:
                value = self.expr(child, env)
                if (isinstance(node.op, ast.And) and not value) or (isinstance(node.op, ast.Or) and value):
                    return value
            return value
        if isinstance(node, ast.Compare):
            left = self.expr(node.left, env)
            for op, child in zip(node.ops, node.comparators):
                right = self.expr(child, env)
                if not _COMPARE[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            return self.expr(node.body if self.expr(node.test, env) else node.orelse, env)
        if isinstance(node, ast.Lambda):
            return _Callable(node=node, env=dict(env))
        if isinstance(node, ast.Call):
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    args.extend(self.expr(arg.value, env))
                else:
                    args.append(self.expr(arg, env))
                if len(args) > MAX_ITEMS:
                    raise EvaluationLimit("call argument limit exceeded")
            kwargs = {item.arg: self.expr(item.value, env) for item in node.keywords}
            if isinstance(node.func, ast.Attribute):
                return self.method(self.expr(node.func.value, env), node.func.attr, args, kwargs)
            return self.invoke(self.expr(node.func, env), args, kwargs)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            result = []
            local = dict(env)
            def visit(index):
                generator = node.generators[index]
                for value in self.expr(generator.iter, local):
                    self.tick()
                    self.assign(generator.target, value, local)
                    if all(self.expr(condition, local) for condition in generator.ifs):
                        if index + 1 < len(node.generators):
                            visit(index + 1)
                        else:
                            result.append((self.expr(node.key, local), self.expr(node.value, local)) if isinstance(node, ast.DictComp) else self.expr(node.elt, local))
                            if len(result) > MAX_ITEMS:
                                raise EvaluationLimit("comprehension limit exceeded")
            visit(0)
            return _bounded(dict(result) if isinstance(node, ast.DictComp) else set(result) if isinstance(node, ast.SetComp) else result)
        raise CandidateRejected("unsupported expression")


def _json_value(value):
    _bounded(value)
    if value is None or type(value) in (str, int, float, bool):
        return value
    if type(value) in (list, tuple):
        return [_json_value(item) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _json_value(item) for key, item in value.items()}
    raise CandidateRejected("result must be JSON-compatible")


def _cases(cases):
    if type(cases) is not list or not 1 <= len(cases) <= 1000:
        raise ValueError("require 1..1000 cases")
    for case in cases:
        if type(case) is not dict or set(case) - {"case_id", "name", "args", "kwargs", "case_type", "hidden", "expected", "raises"}:
            raise ValueError("invalid case fields")
        if "case_id" in case and (type(case["case_id"]) is not str or not 1 <= len(case["case_id"]) <= 256):
            raise ValueError("invalid case ID")
        if (type(case.get("name")) is not str or not case["name"].isidentifier() or "__" in case["name"]
                or type(case.get("args")) is not list or type(case.get("kwargs")) is not dict
                or case.get("case_type") not in {"F2P", "P2P"} or case.get("hidden") is not True
                or ("expected" in case) == ("raises" in case)):
            raise ValueError("invalid case contract")
        if "raises" in case and case["raises"] not in _EXCEPTIONS:
            raise ValueError("unsupported expected exception")
        _bounded(case["args"])
        _bounded(case["kwargs"])
        if "expected" in case:
            _json_value(case["expected"])
    return cases


def _report(status, cases, rows, error=None):
    groups = {kind: {"passed": sum(row.get("passed", False) for row in rows if row["case_type"] == kind),
                     "total": sum(case["case_type"] == kind for case in cases)} for kind in ("F2P", "P2P")}
    result = {"schema_version": "xnet.repair-evaluation.v1", "status": status,
              "resolved": status == "evaluated" and len(rows) == len(cases) and all(row["passed"] for row in rows),
              "passed": sum(row.get("passed", False) for row in rows), "total": len(cases),
              "fail_to_pass": groups["F2P"], "pass_to_pass": groups["P2P"], "cases": rows,
              "candidate_execution": "bounded-ast-interpreter", "os_sandbox": False}
    if error:
        result["error"] = str(error)[:300]
    return result


def _evaluate(source, cases):
    _cases(cases)
    try:
        tree = _parse(source)
    except (CandidateRejected, UnicodeError) as exc:
        return _report("rejected", cases, [], exc)
    rows = []
    for index, case in enumerate(cases):
        row = {"index": index, "name": case["name"], "case_type": case["case_type"], "passed": False}
        if "case_id" in case:
            row["case_id"] = case["case_id"]
        interpreter = _Interpreter(tree)
        try:
            # Each case receives a fresh independent object graph and globals.
            payload = json.loads(json.dumps({"args": case["args"], "kwargs": case["kwargs"]}))
            value = interpreter.invoke(interpreter.globals.get(case["name"]), payload["args"], payload["kwargs"])
            _json_value(value)  # Validate portability without changing return-type equality.
            row["passed"] = "expected" in case and value == case["expected"]
            row["status"] = "passed" if row["passed"] else "wrong-answer"
        except Exception as exc:
            row["error_type"] = type(exc).__name__
            row["error"] = str(exc)[:200]
            row["passed"] = type(exc) in set(_EXCEPTIONS.values()) and case.get("raises") == type(exc).__name__
            row["status"] = "passed" if row["passed"] else "error"
        except (_Break, _Continue):
            row["status"] = "error"
            row["error_type"] = "CandidateRejected"
            row["error"] = "loop control outside loop"
        row["steps"] = interpreter.steps
        rows.append(row)
    return _report("evaluated", cases, rows)


def evaluate_source(source, cases, timeout_seconds=3):
    """Evaluate a pure candidate through this fixed host entrypoint.

    ``name`` in each case selects a source function. Hidden cases are never
    appended to candidate context. Errors and rejected code remain failures.
    """
    _cases(cases)
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60:
        raise ValueError("timeout_seconds must be in (0,60]")
    try:
        raw = json.dumps({"source": source, "cases": cases}, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ValueError("evaluation input must be portable JSON") from exc
    if len(raw) > MAX_INPUT:
        raise ValueError("evaluation input exceeds limit")
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    try:
        with tempfile.TemporaryDirectory(prefix="xnet-repair-eval-") as directory:
            process = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker"],
                                     input=raw, capture_output=True, cwd=directory, env=environment,
                                     timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return _report("timed-out", cases, [], "fixed evaluator subprocess exceeded timeout")
    if process.returncode or len(process.stdout) > MAX_OUTPUT or len(process.stderr) > 65536:
        return _report("worker-error", cases, [], "fixed evaluator subprocess failed")
    try:
        result = json.loads(process.stdout)
    except (ValueError, UnicodeError):
        return _report("worker-error", cases, [], "invalid evaluator response")
    if not isinstance(result, dict) or result.get("schema_version") != "xnet.repair-evaluation.v1":
        return _report("worker-error", cases, [], "unexpected evaluator response")
    return result


def _main():
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("Use evaluate_source(); only --worker is a valid internal entrypoint")
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise SystemExit(2)
    value = json.loads(raw)
    if type(value) is not dict or set(value) != {"source", "cases"}:
        raise SystemExit(2)
    result = _evaluate(value["source"], value["cases"])
    output = json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(output) > MAX_OUTPUT:
        raise SystemExit(2)
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    _main()
