"""Import the unchanged preview under a private source-checkout namespace.

The audited flat scripts remain runnable in their own process. This adapter
keeps their legacy imports and dependency names away from the public xnet
package and other test modules. No model or worker is constructed on import.
"""
from __future__ import annotations

import builtins
from collections.abc import MutableMapping
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import threading
import types

HERE = Path(__file__).resolve().parent
PREFIX = "_xnet_public_lab_accuracy_preview_v1"
ORIGIN_SHA256 = "f8c18b9f41a590f6707b78d75d8a18334bfafeff5c60ae8c5ca4b66740d68930"
RUNTIME_FILES = {"controller", "metadata_bridge", "halo_binding", "frozen_integrations", "preview_cli"}
_LOCK = threading.RLock()


def verify_sources():
    raw = (HERE / "origin-verification.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != ORIGIN_SHA256:
        raise ValueError("portable origin verification changed")
    receipt = json.loads(raw)
    for relative, expected in receipt["byte_identical_files"].items():
        path = HERE / relative
        path.resolve().relative_to(HERE)
        if path.stat().st_size > 1024 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("portable audited source changed: " + relative)
    return dict(receipt["byte_identical_files"])


def _qualified(name):
    return name if name == PREFIX or name.startswith(PREFIX + ".") else PREFIX + "." + name


class _PrivateModules(MutableMapping):
    def __getitem__(self, key): return sys.modules[_qualified(key)]
    def __setitem__(self, key, value): sys.modules[_qualified(key)] = value
    def __delitem__(self, key): del sys.modules[_qualified(key)]
    def __iter__(self):
        return iter([name[len(PREFIX)+1:] for name in list(sys.modules) if name.startswith(PREFIX + ".")])
    def __len__(self): return sum(name.startswith(PREFIX + ".") for name in sys.modules)


# Module-local views; real sys/importlib/builtins objects are never patched.
_private_sys = types.SimpleNamespace(**vars(sys))
_private_sys.modules = _PrivateModules()
_private_sys.path = list(sys.path)
_private_util = types.SimpleNamespace(**vars(importlib.util))
_private_util.spec_from_file_location = lambda name, path: importlib.util.spec_from_file_location(_qualified(name), path)
_private_importlib = types.SimpleNamespace(util=_private_util)
_private_builtins = types.SimpleNamespace(**vars(builtins))


def _import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0:
        if name in RUNTIME_FILES: return _load(name)
        if name == "sys": return _private_sys
        if name == "builtins": return _private_builtins
        if name == "importlib.util": return _private_util if fromlist else _private_importlib
    return builtins.__import__(name, globals, locals, fromlist, level)


_private_builtins.__import__ = _import


def _load(name):
    if name not in RUNTIME_FILES: raise ValueError("unknown portable runtime module")
    with _LOCK:
        pins = verify_sources()
        path = HERE / (name + ".py")
        full = _qualified(name)
        old = sys.modules.get(full)
        if old is not None:
            if Path(old.__file__).resolve() != path:
                raise ValueError("private preview module name collision")
            return old
        if PREFIX not in sys.modules:
            package = types.ModuleType(PREFIX); package.__path__ = [str(HERE)]
            sys.modules[PREFIX] = package
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != pins[name + ".py"]:
            raise ValueError("portable runtime changed before execution")
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(full, path))
        module.__dict__["__builtins__"] = dict(vars(builtins), __import__=_import)
        sys.modules[full] = module
        try: exec(compile(raw, str(path), "exec"), module.__dict__)
        except BaseException: sys.modules.pop(full, None); raise
        return module


def load_runtime():
    """Return PreviewLoop/QualityPolicy/adapter APIs without flat-name imports."""
    return _load("controller")


def load_cli():
    """Return the unchanged operator CLI; loading does not invoke transports."""
    return _load("preview_cli")


def __getattr__(name):
    if name == "FeedbackPreviewLoop":
        from .feedback_preview import FeedbackPreviewLoop
        return FeedbackPreviewLoop
    if name in {"PreviewLoop", "QualityPolicy", "HaloBinding", "adapter", "AdapterError", "UncertainCall"}:
        return getattr(load_runtime(), name)
    raise AttributeError(name)
