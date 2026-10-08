"""Six exact sources, with an optional portable dependencies folder.

Compile only verified bytes. Legacy imports in the unchanged shared review are
resolved inside its module, without changing r02 source or module globals.
"""
import builtins
import hashlib
import importlib.util
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
GATES, WORK = HERE.parent, HERE.parent.parent
PINS = {
    "repo_agent.py": "07b406329a8cf2794c322b4c06ac69c62ef43268d6af551f22f9a9f0fef1a32b",
    "xnet/protocol.py": "79442a457765753dcffd629847d504ad652e8af3f70b736fc3e58181bebed443",
    "xnet/halo_context_v1.py": "e1f5c9c2f0b6f4f9a817f9a405f59e9e74a6ef7255a29e8f47504c3d5714e84e",
    "common_r02.py": "060cedd08c4bc192daed7b437f1d3b3fd73539335ae5642450bfea5384cbaa95",
    "public_review.py": "215d397665c6eb2fd23bd85c66ba76b767ca3758d51f1af5fce35e5ba797cacc",
    "stream_index.py": "5999d5894c07f8a7d514659a8a9bcf477f1ec077f368188a2e1da0e4a16e7c94",
}
LOCAL = {
    "repo_agent.py": WORK / "official-swebench-local-20261008-r01" / "adapter" / "repo_agent.py",
    "xnet/protocol.py": WORK / "home-feedback-20261008-r03" / "source" / "xnet" / "protocol.py",
    "xnet/halo_context_v1.py": WORK / "home-feedback-20261008-r03" / "source" / "xnet" / "halo_context_v1.py",
    "common_r02.py": GATES / "xnet_arm_r02" / "common_r02.py",
    "public_review.py": GATES / "accuracy_review" / "public_review.py",
    "stream_index.py": GATES / "metadata_stream_index" / "stream_index.py",
}
BUNDLED = HERE / "dependencies"
PATHS = {key: BUNDLED / key for key in PINS} if BUNDLED.exists() else LOCAL


def verify():
    for key, expected in PINS.items():
        if hashlib.sha256(PATHS[key].read_bytes()).hexdigest() != expected:
            raise ValueError("approved integration source drift: " + key)
    return dict(PINS)


def load(name, key, *, imports=None):
    path, expected = PATHS[key], PINS[key]
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("approved source changed before execution: " + key)
    if name in sys.modules:
        old = sys.modules[name]
        if Path(old.__file__).resolve() != path.resolve():
            raise ValueError("integration module name collision")
        return old
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    if imports:
        def dependency_import(import_name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and import_name in imports: return imports[import_name]
            return builtins.__import__(import_name, globals, locals, fromlist, level)
        module.__dict__["__builtins__"] = dict(vars(builtins), __import__=dependency_import)
    sys.modules[name] = module
    try: exec(compile(raw, str(path), "exec"), module.__dict__)
    except BaseException: sys.modules.pop(name, None); raise
    return module


verify()  # Verify every source before executing even the first dependency.
adapter = load("repo_agent", "repo_agent.py")
package_name = "_accuracy_preview_frozen_xnet"
if package_name not in sys.modules:
    package = types.ModuleType(package_name)
    package.__path__ = [str(PATHS["xnet/protocol.py"].parent)]
    sys.modules[package_name] = package
protocol = load(package_name + ".protocol", "xnet/protocol.py")
halo = load(package_name + ".halo_context_v1", "xnet/halo_context_v1.py")
core = types.ModuleType("_accuracy_preview_core_facade")
core.adapter, core.source_pins, core.modules = adapter, verify, {"halo_context_v1": halo}
common = load("_accuracy_preview_common", "common_r02.py", imports={"frozen_core_r02": core})
metadata = load("_accuracy_preview_metadata", "stream_index.py")
review = load("_accuracy_preview_public_review", "public_review.py",
              imports={"common_r02": common, "frozen_core_r02": core})
