"""Portable operator entry point; dry-run never constructs caller transports."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys

from controller import PreviewLoop, QualityPolicy, source_pins, adapter, canonical, digest
from halo_binding import HaloBinding

SCHEMA = "xnet.accuracy-preview-operator-config.v1"
FIELDS = {"schema", "task_file", "source_repo", "namespace_root", "arm", "scope", "task_origin",
          "model_name", "public_profile", "public_profile_sha256", "schedule", "halo", "runtime_factory"}


def pin(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise adapter.AdapterError("complete lowercase source SHA256 is required")
    return value


def path_from(base, value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise adapter.AdapterError("operator file path required")
    path = Path(value)
    return (path if path.is_absolute() else base / path).resolve()


def load_config(path):
    path = Path(path).resolve()
    if path.stat().st_size > 65536: raise adapter.AdapterError("operator config exceeds cap")
    raw = path.read_bytes(); config = json.loads(raw)
    if not isinstance(config, dict) or set(config) != FIELDS or config["schema"] != SCHEMA:
        raise adapter.AdapterError("operator config schema refused")
    if config["task_origin"] != "operator-approved-public-practice":
        raise adapter.AdapterError("preview accepts only separately approved public practice tasks")
    for name in ("arm", "scope", "public_profile"):
        if not isinstance(config[name], str) or not adapter.ID_RE.fullmatch(config[name]):
            raise adapter.AdapterError("bounded operator identifier required")
    if "official" in config["scope"].casefold(): raise adapter.AdapterError("separate practice scope required")
    if not isinstance(config["model_name"], str) or not 1 <= len(config["model_name"]) <= 200:
        raise adapter.AdapterError("bounded caller model name required")
    pin(config["public_profile_sha256"])
    policy = QualityPolicy(schedule=tuple(config["schedule"])).validate()
    for name in ("task_file", "source_repo", "namespace_root"):
        config[name] = str(path_from(path.parent, config[name]))
    task_path = Path(config["task_file"])
    if task_path.stat().st_size > adapter.MAX_FILE: raise adapter.AdapterError("public task exceeds cap")
    task_raw = task_path.read_bytes(); task = adapter.public_task(json.loads(task_raw))
    if not Path(config["source_repo"]).is_dir(): raise adapter.AdapterError("caller public source repo absent")
    if not isinstance(config["halo"], dict) or set(config["halo"]) != {"mode", "proposal_file"} or \
            config["halo"]["mode"] not in {"staged", "active"}:
        raise adapter.AdapterError("explicit HALO mode and optional proposal file required")
    if config["halo"]["proposal_file"] is not None:
        config["halo"]["proposal_file"] = str(path_from(path.parent, config["halo"]["proposal_file"]))
    factory = config["runtime_factory"]
    if factory is not None:
        if not isinstance(factory, dict) or set(factory) != {"path", "sha256"}:
            raise adapter.AdapterError("caller runtime factory needs an exact source pin")
        factory["path"] = str(path_from(path.parent, factory["path"]))
        source = Path(factory["path"])
        if source.stat().st_size > adapter.MAX_FILE or digest(source.read_bytes()) != pin(factory["sha256"]):
            raise adapter.AdapterError("caller runtime factory source drift")
    return config, task, policy, {"config_sha256":digest(raw), "task_file_sha256":digest(task_raw),
                                 "public_task_sha256":digest(canonical(task))}


def inspect_plan(config, task, policy, receipt):
    # Active validation needs an actual observer at run time. Dry-run explicitly
    # stages the proposal and makes no actual launch/profile attestation.
    staged = HaloBinding(config["halo"]["proposal_file"], mode="staged")
    return {"schema":"xnet.accuracy-preview-operator-dry-plan.v1", "status":"staged-only",
        "run_performed":False, "source_pins":source_pins(), "input_receipt":receipt,
        "instance_id":task["instance_id"], "repo":task["repo"], "base_commit":task["base_commit"],
        "policy":as_policy(policy), "scope":config["scope"], "metadata_mode":"practice",
        "public_profile":config["public_profile"], "public_profile_sha256":config["public_profile_sha256"],
        "halo_proposal":staged.plan(), "requested_halo_mode":config["halo"]["mode"],
        "runtime_factory_sha256":None if config["runtime_factory"] is None else config["runtime_factory"]["sha256"],
        "caller_observer_required":config["halo"]["mode"] == "active", "hidden_grading":False,
        "operations": {"model":0, "worker":0, "remote_fetch":0, "lifecycle":0}}


def as_policy(policy):
    from dataclasses import asdict
    return asdict(policy)


def factory_runtime(config):
    item = config["runtime_factory"]
    if item is None: raise adapter.AdapterError("run requires a pinned caller runtime factory")
    path = Path(item["path"]); raw = path.read_bytes()
    if digest(raw) != item["sha256"]: raise adapter.AdapterError("runtime factory changed before import")
    name = "_accuracy_preview_caller_" + item["sha256"]
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    try: exec(compile(raw, str(path), "exec"), module.__dict__)
    except BaseException: sys.modules.pop(name, None); raise
    runtime = module.build_runtime(config)
    required = {"model_callback", "token_counter", "bounded_public_worker"}
    if not isinstance(runtime, dict) or not required <= set(runtime) or set(runtime) - required - {"runtime_observer", "cancelled", "close"}:
        raise adapter.AdapterError("runtime factory returned unsupported caller API")
    return runtime


def run_config(config, task, policy, *, reopen=False):
    runtime = factory_runtime(config)
    session = loop = None
    try:
        halo = HaloBinding(config["halo"]["proposal_file"], mode=config["halo"]["mode"],
                           observer=runtime.get("runtime_observer"))
        root = Path(config["namespace_root"]) / config["arm"] / task["instance_id"]
        if reopen:
            session = adapter.RepositorySession(root)
            if session.task != task or session.metadata["arm"] != config["arm"]:
                raise adapter.AdapterError("reopened session differs from approved public task/arm")
        else:
            session = adapter.RepositorySession.create(config["namespace_root"], config["arm"], task, config["source_repo"])
        loop = PreviewLoop(session, runtime["model_callback"], runtime["token_counter"],
            bounded_public_worker=runtime["bounded_public_worker"], public_profile=config["public_profile"],
            public_profile_sha256=config["public_profile_sha256"], scope=config["scope"], policy=policy,
            halo_binding=halo, cancelled=runtime.get("cancelled"))
        loop.run(config["model_name"])
        return json.loads((session.root / "preview-outcome.json").read_bytes())
    finally:
        if loop is not None: loop.close()
        if session is not None: session.journal.close()
        if callable(runtime.get("close")): runtime["close"]()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--dry-run", action="store_true")
    choice.add_argument("--run", action="store_true")
    parser.add_argument("--reopen", action="store_true", help="explicitly reopen an existing namespace; uncertain outcomes still hold")
    args = parser.parse_args(argv)
    config, task, policy, receipt = load_config(args.config)
    if args.reopen and not args.run: parser.error("--reopen requires --run")
    result = run_config(config, task, policy, reopen=args.reopen) if args.run else inspect_plan(config, task, policy, receipt)
    print(canonical(result).decode())
    return 0


if __name__ == "__main__": raise SystemExit(main())
