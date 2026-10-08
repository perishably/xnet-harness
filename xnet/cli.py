"""XNET command line entrypoint."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from . import __version__
from .hce_capsule_v1 import encode_capsule, decode_capsule, render_face
from .protocol import sha256


def main(argv=None):
    parser = argparse.ArgumentParser(prog="xnet", description="XNET~ source-context utility")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version")
    sub.add_parser("demo")
    capsule = sub.add_parser("capsule")
    capsule.add_argument("--text", required=True)
    capsule.add_argument("--ring", type=int, default=1)
    capsule.add_argument("--kind", default="note")
    capsule.add_argument("--face", choices=("machine", "en", "zh"), default="machine")
    initialize = sub.add_parser("init", help="create a secret-free local model profile")
    initialize.add_argument("--path", required=True)
    initialize.add_argument("--base-url", required=True)
    initialize.add_argument("--model", required=True)
    initialize.add_argument("--model-sha256", required=True)
    initialize.add_argument("--runtime-sha256", required=True)
    initialize.add_argument("--context-tokens", required=True, type=int)
    initialize.add_argument("--max-output-tokens", required=True, type=int)
    initialize.add_argument("--temperature", type=float, default=0.0)
    initialize.add_argument("--seed", type=int, default=0)
    doctor = sub.add_parser("doctor", help="probe one configured numeric-loopback provider")
    doctor.add_argument("--profile", required=True)
    doctor.add_argument("--timeout-seconds", type=float, default=5.0)
    benchmark = sub.add_parser("benchmark", help="prepare, run, freeze and grade a frozen repair comparison")
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_command", required=True)
    prepare = benchmark_commands.add_parser("prepare")
    prepare.add_argument("--root", required=True)
    prepare.add_argument("--public-suite", required=True)
    prepare.add_argument("--hidden-suite-sha256", required=True)
    prepare.add_argument("--protocol", required=True)
    prepare.add_argument("--corpus", required=True)
    prepare.add_argument("--profile", required=True)
    prepare.add_argument("--environment")
    run = benchmark_commands.add_parser("run")
    run.add_argument("--root", required=True)
    run.add_argument("--profile", required=True)
    run.add_argument("--timeout-seconds", type=float, default=120.0)
    run.add_argument("--task-id", action="append", default=None)
    freeze = benchmark_commands.add_parser("freeze")
    freeze.add_argument("--root", required=True)
    grade = benchmark_commands.add_parser("grade")
    grade.add_argument("--root", required=True)
    grade.add_argument("--hidden-suite", required=True)
    report = benchmark_commands.add_parser("report")
    report.add_argument("--root", required=True)
    report.add_argument("--profile", required=True)
    report.add_argument("--source-commit", required=True)
    report.add_argument("--output")
    route = sub.add_parser("route", help="select Apple-native, qualified 4B or home 14B")
    route.add_argument("--policy", required=True)
    route.add_argument("--request", required=True)
    route.add_argument("--after-lane", choices=("apple-native", "xnet-4b", "home-14b"))
    route.add_argument("--prior-outcome-sha256")
    outcome = sub.add_parser("outcome", help="bind verifier evidence to a model route")
    outcome.add_argument("--route", required=True)
    outcome.add_argument("--status", required=True,
                         choices=("verified", "failed", "abstained", "unavailable"))
    outcome.add_argument("--evidence-sha256", action="append", default=[])
    updates = sub.add_parser("updates", help="inspect the pinned XNET~ component registry")
    update_commands = updates.add_subparsers(dest="updates_command", required=True)
    update_commands.add_parser(
        "inventory",
        help="print the reviewed component inventory without network or process access",
    )
    args = parser.parse_args(argv)
    if args.command == "version":
        print(json.dumps({"application": "xnet", "version": __version__}))
        return 0
    if args.command == "init":
        from .local_provider import LocalProviderProfile, save_profile
        profile = LocalProviderProfile(base_url=args.base_url, model=args.model,
            model_sha256=args.model_sha256, runtime_sha256=args.runtime_sha256,
            context_tokens=args.context_tokens, max_output_tokens=args.max_output_tokens,
            temperature=args.temperature, seed=args.seed)
        print(json.dumps({"profile": profile.as_dict(), "write": save_profile(args.path, profile)},
                         sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "doctor":
        from .local_provider import doctor_profile, load_profile
        print(json.dumps(doctor_profile(load_profile(args.profile), timeout_seconds=args.timeout_seconds),
                         sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "updates":
        from .component_updates import ComponentUpdateCenter
        center = ComponentUpdateCenter.from_default_manifest()
        print(center.inventory_receipt().decode("ascii"), end="")
        return 0
    if args.command in ("route", "outcome"):
        from .model_ladder import record_outcome, select_route
        if args.command == "route":
            policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
            request = json.loads(Path(args.request).read_text(encoding="utf-8"))
            result = select_route(policy, request, after_lane=args.after_lane,
                                  prior_outcome_sha256=args.prior_outcome_sha256)
        else:
            route_value = json.loads(Path(args.route).read_text(encoding="utf-8"))
            result = record_outcome(route_value, status=args.status,
                                    verifier_evidence_sha256=args.evidence_sha256)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "benchmark":
        from .blind_repair_benchmark import (freeze as freeze_benchmark, grade as grade_benchmark,
            local_provider_callback, prepare as prepare_benchmark, release_note, run as run_benchmark,
            summarize)
        from .local_provider import load_profile
        if args.benchmark_command == "prepare":
            result = prepare_benchmark(args.root, public_suite=args.public_suite,
                hidden_suite_sha256=args.hidden_suite_sha256, protocol=args.protocol,
                corpus=args.corpus, provider_profile=args.profile,
                environment_receipt=args.environment)
        elif args.benchmark_command == "run":
            profile = load_profile(args.profile)
            result = {"attempts": len(run_benchmark(args.root,
                local_provider_callback(profile, timeout_seconds=args.timeout_seconds),
                task_ids=args.task_id))}
        elif args.benchmark_command == "freeze":
            result = freeze_benchmark(args.root)
        elif args.benchmark_command == "grade":
            result = grade_benchmark(args.root, args.hidden_suite)
        else:
            summary = summarize(args.root)
            profile = load_profile(args.profile)
            note = release_note(summary, model_label=profile.model,
                source_commit=args.source_commit, model_sha256=profile.model_sha256,
                runtime_sha256=profile.runtime_sha256)
            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(note, encoding="utf-8")
            result = {"summary": summary, "release_note": note, "output": args.output}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    text = "Exact public source context.\n" if args.command == "demo" else args.text
    source = text.encode("utf-8")
    try:
        wire = encode_capsule(source, expected_source_sha256=sha256(source),
            ring=1 if args.command == "demo" else args.ring,
            kind="note" if args.command == "demo" else args.kind,
            classification="public")
        value = decode_capsule(wire, expected_sha256=sha256(wire))
    except ValueError as error:
        parser.error(str(error))
    if args.command == "demo":
        print(json.dumps({"source_roundtrip_verified": value["text"].encode("utf-8") == source,
            "source_sha256": sha256(source), "capsule_sha256": sha256(wire),
            "model_calls": 0, "network_calls": 0, "authority": "none"}))
    else:
        print(render_face(value, face=args.face))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
