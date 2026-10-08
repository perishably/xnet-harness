"""Bounded offline step/query/demo; no daemon or feed acquisition lifecycle."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import time

from .stream_index import MetadataIndex, ReadOnlyMount, Limits, IndexErrorClosed, canonical, digest, sha256, source_descriptor, strict_json


def utc():
    return datetime.now(timezone.utc).isoformat()


def load_config(path):
    raw = Path(path).read_bytes()
    if len(raw) > 16384:
        raise IndexErrorClosed("CLI config exceeds bound")
    value = strict_json(raw)
    fields = {"root", "scope_id", "task_id", "mode", "adapters", "limits"}
    if type(value) is not dict or set(value) != fields or type(value["adapters"]) is not dict:
        raise IndexErrorClosed("closed CLI config schema required")
    adapters = {}
    for alias, row in value["adapters"].items():
        if type(row) is not dict or set(row) != {"root", "tier"}:
            raise IndexErrorClosed("closed read-only adapter config required")
        adapters[alias] = ReadOnlyMount(row["root"], tier=row["tier"])
    return MetadataIndex(value["root"], adapters=adapters, scope_id=value["scope_id"], task_id=value["task_id"], mode=value["mode"], limits=Limits(**value["limits"]))


def demo(root):
    """Index and warm before a question, then point to exact source slices."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    source = root / "public-sources"
    source.mkdir()
    contents = {
        "codec.py": "def decode(line):\n    \"\"\"Encoding and quoted-field boundary example.\"\"\"\n    return line.split('|')\n",
        "queue.py": "def next_job(jobs):\n    \"\"\"FIFO scheduling; empty input is explicit.\"\"\"\n    return jobs[0] if jobs else None\n",
        "README.md": "Public offline examples for metadata-first source retrieval. No generated answers.\n",
    }
    rows = []
    for name, text in contents.items():
        raw = text.encode()
        (source / name).write_bytes(raw)
        family = "encoding" if name == "codec.py" else "scheduling" if name == "queue.py" else "documentation"
        rows.append(source_descriptor(scope_id="offline-demo", task_id="demo-task", source_id=name, adapter="c", relative_path=name, repo="xnet/demo", revision="public-r1", source_sha256=sha256(raw), source_bytes=len(raw), language="python" if name.endswith(".py") else "markdown", task_family=family, tags=[family], provenance="workspace-source", upstream_receipt_sha256=digest({"synthetic_public_demo": name, "source_sha256": sha256(raw)})))
    (root / "public-descriptors.json").write_bytes(canonical(rows))
    started, before = utc(), time.monotonic()
    with MetadataIndex(root / "index", adapters={"c": ReadOnlyMount(source)}, scope_id="offline-demo", task_id="demo-task") as index:
        intake = index.step(rows)
        # Planned-work metadata is available before the user question.
        prewarm = index.propose_prefetch("encoding decode boundaries", repo="xnet/demo", revision="public-r1", task_family="encoding")
        fetched = index.prefetch(prewarm, cancelled=lambda: False)
        before_question = index.status()
        slices = index.source_slices("decode quoted fields", repo="xnet/demo", revision="public-r1", task_family="encoding")
        review = index.fetch_verified_source(slices["rows"][0]["metadata_sha256"], expected_source_sha256=slices["rows"][0]["source_sha256"])
        checkpoint = index.checkpoint({"kind": "offline-demo", "accuracy_review": "source provenance verified; task answer not generated or graded"})
        source_pins = {name: sha256((Path(__file__).resolve().parent / name).read_bytes()) for name in ("stream_index.py", "cli.py")}
        report = {"schema": "xnet.metadata-demo.v1", "source_pins": source_pins, "started_utc": started, "finished_utc": utc(), "monotonic_elapsed_seconds": time.monotonic() - before, "intake": intake, "prewarm": prewarm, "fetch": fetched, "before_question": before_question, "source_slices": slices, "review_source_sha256": review["source_sha256"], "checkpoint_sha256": checkpoint["event_sha256"], "models_called": 0, "token_savings": "not-measured", "coding_accuracy": "not-measured", "remote_cloud_retrieval": "not-measured"}
        (root / "demo-receipt.json").write_bytes(canonical(report))
        return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="operation", required=True)
    command = commands.add_parser("demo")
    command.add_argument("--root", required=True)
    for name in ("step", "query", "status"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True)
        if name == "step":
            command.add_argument("--batch", required=True)
            command.add_argument("--max-records", type=int, default=16)
        elif name == "query":
            command.add_argument("--text", required=True)
            command.add_argument("--repo", required=True)
            command.add_argument("--revision", required=True)
            command.add_argument("--family")
            command.add_argument("--prefetch", action="store_true")
    args = parser.parse_args(argv)
    if args.operation == "demo":
        value = demo(args.root)
    else:
        with load_config(args.config) as index:
            if args.operation == "step":
                path = Path(args.batch)
                if path.stat().st_size > 64 * 8192:
                    raise IndexErrorClosed("metadata batch exceeds bound")
                rows = strict_json(path.read_bytes())
                value = {"intake": index.step(rows, max_records=args.max_records), "status": index.status()}
            elif args.operation == "query":
                parameters = {"repo": args.repo, "revision": args.revision, "task_family": args.family}
                proposal = index.propose_prefetch(args.text, **parameters)
                fetched = index.prefetch(proposal, cancelled=lambda: False) if args.prefetch else []
                value = {"proposal": proposal, "fetch": fetched, "source_slices": index.source_slices(args.text, **parameters)}
            else:
                value = index.status()
    print(canonical(value).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
