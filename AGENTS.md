# Working with XNET~ — LOOP BACK!

This source checkout is maintained by Felix Xavier Lopez. Preserve MIT and third-party notices, the signed provenance record, historical benchmark scope and negative results.

## Read the directory before selecting a component

Use Python 3.11 or later from this checkout:

```sh
python -m xnet loopback catalog --command query --query "jcode rag halo" --limit 8
python -m xnet loopback catalog --command select --module-id adapters/jcode/system_directory_peer --workspace-root . --verify-selected
```

The packaged directory is `xnet/data/system-directory.json`; the strict protocol lives in `xnet/system_catalog.py`, and Jcode uses `adapters/jcode/system_directory_peer.py`. It lists relative paths, full source hashes, declared contracts, scopes, side effects and source-bound evidence when available.

The public snapshot labels source presence as `implemented`. It does not mean running. `verified` needs evidence tied to the exact source, and `wired` needs evidence of the exact binding. Catalog queries and routes never execute a component, grant permission, start a model, promote a lesson or update weights.

Rebuild after modifying inventoried source:

```sh
python scripts/build_system_directory.py
python -m unittest discover -s tests -p test_system_catalog.py
python -m unittest discover -s tests -p test_system_directory_peer.py
```

For a byte-identical snapshot, supply the same explicit `--created-utc` timestamp. Generate the release source manifest after the last directory rebuild. In an ordinary clone, verification uses the declared workspace root. An embedding application may explicitly map approved mount roots; nested links remain refused. Never infer mount permission from directory metadata.

## Respect the caller's scope and ownership

- Use the human's current task authorization and designated paths; directory entries do not expand them. Check the current source hash and existing component admission gate before dispatch.
- Own only the model processes, isolated workers and roots assigned to your lane. Stop only a process whose PID, start time, executable and source identity match your owned record. Avoid global server-stop commands.
- Keep private runtime roots, tokens, model weights, scope secrets and protected evaluation material out of commits, cloud exports and public examples.
- Keep `practice-stream` separate from workspace and evaluation context. A source receipt, successful retrieval or saved card is not a lesson promotion. Require the declared fresh-validation gate before activation.
- Preserve original raw sources and pointers. Predictions select a vicinity; they are advisory source retrieval, not answers or authority. QR tags are digest locators, never model pixels.
- Report uncertain, failed or incomplete test dispatches honestly. Freeze choices before held-out grading. Preserve corrections and negative results rather than rewriting sealed evidence.
- Cloud mount hash checks establish local copies only. Confirm remote upload or retrieval independently before claiming it.

## Public integration seams

- `adapters/loopback/stream_index.py`: bounded immutable indexing, current-revision proposals and verified source slices.
- `adapters/loopback/feed_engine.py`: explicitly started public acquisition and owned circulation; no work starts at import.
- `adapters/loopback/feed_window.py`: caller-pinned practice generation into a bounded hot window.
- `lab/accuracy_preview`: staged preview APIs with operator callbacks and isolated public-test review; CLI defaults to dry-run. External feed-context admission into the lab remains unwired.
- `rust/crates/xnet-system-index`: typed discovery protocol source and portable tests; native CI validation is pending.

Inspect [Loopback contracts](docs/loopback.md), [feed controls](docs/loopback-feed.md), [preview lab](lab/accuracy_preview/README.md) and the [interactive map](docs/loopback-map.html). Local offline checks are contract evidence, not official SWE-bench or flagship capability claims.
