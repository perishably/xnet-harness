# Staged accuracy preview lab

This source-checkout lab packages an audited practice controller with exact source pins. It owns no model, service, endpoint, VM, worker lifecycle or private evaluator. The five runtime sources and six dependencies are byte-identical to the accepted preview. `origin-verification.json` binds those files to the original acceptance receipt. No operator config, credentials, personal lifecycle state, official task input or private oracle is included.

## Source-checkout imports and commands

From the repository root:

```python
from lab.accuracy_preview import PreviewLoop, QualityPolicy, adapter, HaloBinding
# Or obtain the complete controller module explicitly:
from lab.accuracy_preview import load_runtime
runtime = load_runtime()
```

The package adapter loads the unchanged flat sources under a private module prefix. It preserves the public `xnet` modules, unrelated flat module names and real `sys.path`. No runtime transport is constructed by these imports.

```sh
python -B -m lab.accuracy_preview --help
python -B -m lab.accuracy_preview --config operator.json --dry-run
python -B -m lab.accuracy_preview --offline-checks
python -B -m unittest discover -s tests -p test_accuracy_preview_portable.py -v
```

The CLI defaults to dry-run. Dry-run validates public inputs, the proposal and factory source pin without importing the factory, creating a task namespace, invoking a model or worker, or performing lifecycle operations. The offline command runs only the authored alignment fixtures in a separate Python process. The public test launcher also checks import isolation.

For direct scripts the unchanged interface remains available:

```sh
python -B lab/accuracy_preview/preview_cli.py --config operator.json --dry-run
python -B lab/accuracy_preview/run_offline_checks.py
```

Python 3.11+ and Git are required for the authored snapshot tests. No third-party Python runtime dependency is required. This lab is available from a source checkout; it is not included in the standard wheel package.

## Registered practice policy

| Limit | Value |
| --- | --- |
| Model calls | 24 |
| Reported output tokens | 30000 |
| Active seconds | 900 |
| Measured prompt pin | 6400 |
| Maximum request generation | 1300, bounded by remaining output budget |
| Builder / Breaker / Arbiter calls | 12 / 6 / 6 |
| Actual public worker dispatches | At most 4 |

The default order is Builder, Breaker, Arbiter. The alternate preregistered order is Breaker, Builder, Arbiter; it changes only scheduling. All public tools remain available in every phase, with unchanged allocations and limits. Early finish yields a role. Empty Builder finish is held so patch progress can occur within its allocation. Terminal phase completion is saved durably before finalization; restart cannot add another final role call after a saved quota or finish.

The controller charges iteration checks, prewarm, packing/tokenizer work, generation, public actions, automatic review and actual final prediction freezing to active time. The caller must enforce the remaining transport deadline for both generation and public tests. Unknown outcomes stay reserved and stop reentry before prewarm, tokenizer or dispatch. No automatic retry or reconciliation is supplied. An interrupted final stage without its timing checkpoint also holds reentry.

## Metadata, reads and public review

Task-local source descriptors bind practice scope, task, repository, current revision, whole source SHA256 and byte length. The controller calls the actual shared `propose_prefetch` and `prefetch` APIs before each request. Prompt packing reads only hot `source_slices`, capped at 2048 source bytes. Retrieval uses an exact original issue prefix of at most 512 UTF-8 bytes; it does not summarize or replace the full pageable issue. README contract duplicates are omitted from source prefill.

Explicit `read` uses 1-based inclusive line bounds. It returns exact current text, capped at 64 lines and 8192 UTF-8 bytes, with source hash, omissions and next line. An unchanged covered request uses verified current CAS and returns real source text labeled `cached_source=true`; its prompt tokens still count. Changed revisions invalidate earlier hashes. A known source not yet prefetched can use the ordinary source path. Corrupt or superseded receipted CAS is refused. `issue` uses 0-based Unicode code point offsets with an exclusive end. Original issue text is preserved, and omitted bytes are never inferred absent.

A successful changed candidate receives deterministic `PublicReview`, and final finish checks or replays the exact current patch. Review binds one frozen public profile/SHA256, snapshot and patch. Same-patch replay adds zero new worker dispatches. An ordinary model `public-test` action uses the same gate and cap and consumes its model call. Automatic review adds no model calls and consumes active time. Passing requires exact public identities, integer zero exit status, confirmed cleanup, explicit false timeout/output clipping flags, and remaining registered time. Current cancellation and time are checked after actual final freezing. Late actual passing feedback stays visible but cannot produce `verified_public_accept`.

Public tests and evaluator paths are read-only under the shared adapter. A public pass describes only the exact profile result; task correctness remains ungraded. External practice feeds and evaluation sources are not admitted by this lab. A future feed needs a separate explicit opt-in adapter with task, scope and source verification.

## Caller integration

```python
session = adapter.RepositorySession.create(
    output_root, "practice-preview", public_five_field_task, approved_public_base_repo)
loop = PreviewLoop(
    session, measured_model_callback, measured_token_counter,
    bounded_public_worker=public_worker,
    public_profile=frozen_profile_name,
    public_profile_sha256=frozen_profile_sha256,
    scope="accuracy-preview-practice",
    policy=QualityPolicy(),
    halo_binding=HaloBinding(),  # staged, no activation
    cancelled=caller_cancellation_predicate)
try:
    prediction = loop.run(caller_model_name)
finally:
    loop.close()
    session.journal.close()
```

The task has exactly `instance_id`, `repo`, `base_commit`, `problem_statement`, `version`. Use this lab's exported adapter to construct or reopen sessions. The model request contains exact messages, measured tokens, phase, remaining generation budget and `remaining_active_seconds`. Its callback must enforce that deadline and return authenticated output usage.

```python
def public_worker(strict_public_test_request, *, remaining_seconds: float):
    # Caller transport enforces this hard deadline and confirms owned cleanup.
    # Return public-test feedback plus exact profile_hash and snapshot_hash.
    ...
```

The strict request fields remain `schema`, `instance_id`, `base_commit`, `snapshot_hash`, `patch_hash`, `patch`, `profile`. No shell command or task supplied program is accepted here. The caller chooses and attests its current ordinary model and exact endpoint; the lab ships no default service or personal process binding.

### HALO binding

`HaloBinding(proposal_file, mode="staged")` stages a valid proposal without activation. Active mode requires an actual current runtime observer returning a complete exact profile and launch binding, `artifact_pins_verified is True`, and `attestation_kind="actual-current-profile-and-process"`. The proposal binds model, tokenizer, template, configuration, runtime bundle, launch instance, PID/start time and actual command hash. Drift blocks continuation.

For active HALO the measured token counter, or its bound owner, exposes the latest actual `last_messages_sha256`, `last_rendered_sha256`, and `last_count`. A hash of JSON messages cannot stand in for the actual rendered template. The proposal must bind review 6400 and generation reserve 1300. A 6791 recall receipt establishes a context margin only, with no reasoning or accuracy guarantee. No activation or live diagnostic is claimed by packaging.

## Operator configuration

Paths resolve against the config file. The CLI requires a separately approved public practice declaration; this is operator admission, not an automatic authenticity classifier.

```json
{
  "schema": "xnet.accuracy-preview-operator-config.v1",
  "task_file": "public-practice-task.json",
  "source_repo": "public-practice-base",
  "namespace_root": "practice-output",
  "arm": "quality-preview",
  "scope": "accuracy-preview-practice",
  "task_origin": "operator-approved-public-practice",
  "model_name": "caller-current-model",
  "public_profile": "caller-public-profile",
  "public_profile_sha256": "<actual 64 lowercase hex profile hash>",
  "schedule": ["Builder", "Breaker", "Arbiter"],
  "halo": {"mode": "staged", "proposal_file": null},
  "runtime_factory": null
}
```

Only explicit `--run` constructs the caller runtime. Set `runtime_factory` to `{"path":"caller_runtime.py","sha256":"<actual source hash>"}`. Exact factory bytes are verified before compilation. Its `build_runtime(config)` returns `model_callback`, `token_counter`, `bounded_public_worker`, optionally `runtime_observer`, `cancelled`, `close`. Factory construction is a trusted operator boundary and should construct callbacks without dispatching work. `--reopen` is explicit and still refuses unknown outcomes or missing timing.

## Portable contents and evidence

Runtime files are `controller.py`, `metadata_bridge.py`, `halo_binding.py`, `frozen_integrations.py`, `preview_cli.py`. The complete dependency folder contains:

```text
dependencies/common_r02.py
dependencies/public_review.py
dependencies/repo_agent.py
dependencies/stream_index.py
dependencies/xnet/halo_context_v1.py
dependencies/xnet/protocol.py
```

Every dependency is verified before execution. A partial or changed folder fails closed. The package-level adapter changes import namespaces without rewriting these audited bytes. The standard public `xnet` package stays separate. No worker lifecycle helpers, protected dataset, grading artifact or private runtime configuration is required.

The original preview passed 25 offline checks plus seven independent focused checks. Packaged receipts in `evidence/` record the copied suite run and exact source/test/runner/log hashes. The first ten checks cover source prewarm, current revision, pass/replay, failed or incomplete review, uncertainty, rotation/fetch, profile drift, cancellation, schedule variation and budgets. Additional checks cover review caps, late feedback, issue paging, interrupted final timing, dry-run isolation, portable layout/drift, actual render receipts, public failure, final freeze cost, Builder progress, terminal recovery, cancellation after review and CAS integrity. All sources are authored public fixtures and all model/tokenizer/worker callbacks are fake. Only local Python/Git operations occur; no repository tests, live inference, network operation or hidden grader is run.

## Optional current public feedback context

`feedback_preview.py` adds an optional source-checkout subclass. The default `PreviewLoop` and CLI remain the baseline preview. Select the extension explicitly:

```python
from lab.accuracy_preview import FeedbackPreviewLoop
# Or: from lab.accuracy_preview.feedback_preview import FeedbackPreviewLoop
loop = FeedbackPreviewLoop(session, model_callback, measured_token_counter,
    bounded_public_worker=public_worker, public_profile=frozen_profile_name,
    public_profile_sha256=frozen_profile_sha256)
```

Its constructor and remaining API match `PreviewLoop`. `task_messages` includes the latest exact completed public review trace even after the full action observation rotates out. The extension checks the current candidate/profile/snapshot/policy binding, the immutable request and response CAS identities, and the completed action's durable journal receipts. An absent, stale or incomplete review gives no excerpt; corrupted identities are refused. It never runs a review or changes passing acceptance.

The task payload's `latest_public_review_feedback` contains an exact stdout prefix and stderr suffix under one combined **2048 UTF-8 byte** cap. Each stream records its original byte length/full SHA256, excerpt hash, UTF-8 byte offsets and omissions. The packet identifies the original review outcome CAS and its ordinary counted `fetch` action. If the outcome exceeds the existing 65536-byte fetch cap, it is explicitly labeled not publicly fetchable; the cap is not relaxed. No conclusions, trace summaries or repair instructions are generated.

The enriched task passes through the existing measured packing algorithm. Source and issue reductions can make room for the packet, and the final actual prompt count includes it. No model calls, worker dispatches, tools, budgets, schedule or acceptance rules are added. `feedback-preview-plan.json` pins the extension source and exact excerpt policy in each new namespace; drift is refused.

```sh
python -B -m unittest -v lab.accuracy_preview.test_feedback_preview
python -B -m lab.accuracy_preview.run_feedback_checks
```

The ten focused tests cover exact binding/pointer, stale patch, profile mismatch, corrupt CAS, changed SQL projection, multibyte cap/offsets, unknown review without retry, unchanged status/policy, measured feedback after rotation, and extension plan/source drift. They seed public JSON receipts and use authored local Git; no model, worker, repository test, network or private grader is invoked. The extension runner writes only `evidence/feedback-preview-checks-r01.*` and preserves the baseline acceptance evidence. The original thirteen source files remain byte-identical. Visibility testing does not establish a model accuracy improvement.
