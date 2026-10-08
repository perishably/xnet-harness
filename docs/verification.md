# Release verification

## XNET~ v0.1.0 alpha evidence status

This page separates evidence already produced from gates that still have to run on the final public source snapshot. Receipt hashes identify the private operator evidence without publishing model weights, private runtime roots, keys or launch settings.

### Blind50 operator-blind comparison: verified current evidence

Blind50 is a **custom frozen SWE-style repair battery**. It is not the official SWE-bench or SWE-bench Verified benchmark, and its scores must not be compared directly with those leaderboards. All 150 model choices across the three arms were frozen before the hidden suite was opened. Hidden grading made zero model calls, and the leakage audit recorded zero violations.

| Arm | First-attempt solves | Final solves | Calls | Retries | Recorded tokens | Median generation |
|---|---:|---:|---:|---:|---:|---:|
| Raw model | 29/50 | **32/50** | 65 | 15 | 55,133 | 7.423358 s |
| Retrieval only | 22/50 | **27/50** | 75 | 25 | 70,075 | 8.0034571 s |
| Full XNET | 24/50 | **29/50** | 72 | 22 | 69,856 | 8.21977155 s |

The paired results were:

| Comparison | Both solved | XNET/full only | Other arm only | Neither | Net final-solve delta for full XNET |
|---|---:|---:|---:|---:|---:|
| Full XNET vs raw | 26 | 3 | 6 | 15 | **-3** |
| Full XNET vs retrieval only | 24 | 5 | 3 | 18 | **+2** |

All eight preregistered initial checks are explicit:

| Check | Threshold | Observed | Result |
| --- | ---: | ---: | --- |
| Full minus raw | at least +5 final solves | -3 | **FAIL** |
| Full minus retrieval | at least +2 final solves | +2 | PASS |
| Full-lane P2P preservation | at least 48/50 tasks | 35/50 | **FAIL** |
| Candidate host execution | at most 0 | 0 | PASS |
| Hidden or retrieval leakage | at most 0 | 0 | PASS |
| Full median generation time | at most 15 s | 8.21977155 s | PASS |
| Provider telemetry completeness | every call | retrieval 74/75 | **FAIL** |
| Full/raw total-token ratio | at most 1.25 | unavailable because telemetry is incomplete | **FAIL** |

Final public F2P/P2P cases were Raw 38/50 and 41/50, Retrieval 31/50 and
36/50, and Full 34/50 and 38/50. Final hidden F2P/P2P cases were Raw 73/100
and 81/100, Retrieval 60/100 and 70/100, and Full 67/100 and 75/100.
Recorded input/output token counts were Raw 49,462/5,671, Retrieval
64,377/5,698 for the 74 calls with telemetry, and Full 64,434/5,422.
Selected retrieval cards/bytes were 0/0, 150/31,069, and 116/24,205.
Retrieval time was not separately instrumented. Aggregate prompt and decode
seconds were not sealed separately; total provider-generation/end-to-end
seconds were Raw 550.785656/567.268000, Retrieval 613.673990/633.102801, and
Full 608.761296/623.966000. The complete required-metric table, including
no-op/schema/timeout counts and unavailable abstention fields, is retained in
the [release notes](release-notes-v0.1.0.md#measured-private-evidence-xnet-blind-repair-50).

The preregistered improvement gate failed. Full XNET finished three solves behind raw and two solves ahead of retrieval only. This run therefore provides no evidence of score uplift over the raw 4B model and no evidence of flagship parity. It does provide a frozen, replayable comparison with bounded evaluation, zero detected leakage and explicit negative results.

Evidence identities:

| Evidence | SHA-256 or committed identity |
|---|---|
| Hidden-suite commitment | `eb1cf49e9e4e225393ea844d368118dccc421c71fcdf8438c15cb26a1a8f80f5` |
| Frozen-choices receipt | `f5264c0604465abbb804e0583e68074f363e6561d163da02a6f0a9c692f40ca4` |
| Hidden-grade receipt | `9a9aaa75128e3d756b84d57a4868a9e51cb6917356be09f43a1a15f1247b405b` |
| Final-summary receipt | `353d339918cb526cdac7c54a41941b24945e171307a40bb88e85c941b357ea2f` |
| Environment identity | `31925a1d1840b087ffe55cb2e8eeef869757fbf384d8c8c778187d6c97030f54` |
| Model identity | `qwen3.5-4b-q4km` |
| Model file | `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4` |
| Runtime | `d64f605adbf0668757115a522d602024ded6a7705bef1590a87034e4e9f6d212` |
| Source-pin manifest | `80cfa077029188746fd31ef3b0f58751945acdec4bb7983078e6c5471fd04b94` |
| Manifest receipt | `f686a60bbf4ddb317aa0e1dc18421c4bf63fc14ec8118dd8638cadd34e74644f` |

#### Transport reset and conservative reconciliation

After 138 attempt records had been produced, the local Vulkan server reset one connection during retrieval arm task `blind50r01--education-feedback--blank-answer`, attempt 2. The durable reservation was not dispatched again. It was reconciled as an empty status-599 response and therefore received zero credit. This deliberately conservative treatment prevents a transport retry from silently giving the affected arm an extra model attempt.

| Incident evidence | SHA-256 |
|---|---|
| Reconciliation file | `9d16a60ba3681300e3a5e8cea6f2845aff1b0148be0a6baf9fafec23ab12d3c9` |
| Immutable failed-attempt receipt | `9aca241526075c77312c21590aec8fdfe2d9246f28fd9e27f27196c93907af8f` |
| Successful resume configuration | `0e73b0e297d008df7820e4a345a5faf67d112dc22210669e1faa1657aec86c16` |
| Aborted first restart configuration | `3549d128830a6c303ed596e54690f2420015ce6cd1bccc092c252046f67e766d` |

The successful restart matched the original model, runtime and launch settings. The first restart stopped before benchmark work because of a PowerShell text-encoding name error; its receipt is retained rather than discarded.

### Focused component checks: verified current evidence

These checks are separate from Blind50. They verify bounded utility contracts and do not change or strengthen its model-score conclusion.

| Component | Observed result | Scope |
|---|---:|---|
| Component inventory/checker release surface | **16/16 passed** | Local/package-resource inventory, caller-fetched read-only checks, version probing and fail-closed refusal of every mutating entry point after adversarial review |
| Legions contract core | **18/18 passed** | Assignments bound to a caller-authenticated coordinator identity, replay refusal, bounded capacity, clock and wire-value limits, and one receipt per accepted assignment |

The updater's initial happy-path suite missed Windows junction swaps, stale apply, forged rollback state and concurrent-writer hazards. Those findings were reproduced; the unsafe state-writing implementation and helpers were removed. The supported v0.1.0 surface is local inventory plus caller-fetched read-only checking, and all mutation entry points refuse before fetch, process or filesystem effects. Installation is operator-owned. The Legions result does not prove a network daemon, remote execution, scheduling, quorum or distributed aggregation; those features are outside the tested contract core.

### Final local candidate checks

These commands ran after the release code and tests were frozen:

| Check | Final local result |
|---|---:|
| Python suite with the built native binary selected | **649 run: 648 passed, 1 skipped** |
| Locked main Rust workspace | **58 passed, 0 failed** |
| Locked Jcode Rust adapter workspace | **32 passed, 0 failed** |
| Component inventory/checker focused suite under `-W error` | **16/16 passed** |
| Legions focused suite under `-W error` | **18/18 passed** |
| Portable `xnet demo` | Passed; exact source round trip, 0 model calls, 0 network calls |
| `xnet updates inventory` | Passed; canonical local receipt, XNET~ report-only and Jcode v0.91.0 check-only |
| Apple project metadata validator | Passed; 9 source files and 17 authored core test cases; compilation/device flags remain false |

The one Python skip is the explicit Windows symbolic-link test on a host where
the current process lacks symlink-creation privilege. It is recorded as a
platform limitation, not counted as a pass. Local Rust verification used the
previously documented private LLVM/Zig `dlltool` wrapper because this Windows
GNU toolchain does not include its own import-library tool. The wrapper is not
part of the public source tree.

### Remaining publication gates

[The public release checklist](../RELEASE_CHECKLIST.md) is the canonical list
of blocking gates and evidence requirements. The results above do not close an
unchecked checklist item. The dated maintainer affirmation is recorded in
`PROVENANCE.md`; the final snapshot still has to be shown byte-identical to the
reviewed candidate and bound to its commit and manifest identities.

Unless the checklist gains retained completion evidence, the release owner must
still:

- freeze and review the public claims against the coverage inventory,
  verification record, security policy and exact Blind Repair, mobile and
  Legions boundaries;
- complete the final license, third-party, provenance and private-data review,
  including redistribution rights and exclusion of credentials, model weights,
  restricted benchmark answers and private provider or user material;
- create and inspect the clean one-commit snapshot, refresh `MANIFEST.in` and
  `source-manifest.json`, and pass the exact inventory checks;
- run and retain the secret, private-data and large-file scans over the
  worktree, complete reachable one-commit Git object set and built artifacts;
- build and inspect final artifacts from that snapshot, then run the required
  smoke tests and applicable focused checks from the extracted artifact;
- run hosted Windows and Ubuntu CI at the exact release commit and inspect the
  individual job logs, counts and skips; and
- verify the public repository from a fresh unauthenticated clone and record
  the final URL, commit, manifest, artifact, CI and scanner identities in the
  external release record.

## Earlier source-preparation checks

The source tree was checked during release preparation on Windows with Python 3.12.14 and Rust 1.99.0. These results describe their recorded runs; the final-snapshot gates above remain pending. Tests used synthetic public sources and fresh temporary roots. No model inference, cloud replication or external target execution was required.

| Check | Observed result |
|---|---|
| Python utility suite before native build | 275 tests: 268 passed, 7 skipped |
| Rust utility workspace after parallel fixture correction | 51 passed, zero failed |
| Separate Jcode Rust adapter workspace | 32 passed, zero failed |
| Native Python SDK checks after build | All 7 passed, including the 6 previously skipped native checks |
| Strict curator intake and inactive observations | 12 passed; related HCE/HALO checks also passed |
| Added portable outer/Jcode/bridge/learning/control closure | 222 tests passed across completed group checks; interrupted aggregate attempts retained |
| Native source packet and literal citation contracts | 14 passed; no native provider call |
| Editable installation | Passed without runtime dependencies |
| Installed command from outside the source directory | Demo passed; exact source round trip, no models or network |

The remaining Python skip required Windows symlink privileges. The suite initially exposed a synthetic fixture omission and two renamed test-label errors; those were corrected before the successful full run. A supplemental native test initially treated a serialized occurrence envelope as plain source text; it was corrected to verify the envelope and its task/event bindings. Failed development attempts were retained locally.

The first hosted Ubuntu run passed all 287 Python tests plus both Rust workspaces and the demo. Its Windows counterpart exposed a fault-injection fixture that compared a temporary-directory alias against the controller's canonical destination. The test now targets the transfer's actual declared destination root; all pending-state, committed-hop and resumed-cycle assertions remain. The utility implementation is unchanged. The original failed run remains in Actions.

A subsequent hosted Windows log exposed a concurrent Rust fixture collision (`WriterLeasePresent` in `xnet-gates`). Its combined multi-command shell step allowed later successful commands to mask that failure. The Rust fixtures now allocate exclusive directories with process-local atomic nonces, and an eight-thread equal-timestamp regression passes locally. Every native CI command now has its own step. The earlier overall green status is not treated as proof that the Rust workspace passed.

Portable closure checks initially encountered a long temporary-path fixture issue and an expensive pacing test that repeated 71 complete circulation cycles merely to reach its quota. Test child paths were shortened. The pacing fixture now uses two real cycles and the original 600-entry queue, verifying all ten real reads, rollover, unchanged policy and queue identity. Its runtime implementation is unchanged. The interrupted aggregate results and completed group checks remain in private preparation receipts; the expanded full-suite CI is a separate gate.

The first expanded Ubuntu run exercised 523 Python tests and exposed an SDK startup race: the native process emitted a valid lease refusal and exited before the initial health write flushed. A second broken-pipe error during cleanup hid the typed refusal. The SDK now accepts only the independently validated startup rejection in that situation, sends no second request, and finishes cleanup without replacing the original error. Controlled-process regressions cover startup rejection, corrupted replies, later transport failure and preservation of a completed response. The actual existing-lease control is unchanged. Hosted reruns are a separate gate; inspect their job logs as well as their conclusion.

Linux explicitly skips the seven Windows retained-handle integrity controls and 24 fast-epoch controls that require those actual Windows leases. These skips are platform limitations, not passing substitutes for Windows behavior. The Windows job exercises those controls. Native process tests must run on both platforms after the CLI build.

The expanded Windows run also correctly refused promotion in a synthetic success fixture when host I/O timing exceeded its cost bound. The fixture now supplies a controlled callback clock, verifies the exact recorded baseline/candidate wall costs, and keeps evaluator/process deadlines real. A separate expensive-candidate case confirms that additional solves still cannot bypass the unchanged cost gate. No production learner, repair or promotion rule changed for this correction.

The authored Swift/C# bridge references are **not compiled or device-validated**. Windows cannot build/sign an iPhone app; neither the Apple nor the required Windows native AI SDK was exercised by these utility checks. Context packet tests verify bytes, refusal behavior and literal citation attribution only.

The Windows GNU toolchain lacked an assembler for its bundled import-library tool. Local verification used an existing Zig import-library tool through a fixed, private wrapper. This workaround changes no public source and is not distributed. Users should use a complete supported Rust toolchain. CI is configured to build on Windows and Ubuntu with the runner's toolchain; consult Actions for hosted status.

## Reproduce from a source checkout

```sh
python -m pip install -e .
cargo test --locked --workspace --manifest-path rust/Cargo.toml
cargo build --locked --manifest-path rust/Cargo.toml -p xnet-cli
cargo test --locked --workspace --manifest-path adapters/jcode/rust/Cargo.toml
python -m unittest discover -s tests -v
python -m xnet demo
```

Native tests use the built `rust/target/debug/xnet` executable (`xnet.exe` on Windows). If using a different Cargo target directory, set `XNET_NATIVE_BINARY` to that exact build. A missing binary produces explicit skips rather than successful native validation.

`source-manifest.json` lists exact public source file sizes and SHA-256 hashes. It does not hash itself. Private runtime roots, model weights, keys, launch settings and operator receipts are excluded.

## What these checks establish

They exercise source integrity, task separation, durable handoff and acknowledgment replay, refusal of corrupted data, bounded inert evaluation and harness policy gates. They establish utility behavior on these fixtures. They are not benchmark results for model intelligence, live cloud durability, long-context reasoning or harness accuracy uplift. Engine calibration and curator trials require their own artifact identities and evidence.
