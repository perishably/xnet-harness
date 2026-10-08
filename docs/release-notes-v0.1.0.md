# XNET~ v0.1.0 MIT public source release

![XNET~ build quote: XNET~ — LOOP BACK!](xnet-build-quote.svg)

**XNET~ — LOOP BACK!** Preserve the source, verify the result, and feed the
evidence into the next bounded pass.

- Author: **Felix Xavier Lopez**
- License: [MIT](../LICENSE)
- Release type: development-stage public source release

XNET~ v0.1.0 is a model-agnostic harness for source-bound context, bounded
evaluation, evidence-gated harness learning, and caller-owned integrations.
The supported distribution boundary is a source checkout. The release does
not include model weights, a hosted provider, private runtime state, private
benchmark fixtures, credentials, or a resident scheduler. Publication remains
subject to the human gates in the [release checklist](../RELEASE_CHECKLIST.md)
and the signed [provenance statement](../PROVENANCE.md).

This note separates shipped implementation and private measured evidence. A
hash identifies the bytes of a cited private report; it does not independently
prove the report's claims.

## Implemented source in v0.1.0

| Area | Included implementation | Boundary |
| --- | --- | --- |
| Source identity and storage | HCE source capsules, full SHA-256 identities, content-addressed stores, append receipts, and separate Python/Rust evidence stores | HCE provides byte identity and addressing. It does not compress a prompt by itself, classify a source, or grant authority. See [native HCE/HALO](native-hce-halo.md) and [Oroboros](oroboros.md). |
| Context and handoff | Bounded retrieval, configuration-specific HALO observations, fresh-session Oroboros handoff, acknowledgments, and uncertain-outcome reconciliation | The caller owns the model, tokenizer, session, credentials, and lifecycle. HALO advice applies only to the attested configuration. See [HALO](halo.md) and the [architecture](architecture.md). |
| Repair and harness learning | Strict changed-file admission, semantic no-op refusal, bounded AST evaluation, public-feedback retry, immutable choices before held-out grading, procedural memory, scaffold comparison, and promotion gates | Candidate Python remains data and is not imported into the host interpreter. Learning changes validated harness guidance, retrieval, or routing; it does not update model weights. See the [adaptive repair contract](adaptive-repair-contract.md). |
| Blind comparison machinery | Frozen three-arm Raw / Retrieval / Full XNET protocol, public corpus, reservation receipts, freeze-before-grade workflow, cost accounting, and report generation | The machinery is implemented and the final private run is reported below. The initial benchmark gate failed; the result does not support an uplift claim. See [Blind Repair 50](blind-repair50.md). |
| Application seams | Jcode history/context/learning adapters, OpenClaw source admission, local XNET NullClaw controls, Hermes procedural-memory data exchange, local-provider contracts, mobile pairing/protocol/gateway gates, and explicit model-ladder policy | These are narrow source or protocol interfaces. The upstream applications, live providers, phone transport, and model runners are separately obtained and caller-owned. See [extension points](extension-points.md) and [coverage](coverage.md). |
| Native source examples | Authored Apple Swift/SwiftUI and Windows C# source, plus metadata and pure protocol checks | Native model calls, signing, installation, and device behavior are not certified. See [native intelligence](native-intelligence.md). |
| Legions protocol core | Canonical capability cards and job capsules, local worker admission, budget ceilings, HMAC-authenticated result metadata, replay refusal, revocation, and a local kill switch | The core describes and admits work. It does not transmit, schedule, sandbox, or execute it. See [Legions](legions.md). |
| Component inventory and update check | A reviewed local registry for XNET~ and Jcode v0.91.0, canonical inventory receipts, fixed version probes and caller-fetched read-only release checks | An adversarial release review broke the original mutating stage/apply/rollback design through Windows junction swaps, stale apply, forged local state and concurrent writers. Those mutations are disabled in v0.1.0. The caller owns bounded HTTP fetching and installation. See [update center](update-center.md). |
| Optional native utilities | Rust workspace and Jcode Rust adapter with locked dependency graphs, source storage, audit, task-history, context, and policy crates | Native and Python persistence are separate. A versioned adapter is required to exchange evidence between them. |

The detailed inclusion boundary is the [portable coverage inventory](coverage.md).
The eight-date release-candidate history is summarized in the
[build timeline](build-timeline.md).

## Public safety and refusal evidence

The repository's utility tests exercise failures with synthetic sources, inert
callbacks, temporary roots, and bounded local transports. They establish the
listed contract behavior on those fixtures; they are not a security
certification or a model-safety score.

| Refusal or containment behavior | Public evidence |
| --- | --- |
| Reject complete model-supplied bundles, provenance fields, duplicate or unrequested paths, malformed schemas, unchanged files, semantic no-ops, and hidden feedback | [Adaptive repair tests](../tests/test_adaptive_repair_contract.py) |
| Keep candidate code out of Python imports; reject dunder access, dynamic capabilities, unsupported paths, oversized bundles, and hidden or mixed evaluator reports | [Bounded SWE repair evaluator tests](../tests/test_swe_repair_evaluator.py) |
| Poison a run after artifact drift, unavailable paths, refused scope, or changed pinned selections; retain explicit integrity state | [Artifact integrity guard tests](../tests/test_artifact_integrity_guard_v3.py) |
| Reject tampered or missing sphere objects and keep optional cloud-folder readback distinct from authenticated remote-provider proof | [Sphere tests](../tests/test_oroboros_sphere.py) and [public export tests](../tests/test_oroboros_public_export.py) |
| Refuse public bind targets, redact pairing secrets, reject replay or conflicting request IDs, and prevent blind redispatch after an uncertain mobile outcome | [Pairing tests](../tests/test_mobile_pairing.py) and [gateway tests](../tests/test_mobile_gateway.py) |
| Refuse altered, expired, over-budget, replayed, or revoked Legions work and refuse work while the local kill switch is active | [Legions tests](../tests/test_legions.py) |
| Preserve a validated native startup refusal even when process I/O fails during cleanup | [SDK cleanup tests](../tests/test_sdk_cleanup.py) |

Reproduction commands and platform limitations are recorded in
[release verification](verification.md). The [security policy](../SECURITY.md)
documents the trust boundaries and private reporting route.

## Measured private evidence: spent 4B regression board

Three private reports, identified before this note by their exact SHA-256, cover
a fixed-weight 4B lane on an already spent eight-task dojo/regression board:

- `kimi-epoch3-terminal-histogram-2026-10-07.md` —
  `0539f6b96213c1b1c55249297f6c5538e1e208b5bf3d1e0145b3ee36684c6a55`
- 4B performance/signature-card supplied-report identity —
  `c8d02b47549b00e01c0dc699f9a8e85362087491b621e6cd2b4f7a84c70db307`.
  The later local working file named `kimi-4b-perf-sigcard-2026-10-07.md`
  has SHA-256
  `db9295bf4f279e53138b205cadc277b1d81e093a640580360b6aed748595aa9d`
  and is not represented as the same bytes.
- `kimi-victory-lap-r01-2026-10-07.md` —
  `588651c7270085b1c1d404068f588282cd8583026fd4f0d697d398c9f828d707`

One sealed victory-lap run resolved all hidden cases for **7 of 8 tasks**.
Across separate sealed evidence chains, successful receipts exist for **all 8
of 8 tasks**. This is not a single-run 8/8 result. The terminal-histogram task
was chain-sensitive: a successful chain used the exact repair card and one
retry carrying the concrete `IndexError`; the victory-lap chain instead
returned two no-ops and remained unresolved. The reports state that model
weights stayed fixed and that the changes were task-specific harness guidance
and bounded retry policy.

These private report files are not part of the public source distribution, and
this release did not replay their private grader or inspect their hidden
fixtures. The result supports closure on a previously used board. It does not
show unseen generalization, cross-task transfer, flagship-model parity, or an
official SWE-bench result. The complete claim boundary is in the
[Epoch 3 evidence note](epoch3-4b-regression-board.md).

## Measured private evidence: XNET Blind Repair 50

[XNET Blind Repair 50](blind-repair50.md) is the separate frozen transfer
comparison. It is a custom frozen SWE-style benchmark and is not SWE-bench or
SWE-bench Verified. All three arms used the same unchanged local model, strict
candidate admission, bounded interpreter, and at most one public-feedback
retry. Candidate code was never imported into the host Python interpreter.

| Final metric | Raw | Retrieval only | Full XNET |
| --- | ---: | ---: | ---: |
| Hidden tasks solved / 50 | **32/50** | **27/50** | **29/50** |
| Solved on first attempt / 50 | 29/50 | 22/50 | 24/50 |
| Model calls | 65 | 75 | 72 |
| Retries | 15 | 25 | 22 |
| Recorded total tokens | 55,133 | 70,075 (74/75 calls) | 69,856 |
| Median generation time | 7.423358 s | 8.0034571 s | 8.21977155 s |
| Invalid candidates | 20 | 37 | 28 |
| Semantic no-op candidates | 6 | 8 | 8 |
| Leakage violations | 0 | 0 | 0 |

| Paired comparison | Both solved | Full XNET only | Other arm only | Neither | Full XNET net |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full XNET vs Raw | 26 | 3 | 6 | 15 | **-3** |
| Full XNET vs Retrieval only | 24 | 5 | 3 | 18 | **+2** |

Every preregistered initial gate is reported below. The initial gate is the
conjunction of all eight checks, so one failed check makes the declared gate
fail.

| Preregistered check | Threshold | Observed | Result |
| --- | ---: | ---: | --- |
| Full minus Raw final solves | at least +5 | -3 | **FAIL** |
| Full minus Retrieval final solves | at least +2 | +2 | PASS |
| Full-lane P2P preservation | at least 48/50 tasks | 35/50 | **FAIL** |
| Hidden or retrieval leakage | at most 0 | 0 | PASS |
| Candidate host executions | at most 0 | 0 | PASS |
| Full median generation time | at most 15 s | 8.21977155 s | PASS |
| Complete provider telemetry | every call | Retrieval 74/75 | **FAIL** |
| Full/Raw total-token ratio | at most 1.25 | unavailable because telemetry is incomplete | **FAIL** |

The remaining required metrics from the sealed summary are retained here,
including unavailable fields rather than silently dropping them.

| Metric | Raw | Retrieval only | Full XNET |
| --- | ---: | ---: | ---: |
| Final public F2P cases | 38/50 | 31/50 | 34/50 |
| Final public P2P cases | 41/50 | 36/50 | 38/50 |
| Final hidden F2P cases | 73/100 | 60/100 | 67/100 |
| Final hidden P2P cases | 81/100 | 70/100 | 75/100 |
| Recorded input / output tokens | 49,462 / 5,671 | 64,377 / 5,698 (74/75 calls) | 64,434 / 5,422 |
| Selected retrieval cards / bytes | 0 / 0 | 150 / 31,069 | 116 / 24,205 |
| Retrieval-only seconds | unavailable; not separately instrumented | unavailable; not separately instrumented | unavailable; not separately instrumented |
| Total generation / end-to-end seconds | 550.785656 / 567.268000 | 613.673990 / 633.102801 | 608.761296 / 623.966000 |
| Median / p95 generation seconds | 7.423358 / 17.967032 | 8.003457 / 13.615996 | 8.219772 / 14.706580 |
| Tokens per final joint solve | 1,722.90625 | unavailable because telemetry is incomplete | 2,408.827586 |
| Seconds per final joint solve | 17.727125 | 23.448252 | 21.516069 |
| No-op / schema-error / timeout candidates | 6 / 14 / 0 | 8 / 29 / 0 | 8 / 20 / 0 |
| Abstentions | unavailable | unavailable | unavailable |

Prompt and decode *token rates* were retained per call, but aggregate prompt
seconds and aggregate decode seconds were not sealed as separate fields; they
are therefore unavailable. The sealed summary retains provider-generation,
callback, admission, and end-to-end timing instead.

The initial benchmark gate failed. Raw solved 32/50 while Full XNET solved
29/50, with a paired net of -3. The result therefore does **not** support a
harness-uplift claim, unseen superiority claim, or flagship-model parity
claim. Retrieval only also finished below Raw. These null and negative results
are retained rather than reframed as wins.

All 150 arm/task choices were frozen before the held-out suite was opened.
Grading made zero model calls, and the run recorded zero leakage violations.
The Retrieval-only token and generation aggregates cover 74 calls with known
provider telemetry; the status-599 reset has no provider metrics and remains
zero credit. The release pins and sealed identities are:

- caller-attested source commit:
  `87ba50c270cc02abff437567f4f130f5cc397121`;
- source-pin manifest:
  `80cfa077029188746fd31ef3b0f58751945acdec4bb7983078e6c5471fd04b94`;
- model SHA-256:
  `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4`;
- runtime SHA-256:
  `d64f605adbf0668757115a522d602024ded6a7705bef1590a87034e4e9f6d212`;
- grade receipt:
  `9a9aaa75128e3d756b84d57a4868a9e51cb6917356be09f43a1a15f1247b405b`;
- summary receipt:
  `353d339918cb526cdac7c54a41941b24945e171307a40bb88e85c941b357ea2f`;
- frozen choices receipt:
  `f5264c0604465abbb804e0583e68074f363e6561d163da02a6f0a9c692f40ca4`;
- hidden-suite commitment:
  `eb1cf49e9e4e225393ea844d368118dccc421c71fcdf8438c15cb26a1a8f80f5`;
- environment identity:
  `31925a1d1840b087ffe55cb2e8eeef869757fbf384d8c8c778187d6c97030f54`.

The frozen candidate environment receipt
`benchmark-environment-r08-operator-blind.json` has file SHA-256
`3cb9849df1bf2c4f2ac27bdb64000e2b1ea65f4fc2febbcf2cbccd53e98de704`.
It records Qwen 3.5 4B Q4_K_M on llama.cpp Vulkan, full GPU-layer offload,
disabled prompt caching, one parallel slot, an 8,192-token context, and the
hardware identified in the [build timeline](build-timeline.md). That private
receipt binds the reported run environment and is not shipped in the public
source package.

One reserved attempt encountered a provider connection reset. The harness did
not redispatch an uncertain request, used no hidden data, and assigned a
zero-credit schema rejection. The private reconciliation file
`transport-reconciliation-r08-01.json` has SHA-256
`9d16a60ba3681300e3a5e8cea6f2845aff1b0148be0a6baf9fafec23ab12d3c9`.
The immutable failed-attempt receipt is
`9aca241526075c77312c21590aec8fdfe2d9246f28fd9e27f27196c93907af8f`;
the same-configuration restart receipt is
`0e73b0e297d008df7820e4a345a5faf67d112dc22210669e1faa1657aec86c16`.
The failure remains in the totals as status 599 and zero credit.

## iPhone and native limits

The iPhone directory contains a SwiftUI source scaffold, deterministic source
slicing, literal citation checks, explicit pairing/send/retry controls, and a
metadata validator. It has **not** been compiled with Xcode, signed, installed,
or run on an iPhone. No Apple on-device inference, token behavior, memory fit,
thermal behavior, background recovery, NetBird path, home-host dispatch, or
end-to-end TLS flow has been verified. The optional phone-local `xnet-4b` lane
has no bundled runner or model. The remote `home-4b` then `home-14b` route is a
source protocol and pure gateway gate; the listener, trusted stores, and model
dispatcher remain caller-owned. See the [Apple source README](../examples/native/apple/README.md).

The Windows native bridge is also source-only. Passing packet and citation
tests does not establish access to a Windows native model API on a particular
machine. Neither platform source silently falls back to a public cloud model.

## Legions: implemented core and future runtime

The implemented Legions contract is transport-free. It canonicalizes bounded
capability cards, content-addressed job capsules, and HMAC-authenticated result
receipts using HMAC-SHA256. A worker's local gate checks coordinator, task, capability, expiry,
and advertised plus local budget ceilings. Local state refuses job/nonce and
receipt replay, revoked nodes or jobs, and work after the kill switch is set.
The embedding application must supply worker-specific keys, clocks,
persistence, and actual process/container resource enforcement.

Peer transport, authenticated discovery and invitations, network daemons,
sandbox execution, scheduling, durable distributed control state, retries,
team management, quorum, aggregation, and throughput claims remain future
work. An HMAC-authenticated usage statement is shared-key integrity metadata.
Any key holder can create an indistinguishable statement, so it is not a
digital signature, provides no nonrepudiation, and is not proof of honest
measurement or correct output. See the [Legions protocol core](legions.md) and
the [design boundary](extension-points.md#legions-distributed-compute).

## Publication gate

Felix Xavier Lopez signed the dated
[provenance statement](../PROVENANCE.md) on 2026-10-07. The release is ready to
publish only after every remaining blocking item in the
[release checklist](../RELEASE_CHECKLIST.md) passes: a clean one-commit public
snapshot, secret and large-file scans, applicable tests, exact inventory
verification, archive inspection, and verification from a fresh public clone.
The final commit and artifact hashes must be recorded in the external release
record associated with the signed attestation.
