# Extension points

XNET~ Harness extends through narrow, caller-owned interfaces. This release has no global plugin registry. New integrations should add a versioned data contract or callable adapter, keep authority with the caller and use synthetic tests that run without a live account, model or network.

## Common contract

Every extension should define:

- a versioned input and output shape with exact-field validation;
- the caller that owns lifecycle, credentials and authorization;
- byte, token, time, retry and cost limits;
- complete source and artifact identities;
- behavior for denial, timeout, crash and an uncertain outcome;
- durable receipts where an external side effect may occur; and
- a test that observes zero protected calls after a refusal.

Do not silently fall back to a different model, source, transport or trust level.

## Model and provider adapters

Current seams:

- [xnet/local_provider.py](../xnet/local_provider.py) defines LocalProviderProfile, profile persistence, response normalization, a bounded chat-completion call and a diagnostic probe.
- [xnet/model_ladder.py](../xnet/model_ladder.py) validates an explicit routing policy, request, selected route and outcome.
- Repair and learning loops borrow caller-supplied generation callbacks rather than owning a model process.
- Source-only application peers live under [adapters](../adapters/).

A new adapter should live in adapters/provider-name when it is application-specific. Keep model startup, shutdown, credentials and endpoint selection outside the harness. Pin the complete model and runner identity, validate the actual response shape, report measured usage without inventing missing metrics, bound timeouts and response bytes, and retain an uncertain transport result for reconciliation. Add a loopback or fake transport test that makes no provider call.

Do not add a provider label to a generic route unless the route's configuration and evidence identify what actually ran.

## Retrieval and context selection

Current seams:

- [xnet/rag.py](../xnet/rag.py) provides RagCatalog and PredictiveRagQueue for local, policy-checked source selection.
- [xnet/hce_capsule_v1.py](../xnet/hce_capsule_v1.py) preserves exact UTF-8 source bytes and complete source/capsule hashes.
- [xnet/memory.py](../xnet/memory.py) and [xnet/procedural_memory.py](../xnet/procedural_memory.py) provide local memory contracts with separate validation and promotion.

Retrievers may propose bounded source ranges or ranked records. They must not authorize a fetch, classify a source as public without caller review, rewrite the original bytes, hide clipping or treat retrieved instructions as tool commands. Return source IDs, complete hashes, byte ranges, ranking inputs and a deterministic selection receipt. Measure the complete rendered prompt with the caller's actual tokenizer after selection.

Test empty results, stale indexes, changed bytes, cross-task references, budget overflow, embedded instructions and denied scope.

## HALO evidence and proposed certificates

Current seams:

- [xnet/halo_context_v1.py](../xnet/halo_context_v1.py) binds EngineProfile, ContextPinProposal and HaloPinRegistry to a complete engine configuration and evidence pins.
- [xnet/halo_observation_v1.py](../xnet/halo_observation_v1.py) represents an unbound observation that remains inactive.
- [rust/crates/xnet-halo](../rust/crates/xnet-halo/) mirrors the native contract.

There is no generic HALO certificate authority or portable HaloCertificate type in this release. A certificate proposal must therefore start as a versioned design. It should bind the model, runner bundle, tokenizer, template, launch configuration, declared capacity, generation reserve, evaluation manifest, outputs, grader, measured prompt occupancy and validity interval. Define the signer trust root, key rotation, revocation and offline verification. A certificate may report evidence for that exact configuration; it must not claim universal safety, reasoning quality or authorship.

Keep new evidence inactive until an independent verifier accepts every required binding. Include negative vectors for changed configuration fields, shortened hashes, stale evidence, unknown signers and revoked keys.

## Evaluators

Current seams:

- [xnet/repair_evaluator.py](../xnet/repair_evaluator.py) evaluates a restricted Python subset as AST data.
- [xnet/swe_repair_evaluator.py](../xnet/swe_repair_evaluator.py) validates bundles, import graphs, cases and public feedback.
- [xnet/scaffold_learning.py](../xnet/scaffold_learning.py) and [xnet/inference_promotion.py](../xnet/inference_promotion.py) consume caller-supplied verifier outcomes under declared promotion rules.

An evaluator must publish its admitted language, resource limits, case schema, comparison rule and result schema. Keep candidate code out of the host import system. If general execution is required, propose a separately reviewed isolation boundary and document what escapes remain possible. Freeze evaluator code and visible inputs before held-out grading, retain raw outputs, separate infrastructure errors from task failures and make a timeout fail closed.

Do not modify a frozen benchmark to add an evaluator. Build a separate synthetic fixture or propose a new benchmark version.

## Storage transports

Current seams:

- [xnet/brains.py](../xnet/brains.py) implements caller-designated local content-addressed roots and receipt chains.
- [xnet/ledger.py](../xnet/ledger.py) owns the Python ledger and local CAS.
- [xnet/oroboros_public_export.py](../xnet/oroboros_public_export.py) separates a bounded public projection from private control state.
- [rust/crates/xnet-storage](../rust/crates/xnet-storage/) defines hot, warm and cold tier rules; only verified hot CAS bytes can enter inference.

A new remote or removable-storage transport should accept selected content-addressed objects and return a versioned transfer receipt. Verify source bytes before sending, destination bytes after writing and authenticated provider retrieval when claiming remote durability. Caller code owns credentials, account selection and root initialization. Never place private authorities, inference responses or scope keys in a public archive. Record incomplete and unknown transfers without destructive retry.

Tests should use a temporary fake provider and cover corruption, stale readback, duplicate completion, interrupted transfer, identity mismatch, scope denial and credential redaction.

## Claw integrations

The project uses two deliberately different boundaries:

- [adapters/openclaw/source_gate.py](../adapters/openclaw/source_gate.py) validates bounded public, context-only packets. It does not execute OpenClaw, a model or a tool.
- [xnet/nullclaw.py](../xnet/nullclaw.py) provides local cancellation, source containment, staging quarantine and admission of a fixed worker receipt. It is distinct from the upstream NullClaw agent.

A new Claw adapter must say whether it is a data peer, control peer or external application bridge. Do not combine those roles implicitly. Source packets carry no authority. Control operations require caller authorization before dispatch, a narrow operation allowlist, complete receipt verification and a local kill path. Keep each upstream application's lifecycle and license separate, and retain its notice for copied or adapted MIT material.

## Legions distributed compute

The transport-free core in [xnet/legions.py](../xnet/legions.py) implements canonical capability cards, content-addressed job capsules, a local worker gate, budget ceilings, HMAC-authenticated result metadata, replay refusal, revocation and a local kill switch. It describes and admits work but does not transmit or execute it. The embedding application still owns clocks, keys, persistence and actual resource enforcement. Any holder of the shared HMAC key can create an indistinguishable receipt, so these receipts are not digital signatures and provide no nonrepudiation. See the implemented scope and limits in [docs/legions.md](legions.md).

Peer transport, node discovery and invitations, sandbox enforcement, scheduling, durable control state, quorum and aggregation remain design work. Use the [Legions design issue](../.github/ISSUE_TEMPLATE/legions-design.yml) before submitting one of those layers.

A viable design must specify all of these invariants:

1. **Explicit opt-in nodes.** An operator enrolls each node and can inspect and remove it. No ambient discovery or silent participation.
2. **Allowlisted job types.** Nodes accept versioned, narrow operations rather than arbitrary commands or model-supplied code.
3. **Budgets.** Each job has hard CPU, memory, storage, network, wall-time, retry and monetary limits, enforced by the node.
4. **Capability advertisement.** An authenticated, expiring statement reports what a node can actually run, with its key and trust model stated explicitly and without treating a label as proof.
5. **Content-addressed inputs.** Jobs bind complete hashes, sizes, classification and authorized source references before dispatch.
6. **Authenticated receipts.** Reservations, starts, results, failures and cancellations bind job, node, inputs, outputs and policy version under a documented shared-key or asymmetric trust model.
7. **Result verification or quorum.** The caller defines deterministic verification or an independence-aware quorum and records dissent. Agreement alone is not semantic truth.
8. **Secret isolation.** Jobs receive the minimum scoped capability; secrets, private ledgers and host credentials stay outside worker inputs and logs.
9. **Revocation and kill switch.** Operators can revoke nodes, keys and jobs, stop new dispatch and cancel bounded work locally even when the coordinator is unavailable.
10. **Recovery.** Unknown outcomes are reconciled before retry; duplicate delivery is idempotent and completed results are immutable.

Start with a threat model, wire schemas and an inert single-process simulator. Any prototype must remain disabled by default and describe which invariants are implemented, tested or still only proposed.
