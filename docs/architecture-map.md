# HALO / Oroboros architecture map

[![XNET Harness HALO and Oroboros architecture map](xnet-halo-oroboros-architecture.svg)](xnet-halo-oroboros-architecture.svg)

This map shows how the portable XNET~ Harness contracts can surround a caller-owned model. It also separates source that is present and contract-tested in this repository from optional deployment components and proposed future architecture. An arrow shows an allowed data flow, not proof that an external service is connected or that a model result is correct.

## How to read the status marks

| Mark | Meaning |
| --- | --- |
| **Proven here** | Source is included and its stated contract behavior is exercised with synthetic fixtures or bounded local tests. This does not certify a live deployment, model capability, semantic correctness or performance. |
| **Optional / caller** | The caller chooses, provisions, authenticates and validates the named hardware, application, network or provider. The repository may include a narrow adapter or protocol boundary. |
| **Planned** | Proposed architecture only. The release makes no implementation or performance claim for it. |
| **Trust boundary** | Data needs fresh admission, identity, scope and result checks before it crosses the line. |

The [portable coverage inventory](coverage.md) is the detailed release boundary. The [component architecture](architecture.md), [Oroboros contract](oroboros.md) and [HALO contract](halo.md) describe the corresponding interfaces.

## Portable core around the model

The model is centered because context, evaluation and receipts flow around a selected inference engine. The model process itself remains caller-owned. XNET does not bundle weights, start a hosted provider, inherit the model's credentials or grant tools through context.

The intake layer contains four distinct contracts that an application can compose:

1. The caller selects and classifies source bytes and keeps a trusted expected identity outside the untrusted record.
2. RAG selects bounded source slices. Selection can reduce prompt size, but it does not make an answer true.
3. HCE binds exact UTF-8 source bytes and metadata to complete SHA-256 identities. HCE provides addressing and byte integrity, not compression by itself and no action authority.
4. The OpenClaw source gate admits only a bounded, caller-classified public, context-only envelope. The upstream OpenClaw application, runner and tools are not included or executed by that gate.

The scoped capsule store, ledger and content-addressed storage retain identities and receipts. A digest establishes a byte match only when the expected digest is independently trusted.

## HALO pins and Oroboros rotation

HALO policy is specific to one complete engine profile: model, runner bundle, tokenizer, prompt template, launch and decoding configuration, context capacity and generation reserve. A different engine or configuration needs a different profile and evidence. HALO consumes an exact caller-reported rendered prompt measurement and returns review and headroom advice with `authority: none`. It has no default global threshold and performs no rotation.

Oroboros provides the handoff contract around that advice: verify and select source context, reserve output space, freeze a handoff, ask the caller to create a fresh session, bind its acknowledgment, and reconcile an uncertain callback before retrying. Rotation replays selected context; it does not move hidden state or a KV cache between engines.

## Repair comparison and feedback loop

The [Blind Repair 50 protocol](blind-repair50.md) defines three counterbalanced arms around one unchanged model:

| Arm | Model-visible addition |
| --- | --- |
| Raw | Public issue, source, evaluator capability declaration and strict changed-file schema |
| Retrieval | Raw plus deterministic cards from one frozen public corpus |
| Full XNET | Retrieval plus HCE card identities, the XNET route and bounded accordion expansion after a public failure |

All three arms use the same strict admission and bounded evaluator. Each receives at most one retry with public-test feedback; hidden feedback stays host-side. Choices freeze before held-out grading, and grading performs no model calls. The map describes this implemented comparison machinery and does not publish a benchmark score or imply unseen generalization.

The broader repair loop can retain a public failure, propose a changed-file replacement, reject malformed or no-op proposals, evaluate candidate source as bounded AST data, and retry under a declared policy. Promotion gates can change retrieval, routing or guidance only after a declared outcome and cost rule passes. The loop does not update model weights, and a tie or regression retains the incumbent.

## OpenClaw and NullClaw gates

The two names refer to separate local boundaries in this release:

- The included OpenClaw adapter validates source and proposal envelopes. Producer names are labels rather than authentication, source text stays inert data, and every storage or tool action needs separate authority.
- The included XNET `NullClaw` control records cancellation, source containment, staging quarantine and bounded worker-receipt checks. It is distinct from the separately obtained upstream Zig application.

These gates reduce what crosses a boundary. They do not make a model output safe, authenticate an external peer by name, or replace an application sandbox.

## Optional storage and phone rings

`C:` and `4 TB` in the picture are recognizable deployment examples for the historical logical identifiers `c_nvme` and `d_4tb`. The portable API accepts caller-selected directories; it does not require those drive names, discover capacity or prove that roots are on different physical devices. Four logical directories on one disk still represent four logical stages.

The sphere controller exercises scoped circulation and exact local readback across four designated roots. Proton Drive and Google Drive can be optional archive destinations only after the caller configures approved folders and excludes private control state, credentials, model files and private learning material. A hash match in a desktop sync folder proves local readback. A remote-provider claim requires a separate authenticated provider retrieval and exact-byte check. A minimum local setup does not need the four-root sphere or any cloud provider; see the [minimum Oroboros blueprint](minimum-oroboros.md).

The phone path is also optional. The release includes pure pairing, protocol and host-gateway gates plus a source-authored SwiftUI scaffold, while the TLS listener, trusted receipt store, dispatcher, app signing, device execution and end-to-end transport remain caller-owned or unvalidated. NetBird may provide private reachability, but it does not replace application authentication. A phone may act as a controller or relay. It may act as a small-model worker only after the exact hardware, model, memory and thermal fit, policy and per-device HALO evidence are measured. See [native intelligence adapters](native-intelligence.md).

## Legions local core and planned scale-out

The Legions panel has two status bands. The **proven here** band is the local, transport-free protocol core in `xnet/legions.py`: canonical capability cards and job capsules, typed resource ceilings, worker policy and admission checks, authenticated-coordinator binding supplied by the embedding application, kill and revocation controls, bounded replay state, and HMAC-SHA256-authenticated result receipts. Its tests cover exact schemas and hashes, target and allowlist checks, budget and expiry limits, replay refusal, key mismatch, and receipt binding. The library describes and verifies work; it does not transmit or execute it.

The HMAC receipt authenticates bytes between holders of a caller-supplied shared secret. It is not a digital signature, does not provide nonrepudiation, and does not prove honest resource measurement or semantic correctness. Job capsules are content-addressed and admitted under local policy; the current core applies HMAC-SHA256 only to result receipts.

The **planned** band contains the distributed runtime around those contracts:

1. Networking and peer transport with mutual authentication, encryption, backpressure and bounded messages.
2. A coordinator or node daemon, opt-in discovery and invitations, key rotation, removal and revocation distribution.
3. Sandbox execution and actual resource-budget enforcement, scheduling, leases, retries, persistence and crash recovery.
4. Task-specific quorum and aggregation with independent verification and conflict handling.

Context carries no tool authority, and private archives remain outside a job unless their owner explicitly scopes selected bytes. The `1 → N` diagram is an architecture shape for independently admitted jobs. It is not evidence of a working network, linear speedup, quality improvement, aggregate throughput or continuous availability.

Future distributed layers still need threat modeling and tests for malicious or stale capability cards, task disclosure, transport identity, replay across restarts, equivocation, node revocation, uncertain completion, verifier independence and retention. See the [Legions protocol core](legions.md) for the exact implemented contract and roadmap boundary.
