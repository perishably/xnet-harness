# Portable harness coverage

XNET is a utility harness around a caller-selected model. Its reusable source
keeps context, storage, repair, learning and adapter lifecycles explicit. A model
runner and each external application retain their own lifecycle. The geometry
of a model at the center of rings is a visualization of data flow. The
[visual system map](architecture-map.md) uses the same included, caller-managed
and planned boundaries.

## Included foundations

| Layer | Source interfaces | What they provide |
| --- | --- | --- |
| Native fabric | Rust workspace; `xnet_sdk` | Hash-addressed source storage, append receipts, task histories, context capsules and caller-owned gateway |
| Context rings | `context_ouroboros`, `oroboros_session` | Source-bound context selection, measured occupancy and explicit session handoff/ACK |
| Four-silo sphere | `oroboros_sphere`; membrane scripts | Scoped byte-verified circulation through four caller-designated roots and two fixed lanes |
| Outer Oroboros | `oroboros_outer` | Finite intake → context → session → work → freeze → validate → learn → archive → commit queue, with STOP and pending recovery |
| Public archive | `oroboros_public_export` | Bounded public source projection, exact readback and separate private control state |
| HALO | `halo_context_v1`, `halo_grid_v1`, `halo_observation_v1` | Caller evidence and engine/config-specific context observations; unbound observations remain inactive |
| HCE | `hce_capsule_v1`, `hce_curator_v1` | Exact source-backed capsule faces and curator proposals requiring independent confirmation |
| Retrieval | `rag`, `memory`, `procedural_memory` | Local source catalog/slices and outcome-bound procedural guidance |
| Repair | `repair_loop`, inert repair evaluators and suites | No-op checks, bounded feedback/retry, retained outputs, freeze before held-out grading and resumable receipts |
| Learning | `scaffold_learning`, `learning_cycle`, `learning_epoch`, `learning_wing` | Proposal, matched practice/validation and evidence/cost-gated promotion without weight changes |
| Cost control | `learning_epoch_fast_v4`, `artifact_integrity_guard_v3` | Fresh source hashes and explicit artifact boundaries; retained Windows read leases avoid repeated full large-artifact reads |
| Practice | `dojo_curriculum`, `dojo_exposure`, `dojo_home_practice` | Finite authored tasks, conservative cumulative exposure accounting and fifty fictional home cases |
| Routing | `inference_promotion`, `routing_protocols` | Evidence-bound routing and promotion records supplied by caller evaluators |

The legacy artifact guard v1 is present for the predecessor regression test. It
is not the preferred guard. No module automatically enables another layer.

## Included release contracts and boundaries

| Surface | Included source | Included behavior | Boundary |
| --- | --- | --- | --- |
| Blind Repair 50 and benchmark environment | `blind_repair_benchmark`, `benchmark_environment`; `benchmarks/blind-repair50/v1` | Frozen three-arm prepare/run/resume/freeze/held-out-grade/report workflow, public protocol and retrieval corpus, plus a sanitized receipt binding the provider profile, model/runtime identities, cache isolation and performance controls | Public and held-out task suites, model weights, provider runtime, run roots and private operator receipts are not shipped. The recorded run is a custom negative transfer result, not SWE-bench evidence or an uplift claim. |
| Component inventory and update checker | `component_updates`; `xnet/data/components.json` | Deterministic packaged inventory, caller-fetched read-only release checks and an explicit caller-owned version probe | v0.1.0 disables `stage`, `apply` and `rollback`; each refuses before fetch, process or filesystem effects. The module has no HTTP client, and installation remains operator-owned. |
| Legions contract core | `legions` | Canonical capability cards, job capsules and HMAC result receipts with authenticated-coordinator binding, local allowlists, budgets, replay limits, revocation and a kill switch | The core opens no socket and runs no work. Peer transport, discovery, sandbox enforcement, scheduling, durable control state, quorum and aggregation remain planned runtime layers. |
| Local-provider contract | `local_provider` | Pinned numeric-loopback OpenAI-compatible profiles, bounded JSON requests and responses, exact body hashes, normalized metrics and read-only health/model probes | The caller starts, selects and licenses the server and model. Profiles contain no credentials, headers, launch commands or downloads; generated text remains data and is never imported or executed. |
| Mobile gateway, pairing and protocol | `mobile_gateway`, `mobile_pairing`, `mobile_protocol` | Pure host-side request admission, in-memory single-use pairing and bounded canonical messages that bind private addresses, TLS context, source evidence, explicit send intent, replay state and fixed home-model identities | The modules create no listener, manage no VPN, persist no trusted credential store, and start no model. TLS termination, transport, evidence resolution, dispatch, device qualification and live end-to-end operation remain caller-owned or unverified. |
| Model ladder | `model_ladder` | Deterministic Apple-native → device-qualified 4B → home 14B routing and outcome receipts with pinned identities, capabilities, context limits, offline policy and a fixed 14B ceiling | The ladder does not launch a model, infer device eligibility, trust model self-assessment or verify answer quality. Engines, weights, fit evidence and acceptance decisions remain caller-supplied. |

## Included adapter interfaces

| Adapter | Ownership and behavior |
| --- | --- |
| Jcode context/history | Accepts an explicitly selected offline history export and borrows the caller's native gateway |
| Jcode sphere/outer | Passes completed sphere sources into context; binds optional session and learning stages without owning inference |
| Jcode learning/procedural memory | Exchanges public failure guidance, proposals and promoted catalog records |
| OpenClaw source gate | Admits scoped source/proposal packets; does not bundle or execute the upstream application |
| Local XNET NullClaw | Cancellation, containment, quarantine and receipt checks; distinct from the upstream Zig agent |
| Hermes procedural memory | Data adapter for source-bound procedural memory; upstream Hermes Agent is not bundled |
| Offline bridge | Validates one caller-pinned export and records resumable admission into a borrowed gateway |
| Mobile enrollment | Records a caller-selected phone transfer proof; device identity and phone compute remain unproven |
| iPhone source app | Authored SwiftUI scaffold with protected local originals, deterministic byte-slice retrieval, literal citation checks, and explicit private-gateway pairing/send/retry controls; metadata is validated, while Swift compilation, device inference and live transport remain untested |
| Borrowed learning transport | Bounded numeric loopback chat-completions callback with retained request/response evidence; the caller starts and selects its server |
| Dojo control | Authenticated loopback start/stop/status dashboard around explicit caller callbacks |
| Sphere arbitration/pacing | Serializes one caller-owned sphere and waits for its existing source-I/O quota; does not retry unknown work or relax policy |

The module name `adapters.kimi.learning_transport` records the adapter's origin.
Its endpoint, model labels, artifact declarations and scope are supplied by the
caller. It does not start a Kimi process or select a particular model.

## Local disk and optional cloud directories

Each sphere root is an explicit caller-selected filesystem directory. Fast
local storage can hold live context and public capsules. Portable storage can
hold another designated transport root. A Proton Drive or Google Drive desktop
folder can serve as an optional source-copy tier when the caller configures it.

An on-disk hash match proves exact local readback. It does not prove the desktop
client uploaded the file or that an authenticated remote provider returned it.
The public export API accepts separately supplied provider-download evidence;
provider login, synchronization and remote observations remain caller-owned.
Private scope keys, inference responses, control roots and model files are not
public archive content.

## Portable extraction pending

These pieces exist in the operator deployment but are **not packaged as portable
services in this release**:

- **Phone browser capsule/QR relay:** the deployed version binds one personal
  endpoint pair. A portable version must require explicit local/private bind
  and peer addresses, preserve scope/token/origin/TTL/rate gates, and separate
  strict JSON parsing from the cloud runtime. QR rendering is an optional
  dependency. Mobile enrollment above is a data interface, not this service.
- **Continuous HOME RAG observer:** the deployed observer pins a local practice
  audit script and application layout. It needs a caller-supplied pinned episode
  auditor and source contract before portable packaging. The included retrieval,
  procedural memory and learning primitives are the reusable foundation.
- **Personal runtime/scheduler:** model start/stop, continuous service scheduling,
  desktop launch shortcuts, live cloud clients and private run profiles are not
  transplanted into this source package.
- **Optional language extensions:** PyO3, Go event transport, Zig kernels/workers
  and Julia analytics have separate build/runtime requirements. They are not
  required by this Python/Rust closure; see the final release inventory for any
  separately included optional source.

External Jcode, OpenClaw, NullClaw and Hermes applications, models and toolchains
are separately obtained and retain their own licenses. Their names in an
adapter do not mean the applications are included or running.

## What verification means

Tests use synthetic sources, finite tasks, inert model callbacks, temporary
storage and bounded loopback fixtures. Optional native tests require a freshly
built selected binary and disclose a missing-binary skip. The package does not
contain the operator's private benchmark runs or provider/mobile attestations.
The portable sphere-pacing tests cover its source-I/O quota behavior; two
deployment-only HOME observer lock tests remain with the excluded observer.

Byte circulation and receipt consistency do not establish semantic truth.
Workflow completion is not a solve. A learned scaffold is promoted only under
its declared evaluation contract; an honest tie retains the incumbent. This
source package alone establishes neither model learning, flagship performance,
universal correctness nor a throughput improvement.
