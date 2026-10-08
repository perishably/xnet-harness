# XNET Legions protocol core

Legions is a small, model-agnostic envelope for friends or team members who
explicitly choose to share bounded compute. The current implementation is a
Python library. It describes work, applies a worker's local policy, and produces
shared-key-authenticated result metadata. It does not run or transmit work.

## Implemented now

The core in `xnet/legions.py` implements three canonical JSON objects and two
local safety gates:

| Object or gate | Bound data |
| --- | --- |
| Capability card | Worker identity, sorted task and capability declarations, and resource ceilings |
| Job capsule | Task type, input SHA-256 hash set, required capabilities, resource/time/token/cost budgets, coordinator identity, target worker identity, expiry, and random nonce |
| Result receipt | Job hash, worker identity, sorted output hash set, start/finish times, measured resource/token/cost usage, body hash, and HMAC-SHA256 authentication tag |
| Worker gate | Authenticated coordinator binding, explicit coordinator/task/capability allowlists, target-worker binding, and both advertised and local budget ceilings |
| Safety state | Kill switch, node/job revocation, bounded accepted-job/nonce/completion memory, and one verified receipt per job and worker |

Every wire object uses sorted, compact UTF-8 JSON. A job's SHA-256 is its
content address. Decoders require complete lowercase hashes, exact schemas,
canonical bytes, bounded fields, and no duplicate or nonfinite JSON values.
Wire integers are limited to `2**53 - 1` so common JSON implementations can
preserve them exactly. A hash detects changed bytes but does not authenticate
who supplied them.

`WorkerGate.accept` therefore requires `authenticated_coordinator_id`. The
embedding transport or session-authentication layer must supply that identity;
never derive it from the capsule. Admission requires an exact match between the
authenticated identity and `JobCapsule.coordinator_id`, then applies the local
coordinator allowlist. `expected_sha256` separately pins the accepted bytes.

The HMAC key is supplied for a single receipt-authentication or verification call. It is not
stored in a card, capsule, receipt, or module global. Use a different key per
worker and bind that key to the expected worker identity outside this protocol.
A HMAC proves only that some holder of the shared secret produced the receipt.
Every verifier that knows the key can forge an indistinguishable receipt, so a
HMAC is not a digital signature and provides no nonrepudiation. A shared
team-wide key cannot even distinguish which group member produced a receipt.

Example:

```python
from xnet.legions import (
    Budget, CapabilityCard, JobCapsule, LegionsControl, ResourceUsage,
    WorkerGate, WorkerPolicy, new_nonce, sign_result_receipt,
    verify_result_receipt,
)
from xnet.protocol import sha256

limits = Budget(
    wall_time_ms=30_000, cpu_time_ms=25_000, memory_bytes=2_000_000_000,
    input_bytes=10_000_000, output_bytes=2_000_000, tokens=8_000,
    cost_microunits=100_000,
)
card = CapabilityCard(
    worker_id="friend.alex", task_types=("model.infer",),
    capabilities=("cpu", "model.local"), limits=limits,
)
policy = WorkerPolicy(
    allowed_coordinator_ids=("team.garage",),
    allowed_task_types=("model.infer",),
    allowed_capabilities=("cpu", "model.local"), maximum_budget=limits,
)
job = JobCapsule(
    task_type="model.infer", input_sha256s=(sha256(b"input"),),
    required_capabilities=("cpu", "model.local"), budget=limits,
    coordinator_id="team.garage", target_worker_id="friend.alex",
    expires_at_ms=1_800_000_000_000, nonce=new_nonce(),
)

control = LegionsControl(replay_capacity=4_096)
accepted = WorkerGate(card, policy, control).accept(
    job.to_wire(), expected_sha256=job.sha256,
    authenticated_coordinator_id=transport_peer_identity,
)

# The embedding application performs its already-sandboxed, allowlisted task.
usage = ResourceUsage(
    wall_time_ms=100, cpu_time_ms=80, memory_bytes=100_000_000,
    input_bytes=5, output_bytes=32, tokens=20, cost_microunits=500,
)
receipt_wire = sign_result_receipt(
    accepted, output_sha256s=(sha256(b"output"),),
    started_at_ms=accepted.accepted_at_ms,
    finished_at_ms=accepted.accepted_at_ms + 100,
    usage=usage, key=worker_key,
)
receipt = verify_result_receipt(
    receipt_wire, expected_sha256=sha256(receipt_wire), expected_job=job,
    expected_worker_id="friend.alex", key=worker_key, control=control,
)
```

The application must enforce the accepted budget in its process/container
sandbox. An HMAC-authenticated usage report is integrity metadata shared between
key holders; it is not proof that a worker measured honestly or that the
verifier did not forge it. Input and output hashes prove byte identity, not the
quality or safety of those bytes.

Input and output hash lists are sorted, unique sets. They do not encode order,
roles, or repeated occurrences. A task needing positional or named inputs or
outputs must put that structure in a canonical manifest and use the manifest's
hash in the corresponding hash set. A first-class structured manifest remains
roadmap work.

`LegionsControl` retains at most `replay_capacity` live entries in each replay
category and refuses new work or receipts when that capacity is full. Entries
are pruned when their job expires. Admission, result authentication, and receipt
verification all treat expiry as exclusive, so pruning cannot make an expired
replay acceptable again. Choose capacity for the maximum concurrent unexpired
assignments and verify a receipt before its job expiry. The control state also
fails closed if its observed clock moves backward, because pruning followed by
a clock rollback could otherwise reopen an old replay window.

## Scaling to more nodes

The envelope scales by repeating the same explicit exchange for each opted-in
node:

```text
team coordinator
  |-- job A + unique nonce --> friend/node A --> HMAC-authenticated receipt A
  |-- job B + unique nonce --> friend/node B --> HMAC-authenticated receipt B
  `-- job C + unique nonce --> friend/node C --> HMAC-authenticated receipt C
```

Each node publishes or shares its own content-addressed capability card, keeps
its own allowlist and kill switch, and receives a capsule bound to its worker
identity and tailored to its limits. A coordinator can fan independent jobs
across a clan or legion, then verify every returned receipt against that job,
worker, and worker-specific key. Adding nodes adds independent lanes; it does
not expand any node's authority and does not require sharing model weights,
prompts, credentials, or private inputs through the protocol.

Create a distinct job nonce for every assignment. If the same logical work is
sent to several nodes, create one capsule per assignment so every acceptance
and result has an unambiguous identity. Persist `LegionsControl` replay and
revocation state in the embedding application if those protections must
survive a process restart.

The core intentionally stops at locally HMAC-authenticated receipts. It makes
no claim of nonrepudiation or that several outputs form a correct combined
answer.

## Roadmap boundaries

These are possible layers above the core and are not implemented here:

| Roadmap layer | Required before it can be trusted |
| --- | --- |
| Peer transport | Mutual authentication, encryption, backpressure, message size limits, and explicit addresses |
| Discovery/invitations | User-approved enrollment, identity pinning, key rotation, removal, and audit history |
| Scheduler | Capability matching, leases, retries with new nonces, fairness, budget enforcement, and failure accounting |
| Team/clan management | Roles, membership changes, per-project policy, and revocation distribution |
| Quorum or aggregation | A task-specific deterministic rule, independent output verification, conflict handling, provenance, and a cryptographically authenticated aggregation manifest with an explicit trust model |
| Asymmetric receipts | Worker public-key enrollment, rotation, signature verification, and a nonrepudiation threat model |
| Structured manifests | Canonical named or positional inputs and outputs, repeated-value semantics, media types, and byte sizes |
| Durable control state | Atomic storage for replays, revocations, kill-switch state, and crash recovery |

There is no network daemon, automatic discovery, arbitrary code execution,
remote shell, secret forwarding, scheduler, quorum, or aggregation in this
module. A future layer must preserve the same opt-in and fail-closed gates
rather than treating a capability card as permission to execute anything.
