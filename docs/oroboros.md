# Oroboros

Oroboros is the source preservation and context handoff structure around a caller-owned model session. A ring is a logical grouping of records. Storage tiers can hold copies of those records, and an application can fetch selected records for the next prompt.

The useful loop is:

```text
select source -> seal source -> index -> fetch and verify
      -> bounded context -> caller-owned session -> record outcome
```

Each stage needs an explicit contract. Repeated circulation preserves provenance and availability; it does not by itself improve an answer or update a model.

## HCE source capsule

`xnet.hce_capsule_v1` supplies a lossless canonical JSON codec and a scoped store. The versioned wire schema is `xnet.hce-capsule.v1` with these fields:

| Field | Meaning |
|---|---|
| `schema` | Exact versioned capsule schema |
| `ring` | Positive integer logical ring identifier |
| `kind` | Bounded record-kind identifier |
| `classification` | Explicit caller-selected `public` label |
| `source_sha256` | Complete SHA-256 of the original UTF-8 bytes |
| `text` | Exact UTF-8 source text |

The complete canonical wire also has its own SHA-256 identity. Metadata changes produce a different capsule identity even when source text stays the same. UTF-8, newlines and Unicode normalization are preserved exactly. Decoding requires the expected full wire hash and rejects malformed fields, duplicate fields and noncanonical serialization.

The codec returns bytes in memory. It does not create storage, authority, a model process or a network connection.

## Persistent source records

`HceCapsuleStore` receives an initialized `Ledger`, `scope_gate`, `scope_id` and `task_id`. The gate has the shape `gate(method, target)`; it must raise on refusal before the adapter performs the corresponding operation.

The store preserves:

1. Original source bytes.
2. Canonical capsule bytes.
3. A source receipt binding task, scope and both identities.
4. An append-only ledger witness for the source receipt.

Fetch checks the expected reference, stored receipt, original source, capsule metadata and task/scope witness. Immutable indexes carry full capsule and receipt identities. An index lookup verifies its rows before selecting by ring.

The store checks links and expected hashes. These checks do not authenticate a remote device or protect against an attacker who controls both the source of expected hashes and the storage. Operators must preserve an independently trusted checkpoint when that threat matters.

## Display faces and context selection

Faces are selected explicitly: `machine`, `zh` or `en`. The machine face is canonical wire text. Chinese and English faces are derived plain-text wrappers around the exact source. They do not translate the source, introduce a language default or establish token savings.

`context_record` returns source-backed context and a selection record for an application. It carries no tool authority. A caller sets the byte budget; an oversized rendering is refused rather than silently clipped. This byte budget is not the model's token budget.

## Fresh-session handoff contract

A session adapter can build on these primitives with this lifecycle:

1. Measure the fully rendered current prompt with the active tokenizer.
2. Select verified source context and reserve output headroom.
3. Freeze the handoff and record a durable callback reservation.
4. Ask the caller to create a fresh session and load the exact selected context.
5. Bind acknowledgment to the new session, capsule and measured bootstrap prompt.
6. Reconcile an uncertain callback outcome before any retry.

This lifecycle is an integration contract, not an automatic feature of the capsule codec. The application owns inference, session creation and any model shutdown. Cumulative billed tokens cannot substitute for current prompt occupancy.

The optional session controller borrows a reviewed native gateway and caller callbacks. It requires that SDK and selected native binary; supplying capsule bytes alone does not start or bootstrap a model.

## Storage circulation

A local disk, portable disk or provider adapter can carry a capsule as bytes. Verify the source and returned destination against expected full identities and preserve a receipt for each hop. Copying bytes to a mounted cloud folder does not prove provider upload or remote retrieval. Remote proof needs its own authenticated provider operation.

The included sphere code circulates bounded public envelopes over configured designated directories and verifies local readback. Its source pins include adjacent reviewed scripts and adapters, so it requires the intact source checkout. The operator provides directory mappings; no cloud account, service or mobile connection is inferred from a tier name.

Use fresh public configuration with generic peer labels `operator`, `assistant` and `peer`. Historical tier identifiers are logical names, not proof of a particular physical disk or provider. Do not import private roots into a new public configuration. No automatic old-root migration is supplied.

Context rotation transfers text or structured data. It does not transplant model hidden states or KV caches between different architectures.

## Outcome loop

`RepairLoop` can retain a model's proposed repair and evaluate it in the bounded inert language. Public feedback can support a declared retry; completed output remains durable if an optional evidence mirror fails. A generation reservation with an uncertain outcome requires reconciliation before reuse.

`ScaffoldLearner` and `ProceduralMemory` can retain source-backed guidance only after their respective public outcome or independent validation checks. A caller can compose these through `LearningEpoch`, advancing bounded stages explicitly. The epoch borrows all model callbacks and preserves private originals separately from public projections. Circulating a policy trace does not itself promote that policy.
