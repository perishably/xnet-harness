# Native HCE and HALO boundary

The Rust workspace now contains two model-independent libraries:

- `xnet-hce` implements **HCE (Hash-Addressed Capsule Encoding)** as a
  lossless, canonical v1 codec. It verifies the complete
  wire hash, strict schema, exact source backpointer and public classification,
  and renders deterministic machine, Chinese and English faces.
- `xnet-halo` binds a review threshold to one complete engine profile: model,
  runner bundle, tokenizer, template, launch configuration, capacity and
  generation reserve. Its advice reports review due and remaining headroom.

Both libraries match pinned Python contract vectors in their Rust tests. They
do not own a model, tokenizer, session, Jcode lifecycle, filesystem, ledger,
CAS, retrieval index or scope gate. HCE does not translate or compress source.
HALO consumes caller-attested profile identity and measured prompt tokens; it
does not measure tokens or rotate a session. A needle-recall pin does not prove
reasoning quality.

The existing Python HCE storage adapter remains the live Ledger/CAS authority.
The next persistence step is a versioned runtime operation that seals a native
profile and proposal through the existing CAS and audit stream, then reconstructs
the registry from those receipts at startup. That step needs its own protocol
review and migration tests; these crates do not silently change the current
runtime protocol or historical Oroboros rotation behavior.

Jcode remains a sibling application. A Jcode adapter may call these typed XNET
libraries through a versioned interface, but XNET does not take over Jcode's
provider, model, TUI or process lifecycle.
