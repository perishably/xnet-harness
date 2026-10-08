# Optional intake curator

An external caller may use a small model to propose `(ring, kind, payload)` from
source text. `xnet.hce_curator_v1` supplies the admission seam. The library does
not load a model, start an intake loop, update weights or execute proposals.

1. The caller declares its allowed rings, kinds and payload byte budget in a
   `CuratorPolicy`. There is no default model or maximum ring numbered 39.
2. `parse_curator_proposal` accepts one complete JSON object with exactly the
   three fields, or the literal bytes `NOT-A-CAPSULE`. It refuses duplicate
   fields, JSON embedded in prose, boolean/string/float rings, numeric payload
   coercion and payload text absent from the pinned original intake.
3. The caller independently confirms the selected triple and explicitly marks
   the source public. A payload being present in the intake is necessary but
   does not prove that the proposed selection is semantically correct.
4. `stamp_confirmed_proposal` verifies that confirmation, then uses HCE to
   encode and decode the exact payload. Its source-only receipt binds full
   hashes of the original intake, reply, policy, payload and capsule.
5. The caller persists those original bytes and the receipt through its scoped
   storage gateway. This pure seam performs no storage and grants no authority.

A refusal substring inside a JSON response is not a literal negative response.
Hashes prove exact bytes and derived-face reconstruction; they do not certify
the extraction model's reliability, confirm ownership or authorize a tool.

# HALO observation intake

`xnet.halo_observation_v1.UnboundContextCandidate` records a source-pinned
reported recall margin with explicit unresolved blockers. It always remains
inactive and cannot be registered as an active `ContextPinProposal`.

Before the caller can adopt a rotation policy, it must provide the exact loaded
model, runtime bundle, tokenizer, template and complete configuration identities
required by `halo_context_v1.EngineProfile`. Native and stretched configurations
are separate profiles. Model names, launch descriptions and nominal capacities
cannot substitute for that evidence. Recall probes do not establish long-context
reasoning quality, and clipped outputs require a separate probe to distinguish
budget artifacts from selection errors.
