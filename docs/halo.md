# HALO

HALO means **Hash-Addressed Long-context Observation**. It separates a context experiment from the decision to adopt a rotation policy.

`xnet.halo_context_v1` is a pure policy library. It performs no inference, filesystem operations or session rotation. Registries start empty. There is no default global token threshold.

## Exact engine identity

`EngineProfile` binds:

- A bounded engine identifier.
- Complete hashes for model, runner bundle, tokenizer and prompt template.
- A hash of the complete launch and decoding configuration.
- Context capacity and reserved generation tokens.

These values are supplied by the caller. The library checks their format and consistency; it does not inspect loaded weights or independently attest a server. A model name, hashed label or advertised context size cannot substitute for actual artifact identity.

## Proposing a context pin

`ContextPinProposal` binds a proven-good occupancy, an earlier review threshold and immutable evidence hashes to one exact profile. Its purpose is `needle-recall-only`.

A caller explicitly registers a proposal. Registration checks profile equality and output headroom. It refuses a changed policy under the same frozen identity. An empty registry cannot produce advice.

`advise` requires the selected profile hash, observed current profile hash, complete rendered-prompt hash and exact measured prompt tokens. It rejects a profile mismatch or a prompt that leaves insufficient output headroom. The result reports review status and remaining headroom with `authority: none` and `rotation_performed: false`.

The application decides whether to schedule a review and how to perform a handoff.

## Evidence needed before adoption

A reproducible calibration package should retain:

| Evidence | Purpose |
|---|---|
| Actual runner and artifact identities | Bind measurements to the engine used |
| Complete launch and template configuration | Make context capacity and behavior reproducible |
| Rendered prompt and tokenizer output | Establish exact prompt occupancy |
| Seeded fixture manifest and expected answers | Fix the test before inference |
| Raw responses, refusals and failures | Preserve what actually happened |
| Grader version and frozen outputs | Prevent changing a score after inspection |
| Prompt/decode timing, tokens and retries | Expose the full cost of the result |
| Cache state and trial order | Distinguish reuse from a fresh run |

Leave a candidate inactive until these checks establish its identity and relevant behavior. New model weights, templates, runner versions, context settings or decoding configurations require a new profile and calibration.

## Separate questions, separate tests

- **Capacity:** Will the server accept the complete prompt and requested output reserve?
- **Recall:** Can the model retrieve planted facts at different depths and ordering?
- **Reasoning:** Can it join multiple facts or apply a rule over that context?
- **Retrieval:** Can selected source slices answer the same question at lower total cost?
- **Continuity:** Does a fresh session receive and use the selected prior context?

A recall pass establishes evidence for that recall task and configuration. It does not guarantee long-context reasoning, coding accuracy or a universal operating threshold.

## Harness learning

Oroboros can feed public failure observations into a harness improvement loop. A proposed change to guidance, retrieval or routing must beat a declared baseline under fixed budgets and disjoint evaluation tasks before promotion. Report training cost separately, retain ties and regressions, and count cache returns separately from new solves.

The learning target is the harness policy. Model weights remain unchanged unless a separate, explicit weight-training process is introduced and evaluated.

The included `ScaffoldLearner` applies declared outcome and cost checks. `ProceduralMemory` uses independently validated public evidence before activating a staged card. `LearningEpoch` composes these with bounded inert repair and caller-supplied generation, proposal and boundary-observer callbacks. It advances by explicit `step` or bounded `run` calls; it is not a resident engine and installs no scheduler.

Use new public configuration and separate private local roots for original tasks and references. Retain only approved public projections for context circulation. Generic peer labels such as `operator`, `assistant` and `peer` identify roles; they do not authenticate an operator, model or remote device. This release does not migrate old roots.
