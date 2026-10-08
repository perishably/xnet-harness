# Development goals and useful evidence

XNET aims to help small models deliver useful answers with grounded context, explicit limits and durable memory. A repair score is one measure. Context fidelity, reliable refusal, source traceability, privacy and total cost are also product requirements.

## Evaluate everyday tasks alongside repair

| Goal | Suggested observation | Interpretation limit |
|---|---|---|
| Correct, useful answers | Independently checked task outcomes and user corrections | Fluency and a completed response are not correctness |
| Grounded answers | Supported claims, unsupported claims, exact citations and source coverage | A matching source hash alone does not verify the answer's meaning |
| Reliable refusal | Refusals when evidence is absent, permission is denied or inputs conflict; unnecessary refusals measured separately | A small refusal trial is not a universal safety guarantee |
| Useful memory | Planted-fact recall, multi-source joins, revision handling and stale-fact rejection | Recall does not establish reasoning or updated neural weights |
| Controlled actions | Source instructions leave tool authority unchanged; denied actions observe zero transport calls | Public-text labels and role names do not authenticate a person |
| Affordable operation | Prompt/decode/retrieval time, tokens, retries, memory, cold/warm cache state | A cache return is recorded separately from a new solve |
| Harness improvement | Frozen baseline/candidate comparison on disjoint tasks and budgets, with training cost disclosed | Time spent circulating data does not guarantee improvement |

Useful future fixtures include document questions with missing evidence, household planning with explicit constraints, changed instructions across sessions, conflicting dated facts and retrieval of a small relevant passage from a larger archive. Keep these synthetic or approved public data. Evaluate overconfident wrong answers as failures and record appropriate abstention as its own outcome.

## Current foundations

This release provides source capsules, indexes, local RAG contracts, scope admission, caller-owned context handoff, a bounded repair evaluator and validation/promotion gates for harness guidance. Strict curator admission and inactive HALO observations add clear intake and calibration boundaries. Utility tests exercise these contracts without depending on a model.

Live small-model trials are promising pilot observations. The current reported repair comparison has a hidden-score tie and a separate confounded regression. It does not establish zero hallucinations, superiority over another learning system or inevitable future improvement. Retain these outcomes as development evidence. See [reported pilots](reported-pilots.md).

## Focused contribution opportunities

1. Improve reproducible grounding/refusal fixtures and an independent claim-to-source grader.
2. Add signature-compatible lesson selection with explicit abstention, then compare it against existing selection under frozen budgets.
3. Attest actual engine/tokenizer/template/configuration identities before adopting HALO context margins.
4. Add bounded caller-owned adapters for application context and independently verified storage retrieval.
5. Improve installation, examples and platform coverage while keeping model processes and credentials with the caller.
6. Complete a native app around the Apple/Windows bridge references, prove offline device inference and measured context behavior, and retain OS-managed model identities honestly.
7. Port the personal phone relay and continuous HOME observer into configurable services with caller-supplied endpoint and audit contracts; the coverage appendix identifies the existing reusable seams.
8. Build from the transport-free Legions protocol core toward a distributed runtime only after a reviewed design. Preserve explicit opt-in nodes, allowlisted job types, hard resource and cost budgets, authenticated capability advertisements, content-addressed inputs, authenticated receipts with a documented shared-key or asymmetric trust model, result verification or independence-aware quorum, secret isolation, revocation and an operator kill switch. Transport, sandbox enforcement, discovery, scheduling and quorum are not implemented in this release; use the [scoped design issue](../.github/ISSUE_TEMPLATE/legions-design.yml).

Each contribution should state the changed contract, observed outcome and unresolved limitations. Discuss large changes first; use focused pull requests and retain upstream notices. Existing source-only adapters are entry points for collaboration, not a requirement to replace an application's lifecycle.

No resident training process or scheduler is installed by this release. A caller may run repeated evaluated epochs, retain measured improvements, and stop or roll back regressions. A fair comparison with another system requires the same task split, source access, budgets and independent scorer.
