# Draft RFC: optional source-backed context provider for Jcode

**Status:** discussion proposal. Interface names below are proposed, not claims about a current Jcode API or upstream acceptance. The first contribution is an issue for maintainers to assess before a focused implementation.

## Problem

An agent application can receive useful context from an external memory utility, but needs explicit source identities, a bounded prompt contribution and recovery behavior. Context preparation must preserve the application's authority over inference, fetch operations, tools and session lifecycle.

This proposal is deliberately limited to one optional context-provider interface. Jcode would keep its existing application lifecycle; XNET would remain a separate utility. Existing behavior would remain the default when no provider is configured.

## Proposed boundary

The application calls a provider at a defined prompt-preparation boundary with:

- Task and current session identifiers.
- Approved public source references.
- A byte limit, complete prompt token budget and output reserve.
- The identity of the current tokenizer and prompt template.
- Caller-owned callbacks for authorized fetch and exact token measurement.

The provider returns bounded context data and a selection receipt. Each record includes its kind, exact text, full source hash, full text hash and provenance receipt hash. The complete response binds the task and public input, declares `context_only: true`, and grants no tool authority.

HCE capsules can supply those records: the source hash pins original UTF-8 bytes; the capsule hash additionally binds ring, kind and classification; the intake receipt binds task, scope and both identities. These checks establish byte provenance against trusted expected identities. Caller authorization and content classification remain separate.

## Token and source verification

The application verifies expected full hashes, task/scope binding and source classification before rendering the selection. It measures the complete rendered prompt, including system text and template, using the actual current tokenizer. Summed record estimates or billed usage cannot substitute for that measurement.

Reject a selection that exceeds its byte limit or leaves insufficient generation headroom. Avoid silent clipping. If a smaller selection is needed, make a new explicit selection with a new receipt.

Fetch remains a caller-owned, scope-checked operation over selected references. The provider cannot turn source text into arbitrary commands, select an unapproved source or silently add a network route.

## Handoff and recovery

A first focused implementation can prepare context for the next caller-owned prompt without implementing automatic session rotation.

A subsequent optional handoff interface may freeze an exact context selection, reserve a callback durably, request a fresh session from the caller and bind the acknowledgment to the new session, capsule and measured bootstrap prompt. Unknown callback outcomes require explicit reconciliation. Reopening durable state must not repeat uncertain inference or overwrite completed output.

HALO review advice can inform that caller decision only after a matching engine configuration and relevant evidence are attested. No universal threshold is introduced by this interface.

## Synthetic acceptance tests

All initial tests use synthetic local data and a stub callback, with no model, provider or external target required:

1. With no provider configured, existing prompt construction remains unchanged.
2. A selected public UTF-8 source survives an HCE round trip and retains complete source and capsule identities.
3. Mutated source bytes, metadata, shortened hashes and cross-task provenance are refused before prompt inclusion.
4. A scope denial prevents the caller-owned fetch; the test observes zero storage or transport calls afterward.
5. Complete rendered prompt measurement includes template and system text; over-budget selections are refused without clipping.
6. An instruction embedded in source text does not alter tool permissions or cause an action.
7. Context selection and its receipt are deterministic under the same declared inputs.
8. For any later handoff implementation, an uncertain reservation refuses redispatch, and replaying a committed acknowledgment produces no second bootstrap.

These tests establish interface behavior. They make no model-performance, learning or throughput claim.

## Submission plan

Discuss the optional interface in an upstream issue before attempting a larger integration. Jcode's current contribution policy requires each pull request to link an existing issue and encourages focused, independently reviewable changes. AI-assisted contributions are accepted under the same correctness and validation expectations. [Jcode contribution policy](https://raw.githubusercontent.com/1jehuang/jcode/master/CONTRIBUTING.md)

The first proposed pull request should contain the disabled-by-default interface, a synthetic adapter and focused tests. XNET-specific topology, storage scheduling and model runners can remain separate adapters. Maintainers decide whether the interface fits Jcode.

Jcode is distributed under MIT; copied or substantially reused Jcode source must retain applicable copyright and license notices. This RFC itself does not copy an implementation or grant rights to another project's code. [Jcode license](https://raw.githubusercontent.com/1jehuang/jcode/master/LICENSE)
