# Epoch 3 fixed-weight 4B regression board

Three supplied pilot reports were treated as untrusted evidence. Their exact bytes were identified by SHA-256 before this note was written:

- Epoch 3 terminal-histogram report: `0539f6b96213c1b1c55249297f6c5538e1e208b5bf3d1e0145b3ee36684c6a55`
- 4B performance and signature-card report: `c8d02b47549b00e01c0dc699f9a8e85362087491b621e6cd2b4f7a84c70db307`
- Victory-lap report: `588651c7270085b1c1d404068f588282cd8583026fd4f0d697d398c9f828d707`

The reports record two distinct results on the spent eight-task dojo/regression board. One single sealed victory-lap run resolved all hidden cases for 7/8 tasks. Across separate sealed evidence chains, successful receipts exist for all 8/8 tasks. This is not a single-run 8/8 result.

The as-of-join task required a card that named the exact repair move. Terminal-histogram was chain-sensitive and bimodal. In the successful chain, the initial attempt engaged but produced an off-by-one failure; the exact card plus a retry carrying the concrete `IndexError` crash trace reached 4/4. In the single sealed victory-lap chain, the initial attempt returned the original file verbatim, and the retry triggered by no-op rejection also returned a no-op, leaving that task at 2/4. Each chain allowed the initial attempt and at most one retry.

The reports state that the model weights stayed fixed and that learning occurred only in the harness through task-specific guidance and bounded retry policy.

## Claim boundary

This is a later follow-up to the earlier pilot summarized in [reported pilots](reported-pilots.md). Because the board had already been used for dojo work and regression testing, the cross-chain 8/8 supports only a closure claim for that spent board under targeted harness interventions. It does not demonstrate unseen generalization or cross-task transfer, and it is not an official SWE-bench or SWE-bench Verified result. [XNET Blind Repair 50](blind-repair50.md) remains the separate transfer benchmark, with frozen choices and separately held-out grading.

The hashes establish the identity of the supplied report bytes; this release did not independently replay their private grader or inspect their hidden fixtures. No throughput, latency or broader model-performance claim is adopted here. In particular, the victory-lap report's `4.7x` prompt-path statement is excluded because the supplied evidence does not establish an exact comparable configuration; the current Vulkan benchmark run is separate from this pilot evidence.
