# Reported model pilots and release claims

These observations came from external local pilot artifacts inspected during integration. They are not reproduced or certified benchmark results in this source release. Complete engine identities, frozen artifact manifests and an independent sanctioned replay are still needed before adopting a calibration or performance claim.

## Context and curator pilots

- The 35B trap board recorded 11/14 correct. Its current card subset recorded 4/4. The report describes a native 8K configuration, while the raw rows use a stretched-configuration label and include prompts exceeding 8K; that identity conflict prevents calibration adoption.
- The Lite 4K rows recorded 12/12 in-window recall, 2/2 indexed answers and four server refusals. The proposed 3,400-token review margin remains inactive pending complete model, runner, tokenizer, template and configuration identities. A clipped join response is unresolved reasoning evidence.
- The 4B curator trial recorded seven positive triples and one negative accepted by the older parser. The negative was a JSON-shaped refusal, which does not satisfy the new literal `NOT-A-CAPSULE` contract. The new strict intake seam refuses it. This is a small trial, not a reliability certificate or an always-on deployment.

## 4B repair gauntlet

| Metric | Raw prompt | Tagged-card prompt arm |
|---|---:|---:|
| Tasks passing all hidden cases | 6/8 | 6/8 |
| Hidden cases passing | 28/32 | 28/32 |
| Public cases passing | 14/16 | 15/16 |
| Tasks passing all public cases | 6/8 | 7/8 |

The terminal boundary task improved on public cases from 1/2 to 2/2, while both arms stayed at 2/4 hidden cases. The temporal join remained unresolved, including after feedback. This board therefore shows no aggregate hidden-score improvement.

A separate one-task lesson-transfer probe regressed from 2/2 to 1/2 public cases and from 3/4 to 2/4 hidden cases. The lesson came from another task in the same broad category but with a different failure signature. The intervention also changed the prompt format, so it cannot isolate the lesson's effect. This motivates controlled tests of signature-compatible selection and abstention, not a claim that the lesson alone caused the regression. A no-tool arithmetic probe returned 7 where the expected answer was 9.

The gauntlet's tagged-card arm is a prompt intervention plus public-feedback retry. The inspected script does not exercise full HCE encoding/verification, the native SDK, Jcode, Claw gates or drive circulation. Its results must not be attributed to that full stack. The pilot also executes generated Python in its host grader; XNET's included bounded inert evaluator deliberately provides a different execution contract. Do not run that pilot grader through this release.

The inspected outputs lacked an immutable full-hash output freeze, a verified receipt chain and complete engine artifact identities. The fixtures had prior practice use, with no novel split manifest, and the exact grading fixtures were not included for independent replay. The inspected pack contained 27 candidate directories despite a report count of 25; the main coding rows totaled about 176 seconds rather than the reported two minutes. An indexed control supplied the answer text in the prompt and did not establish an actual QR or drive lookup. Reported wall-clock figures are descriptive pilot observations rather than repeatable throughput guarantees. A future comparison should freeze disjoint fixtures, actual context exposure, engine identities, budgets, complete raw answers and the grader before independent held-out scoring.

## Permitted interpretation

The release includes working utility contracts and synthetic checks. The pilots motivate strict intake, exact engine calibration, task-family validation and baseline retention after ties or regressions. They do not establish flagship-level performance, weight learning or a general model accuracy gain from XNET.
