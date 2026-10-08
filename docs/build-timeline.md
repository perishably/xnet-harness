# XNET~ public candidate build timeline

![XNET~ build quote: XNET~ — LOOP BACK!](xnet-build-quote.svg)

**XNET~ — LOOP BACK!** Preserve the source, verify the result, and feed the
evidence into the next bounded pass.

Author: **Felix Xavier Lopez**

The XNET~ v0.1.0 public candidate was assembled from **September 30 through
October 7, 2026: eight calendar dates, under two weeks**, on one **HP OmniBook
X Flip Laptop 16-cb0xxx**. A frozen October 7 private benchmark-environment
receipt identifies the machine as an Intel Core Ultra 9 386H system with 16
logical processors, 33,933,983,744 bytes of RAM, and Intel Graphics through
Vulkan. The receipt file `benchmark-environment-r08-operator-blind.json` has
SHA-256
`3cb9849df1bf2c4f2ac27bdb64000e2b1ea65f4fc2febbcf2cbccd53e98de704`.
It corroborates the final run environment; it is not a complete attestation of
every action on the preceding dates.

This is a release-candidate assembly and validation timeline. It includes
pre-existing XNET work, MIT-licensed upstream ideas and interfaces, authored
integration source, generated assistance, testing, private experiments, and
public-release hardening. It is not a claim that every line was authored from
scratch during these eight dates. See [provenance](../PROVENANCE.md) and
[third-party notices](../THIRD_PARTY_NOTICES.md).

## Evidence classes

- **Public reproducible:** source, tests, or documentation shipped in this
  repository and inspectable from a clean clone.
- **Private sealed:** a local report or receipt is identified by filename and
  SHA-256. These files are not part of the public source release unless the
  public inventory explicitly lists them.
- **Reported only:** a user/Kimi report or workspace timestamp was retained,
  but this public release does not independently reproduce the dated event.
- **Planned:** a design or proposal existed; implementation or live operation
  was not established at that point.

A public source test can verify the final contract without proving the exact
day on which private work occurred. Private hashes identify bytes; they do not
make the report's interpretation independently true.

## Day-by-day record

| Date | Milestone | Evidence anchor | Evidence class | Limits and failures retained |
| --- | --- | --- | --- | --- |
| **Sep 30** | The project/session workspace was created and the user/Kimi collaboration began recording XNET and Jcode requirements. The final public candidate exposes the resulting model-neutral Jcode context, history, sphere, and learning seams. | Workspace date is the reporting origin. Final public artifacts: [XNET Code and Jcode lineage](xnet-code.md), [Jcode history tests](../tests/test_jcode_history_ingest.py), and [Jcode learning tests](../tests/test_jcode_learning_wing_peer.py). | **Reported only** for chronology; **public reproducible** for final contracts | The dated workspace root is not proof of how much code existed that day. Jcode remains an external MIT project; the full application is not bundled. |
| **Oct 1** | Local toolchain and cache work began for the mixed Python/Rust utility foundation, with Go/Zig exploration also present in the workspace. The release ultimately kept a Python standard-library core, optional Rust workspaces, and narrow external-language boundaries. | Final public artifacts: [Python package declaration](../pyproject.toml), [Rust workspace](../rust/Cargo.toml), [HCE capsule tests](../tests/test_hce_capsule_v1.py), and [coverage inventory](coverage.md). | **Reported only** for the dated workspace activity; **public reproducible** for shipped source | Cache or toolchain directory timestamps do not prove a successful build. Optional Go/Zig ideas are not required runtime components of v0.1.0. |
| **Oct 2** | Rust target activity established the native build lane used for source storage, audit, task history, context, policy, and the separate Jcode adapter workspace. | Final public artifacts: [native HCE/HALO contract](native-hce-halo.md), [Rust workspace](../rust/Cargo.toml), and [Jcode Rust workspace](../adapters/jcode/rust/Cargo.toml). | **Reported only** for the date; **public reproducible** for final source and tests | A target directory shows build activity, not a passed release gate. Python and Rust evidence stores remain separate; no persistence migration is implied. |
| **Oct 3** | Architecture review, a repair-round manifest, the first retained Oroboros graph instance, and a Jcode Rust extension proposal turned the foundation into explicit source, context, repair, and handoff boundaries. | Private/local: `architecture-review.md` `2a5093d7991d1d6ba49d36fc59c6a81b834d98b8cc999c95f0465d0d496cdc1b`; `repair-round-manifest.json` `919176efdb556acae4d1ccf98da69e207e37cda37b3234c04c9d2eaf4a6e0c29`; `ouroboros-graph.instance.json` `faad8cb82a71334141800a18912cd686389cb9953c7fbf0f78c6daa7f7ef764a`. Final public artifacts: [architecture](architecture.md), [Oroboros](oroboros.md), and [adaptive repair](adaptive-repair-contract.md). | **Private sealed** and **public reproducible** | The private handoffs include design discussion and do not all represent shipped implementation. The public contracts and tests define the release boundary. |
| **Oct 4** | Adapter-forge red teaming and a hash inventory examined optional application/model paths. Model assets were handled as external inputs; the public release retained source-only adapters and attribution rather than bundling applications or weights. A DSpark draft/verify path was proposed. | Private/local: `GPT-TO-KIMI-XNET-LATTICE-OS-ADAPTER-FORGE-WARGAME-20261004.md` `9b7b4f8ec64ae1e35c0235ad9dee04ddb698514347274e2bb0af187b550744c4`; `model-fetch-manifest-v1.json` `a3414c216918047e3644e1b25eea846a4f214c8060f9e9e5c17a0e480c5fa18b`; `dspark-draft-verify-spec-v1.md` `95ca48f4109d744288b31e93cbf7772c7eac720a003a944c957fda3c4f415551`. Final public artifacts: [extension points](extension-points.md) and [third-party notices](../THIRD_PARTY_NOTICES.md). | **Private sealed** for reports; **planned** for DSpark; **public reproducible** for final boundaries | The installed llama.cpp build was later found to have no DSpark architecture support. Published DSpark speed ranges were treated as a ceiling, not a result on this laptop. No model weights ship. |
| **Oct 5** | Jcode upgrade work, repair comparisons, live-lite session handoff, speculative-decoding probes, bridge arbitration, and local/cloud archive experiments were recorded. The release narrowed these into caller-owned, source-only, and local-readback contracts. | Private/local: `swe-v2-head-to-head.md` `f480ca82b85fcb003e37f4cd05967eebc94fa5a4e0d480e4a8fc63976726f542`; `session-handoff-receipt-live-lite.md` `fafe7d2c2f4e330ac9383930d034c777e31047ab646f363e51f3c12a49e0a0d8`; `cloud-oroboros-receipts.md` `2b55053aa6ed48938b8a4da88c1c05bf030fc9b77d6ddae500336b05666a3254`; `wsl-bringup-stuck-handoff.md` `8e6107372eb402030665675d4a7ff5488b8cdff183c88a00a2f95ff1753f26d1`; `sim-receipts-14b-shootout-2026-10-05.md` `eecb508ab957d009c80873b495a9d42fd311fa453bd25109761c9ef7e2437f5e`. Final public artifacts: [minimum Oroboros](minimum-oroboros.md) and [verification boundaries](verification.md). | **Private sealed**; **public reproducible** for narrowed contracts | WSL was installed but had no usable Ubuntu distribution and returned `WSL_E_DISTRO_NOT_FOUND`, so the live split-brain path was blocked. The receipt found no DSpark support in the selected llama.cpp binaries. Dense 14B variants decoded at roughly 7.5 tokens/s in the private measurements and lost the declared simulated routing workload; “too slow” applies only to that configuration and workload. Private cloud receipts are not shipped remote-provider proof. |
| **Oct 6** | Oroboros learning-sphere, wargame, outer-loop wiring, phone-mesh/NetBird, and home-dojo work joined source circulation, bounded learning, and mobile control paths. Optional local, Proton-folder, and Google-folder rings were kept distinct from authenticated provider verification. | Private/local: `HANDOFF-XNET-ORNITH-LEARNING-SPHERE-20261006.md` `ccb6020a45d4703f764cf183260ed86c5020ed69e8e9257f2327a8a1f5494426`; `kimi-wargame-report-2026-10-06.md` `f1a06b477f6a829a3c59180f0912f611b8892112901d0c9baf67081bdae2c295`; `HANDOFF-OROBOROS-OUTER-WIRING-20261006-r01.json` `953b31e8cace51285f57b7a4ce9e3cefadaa41cb39f1574fe3e6edf1f9822691`; `HANDOFF-GPT-KIMI-PHONE-MESH-20261006.md` `e8b1059b3894cf062cd769a531db87a5f56783fb5cab1ef176cdfef51581a917`; `XNET-home-dojo-source-receipt-20261006-r01.json` `1d82b53849a6eee90268f4af4074620c3e58f44f8ea6bf554753c19cfb710d86`. Final public artifacts: [outer-loop tests](../tests/test_oroboros_outer.py), [mobile protocol tests](../tests/test_mobile_protocol.py), and [native/mobile limits](native-intelligence.md). | **Private sealed** and **public reproducible** | A reported byte-exact phone relay through NetBird does not prove device identity, phone-side inference, or an end-to-end public product path. iOS was reported to allow NetBird or Proton VPN one at a time; the source does not try to toggle either. Cloud client-folder readback is not authenticated remote retrieval. |
| **Oct 7** | HCE/HALO evidence was reconciled into public contracts; the iPhone source scaffold and metadata checks were prepared; the fixed-weight 4B spent-board gauntlet, Epoch 3, and victory-lap reports were retained; Blind Repair 50 completed under a frozen operator-blind environment; MIT licensing, provenance, security, contribution, inventory, and release packaging were hardened. | Private/local: `HCE-HALO-ASSIMILATION-20261007-r01__manifest.json` `f433c819bcc7101d5a87632b9a2ef6e77ffb05ae17969dbaec28c1f25a3db9b8`; `kimi-4b-slayer-gauntlet-r01-2026-10-07.md` `a3e49e709f48442ce09bc4f1e1cc17ae9e0c26a8b15bfa2c9f4d920d21697851`; `kimi-epoch3-terminal-histogram-2026-10-07.md` `0539f6b96213c1b1c55249297f6c5538e1e208b5bf3d1e0145b3ee36684c6a55`; current `kimi-4b-perf-sigcard-2026-10-07.md` `db9295bf4f279e53138b205cadc277b1d81e093a640580360b6aed748595aa9d` (the earlier supplied-report identity is recorded separately in the release notes); `kimi-victory-lap-r01-2026-10-07.md` `588651c7270085b1c1d404068f588282cd8583026fd4f0d697d398c9f828d707`; Blind grade receipt `9a9aaa75128e3d756b84d57a4868a9e51cb6917356be09f43a1a15f1247b405b`; frozen environment receipt hash above. Public artifacts: [release notes](release-notes-v0.1.0.md), [4B evidence boundary](epoch3-4b-regression-board.md), [Blind Repair 50](blind-repair50.md), [Apple source README](../examples/native/apple/README.md), [MIT license](../LICENSE), and [provenance](../PROVENANCE.md). | **Private sealed** for run evidence; **public reproducible** for source/contracts | The spent board was already used: 7/8 in one sealed run and 8/8 only across separate chains. Blind Repair 50's initial gate failed: Raw 32/50, Retrieval 27/50, and Full XNET 29/50, so there is no harness-uplift or flagship-parity claim. A reserved attempt hit a provider connection reset at 2026-10-08 05:20 UTC (October 7 PDT); it was not redispatched and remains status 599 with zero credit. `transport-reconciliation-r08-01.json` SHA-256: `9d16a60ba3681300e3a5e8cea6f2845aff1b0148be0a6baf9fafec23ab12d3c9`. The iPhone source was not compiled or device-tested. |

## What the eight-day statement means

The timeline supports the narrower statement that one operator assembled,
tested, reconciled, and hardened this public candidate over eight calendar
dates on one laptop, with collaborative user/Kimi reports and generated
assistance retained where available. It does not establish eight days of
greenfield authorship, an independent replay of every private receipt, a
production deployment, general model learning, or parity with a flagship
model.

The public release claim is bounded by the source manifest, tests, release
notes, and [release checklist](../RELEASE_CHECKLIST.md). Private experiment
files named above remain outside the release unless a later inventory and
provenance review explicitly admits them.
