# Minimum Oroboros: local storage and optional Proton Drive

This is a portable setup blueprint. It does not create accounts, provision a cloud client, schedule a job or claim a remote-cloud round trip has happened. A user can start with local storage alone and keep model inference independent of storage providers.

## The small setup

```text
Explicitly selected documents
  -> local exact-byte source store and trusted manifest
  -> local index selects source passages
  -> bounded source packet -> chosen available model -> answer and citations
  -> checked feedback / candidate harness procedure
  -> practice -> frozen trial -> retain or promote -> next task

Selected public archive projection
  -> optional user-managed Proton sync folder
  -> provider upload -> separate authorized remote readback
  -> exact hash check -> local import under current scope
```

The source store retains complete selected bytes. Context windows receive small relevant passages and pointers back to that store. Summaries can lose detail; retrieval can restore it if the complete source is still retained and accessible. Hashes detect changed bytes against an independently trusted expected hash. They do not establish whether the original document is factually true.

For Windows, choose a dedicated directory such as `%LOCALAPPDATA%\XNET\vault` on the user's local drive. Keep the private ledger, learning reference material and credentials outside any sync folder. Select a separate archive directory explicitly for approved exports. Additional portable drives and providers are optional; no drive letter or machine endpoint is hardcoded in the public setup.

Use `oroboros_public_export` for its reviewed public projection and verified readback contract. It refuses unsupported/private material; do not relabel household data public to force an export. `oroboros_outer` supplies durable lifecycle stages and STOP handling with borrowed callbacks. The included core does not install a resident engine. Every application's scheduling and Start/Stop lifecycle stays explicit.

The complete `SphereController` requires four explicitly designated logical roots. A minimum local context loop can use the ledger, RAG and context contracts without provisioning that controller. Four directories on one disk represent four logical stages; they do not prove four physical drives or cloud destinations.

On an iPhone, local storage means the app's sandbox, not a mounted Windows C: drive. A native app must implement and test its own store/index and port compatible contracts. The source-only Apple bridge is not a completed iPhone app. An iPhone browser capsule return proves transfer of those bytes, not local model inference or background learning.

## Proton Drive as an optional archive tier

Proton Drive apps are already open source. Use the official client separately with its retained license; XNET's MIT license does not relicense Proton code. The Windows repository primarily uses GPL-3.0-or-later, with some MIT portions. This source package links to the client and contains no copied Proton implementation. [Proton announcement](https://proton.me/blog/drive-open-source), [Windows source and licensing](https://github.com/ProtonDriveApps/windows-drive)

The Free plan currently offers up to 5 GB. Use it for small approved capsules, manifests and receipts; actual account quota and plan conditions remain the provider's. Large weights and caches are unnecessary for this archive loop. [Proton Free storage](https://proton.me/drive/file-sharing/send-large-files)

For the Windows route, the user installs/signs in to the official client, selects the dedicated approved archive folder using **Add folders**, and waits for the client to report sync completion. Never sync the entire home directory or drive. Cloud-only placeholders may download when opened; an offline check requires locally available files. [Folder sync](https://proton.me/support/proton-drive-windows-sync-folder), [On-demand files](https://proton.me/support/proton-drive-windows-on-demand-sync)

Record distinct stages: local export written, local export readback verified, provider reports upload, authorized remote fetch completed, remote bytes match. A hash match in the desktop sync folder proves only the local readback stage. Remote retrieval and restore require independent evidence from the provider or another device.

## Native AI and interchangeable models

Everyday-user route: check for a supported on-device Apple or Windows model, then supply verified source context. Builder route: choose a compatible local model/runtime and supply its own generation callback. Four billion parameters is an optional size, not a requirement. Model hardware fit, performance and context margins need measurements on that device. See [native interfaces](native-intelligence.md).

`xnet.native_context_v1` prepares source-bound, byte-limited packets for either route. It has no provider call, export, tool authority or fallback. Private classification stays private. Its citation check verifies attributed literal spans; semantic correctness remains an independent evaluation requirement. Missing token counters remain unknown, and desktop HALO pins never activate on a new device by default.

Weights remain fixed in this harness-learning loop. Retrieval and tested guidance can improve outcomes; ties and regressions retain the baseline. Report source fidelity, grounded/refused answers, task accuracy, latency and total practice cost separately. No amount of circulation guarantees improvement or universal correctness.
