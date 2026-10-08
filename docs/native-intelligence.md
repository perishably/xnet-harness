# Native intelligence adapters

**Status: source-only examples, NOT COMPILED. No live Apple or Windows native model integration is certified by this release.**

XNET can surround an operating system's existing local model with verified source cards, local retrieval, durable receipts and caller-owned feedback gates. The application and OS retain the model/session lifecycle. Native providers are optional peers; a custom local model can use the same context contracts later.

## Apple Intelligence on iPhone

`SystemLanguageModel.default` selects Apple's on-device foundation model. `LanguageModelSession` manages a conversation with that model. The example explicitly selects this local provider, registers no tools and uses no Private Cloud Compute or ChatGPT fallback. Check `SystemLanguageModel.default.availability` before inference; unavailable reasons include unsupported hardware, Apple Intelligence disabled and model not ready. [Apple model API](https://developer.apple.com/documentation/foundationmodels/systemlanguagemodel), [availability reasons](https://developer.apple.com/documentation/foundationmodels/systemlanguagemodel/availability-swift.enum/unavailablereason)

Apple lists iPhone 15 Pro models and iPhone 16 models or later among eligible devices, with language/region and enabled-model requirements. An older device's ability to run the OS does not establish Apple Intelligence eligibility. System model preparation may require storage and an OS-managed download; this example only reads availability. [Apple device requirements](https://support.apple.com/121115)

The base framework starts at iOS 26.0. This example targets iOS 26.4 or later so it can use native `tokenCount(for:)` overloads for instructions and prompts. The SDK also supports counting tools, schemas and transcript entries. Use `contextSize` from the actual model rather than adopting a desktop Qwen/Lite pin. Current SDK documentation back-deploys that property to iOS 26.0. Accumulated `LanguageModelSession.usage` is a separate iOS 27 API and is not used by this example. [Apple token count](https://developer.apple.com/documentation/foundationmodels/systemlanguagemodel/tokencount(for:)), [context size](https://developer.apple.com/documentation/foundationmodels/systemlanguagemodel/contextsize), [session usage](https://developer.apple.com/documentation/foundationmodels/languagemodelsession/usage-swift.property)

The sample records SDK-visible prompt and instruction counts plus explicit caller output/padding reserves. This is not an attestation of a hidden internal prompt or OS weight bytes. The caller must handle the platform's context-size error and preserve failed/partial outcomes. Native token caps can produce incomplete text, so completed generation is not correctness. [Apple context management](https://developer.apple.com/documentation/foundationmodels/managing-the-context-window)

Compile in a caller-owned Swift app with a compatible Xcode SDK on macOS, then test on the actual supported iPhone. Windows source review cannot establish Apple signing, installation, memory or Metal behavior. Background execution has finite lifecycle constraints; durable stage boundaries and cancellation are required for resumable work. [Xcode requirements](https://developer.apple.com/xcode/system-requirements), [Apple background tasks](https://developer.apple.com/documentation/uikit/uiapplication/beginbackgroundtask%28withname%3Aexpirationhandler%3A%29)

See [Apple source example](../examples/native/apple/AppleNativeContextBridge.swift).

### iPhone-first route policy

The mobile product ceiling is intentionally small and explicit:

| Route | Intended work | Current release state |
| --- | --- | --- |
| Apple on-device system model | Grounded short answers, extraction, classification, summarization and other home tasks | Swift source scaffold only; not compiled or device-tested |
| Device-qualified `xnet-4b` | Builder-selected phone-local coding/general model after exact device qualification | Backend seam pending; no bundled model or runner |
| Remote `home-4b` | First remote-host rung after a trusted exact Apple-native outcome | Protocol, pure host gate and Swift client/UI source only; caller-owned listener and dispatcher required |
| Remote `home-14b` | Harder coding or reasoning after the exact immediately prior `home-4b` response | Same source-only boundary; no compiled or live dispatch claim |

Apple's current Foundation Models documentation describes the on-device system model as a 4K-context model. It also documents Core AI custom-model sessions on iOS 27 or later and recommends starting around 0.6B parameters for a comfortable device fit. A 3B or 4B phone model therefore stays an opt-in builder lane, with measured peak memory, thermal behavior, latency, tokenizer/template identity and a per-device HALO profile. Parameter count alone is not a fit test.

Routing never silently changes the data boundary. The phone-local `xnet-4b` name is not accepted by the remote wire, whose fixed names are `apple-native`, `home-4b` and `home-14b`. A caller-selected adapter may translate generic 4B intent to `home-4b` only with an explicit route choice and retained evidence; it does not relabel a phone-local outcome. The app shows whether a request stays on the phone or goes to the paired home computer and requires an explicit action before sending private source cards off-device. An unavailable route remains unavailable.

The home route places an XNET gateway in front of the host harness rather than exposing an OpenAI-compatible model server to the phone. Pairing credentials belong in the iOS Keychain; the host must bind to an explicitly selected private interface, authenticate and scope every request, reject replay, and retain an idempotency key before dispatch. An uncertain Swift transport retains the already encoded request and exposes only an explicit byte-identical retry while blocking a different request. Transport success is not answer correctness.

NetBird can supply private reachability, but it does not replace app authentication. On iPhone, the observed NetBird/Proton VPN conflict means remote-home mode uses NetBird while connected; Proton Drive remains a separate archive application. XNET must not attempt to toggle either VPN or assume both tunnels can coexist.

## Windows local intelligence

The supported bridge here uses `Microsoft.Windows.AI.Text.LanguageModel` from the Windows App SDK: readiness check, caller-owned creation and asynchronous response generation. `LanguageModelResponseResult` exposes text, status and extended error. The sample captures these separately; it never treats a completed call as a passed answer. [LanguageModel API](https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.windows.ai.text.languagemodel), [response result](https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.windows.ai.text.languagemodelresponseresult)

The consumer Copilot application is a distinct application/service experience. Its presence is not proof that a supported local inference API exists on the computer. Microsoft documents cloud processing for Copilot text/voice interactions. This adapter does not automate that UI, reuse its authentication or expose a private endpoint. [Microsoft Copilot service behavior](https://support.microsoft.com/en-us/microsoft-copilot/copilot-wake-word-hey-copilot)

Native model availability depends on OS build, hardware, installed AI components, SDK/package access and model access policy. Copilot+ NPU and supported discrete-GPU paths have different prerequisites; an arbitrary CPU/GPU or an installed Copilot app is insufficient. The current GPU documentation requires an Insider Experimental build and matching experimental SDK/driver, and its optional model can be downloaded through `EnsureReadyAsync`. This release performs no such download or configuration change. [Windows native setup](https://learn.microsoft.com/windows/ai/apis/get-started), [supported model/hardware paths](https://learn.microsoft.com/windows/ai/apis/phi-silica)

`GetReadyState()` is the only preflight action. `NotReady` stays unavailable until the user separately chooses an installation action. Phi Silica access can require a Limited Access Feature token. Microsoft is transitioning the OS model toward Aion Instruct; availability and access rules must be rechecked for the actual SDK and installed component instead of inferring them from a brand or forecast date. Do not ship access tokens or modify registry rollout settings in a source example. [Microsoft model access/transition](https://learn.microsoft.com/windows/ai/apis/phi-silica)

`GetUsablePromptLength` returns an index in the prompt where its window limit is reached, not a token occupancy count. The example uses it only for a fit check; tokens remain unmeasured and HALO calibration inactive. The documented options include sampling/filter settings, not the Apple-style `maximumResponseTokens` option. Keep resource deadlines caller-owned and verify output independently. [Prompt fit API](https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.windows.ai.text.languagemodel.getusablepromptlength), [Windows generation options](https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.windows.ai.text.languagemodeloptions)

See [Windows source example](../examples/native/windows/WindowsNativeContextBridge.cs).

## Shared verified-context boundary

The examples accept `source_id`, exact UTF-8 text in `utf8`, full lowercase `sha256` and explicit `classification`. They also require caller-owned trusted source pins and classifications obtained independently of the record. Verify original bytes and classification before prompt wrapping, then retain source/capsule/selection identities in the caller's receipt layer. A self-declared matching digest alone does not authenticate a source.

These references construct separate native prompts. They do not parse the strict canonical `xnet.native_context_v1` request or claim tested wire compatibility with it. A caller wrapper must inspect its full trusted expected wire hash and map admitted records explicitly. The native references retain classification and perform no export.

Presentation JSON in the examples is not an HCE wire codec. HCE capsule and receipt verification, source classification, local CAS/indexing and safe UTF-8 slice selection remain caller operations. The current HCE public-source contract does not authorize relabeling private household notes as public.

The native provider sees selected source cards as untrusted data. Cards grant no tool, filesystem, camera, browser or network authority. A generated citation must reference an admitted card and still be checked for support; correct syntax or structured output does not prove the claim.

OS-managed model identity is opaque. Record the backend, OS/build, SDK/app identities, readiness and any model version the provider actually reports. Do not manufacture a weight SHA-256 or satisfy an existing full-weight-hash attestation using the hash of a model name. These examples explicitly leave HALO calibration inactive.

The source loop, RAG selection, context review, feedback, learning promotion and optional drive circulation remain separate tested stages. A model call does not make every ring green. Learning can update independently validated guidance and retrieval policy; these examples do not change weights or demonstrate learning uplift.

## Acceptance gates

1. Review and compile each example against the selected native SDK; record its exact version and application identity.
2. Verify Unicode source bytes, trusted-pin mismatch, duplicate source IDs, missing identity and byte-budget refusal before model creation.
3. Prove unavailable/no-download behavior with a recording stub and on the real unsupported/not-ready state when available.
4. Run one source-backed task offline on the actual device and capture native status, complete output and elapsed time.
5. Validate prompt budget behavior, output limits, cancellation and restart without silently replacing completed responses.
6. Calibrate any provider-specific HALO policy with actual measured evidence; retain unmeasured capabilities as such.
7. Compare frozen fixed and learned guidance on disjoint tasks before claiming improvement or activating a candidate.

## Licensing and alternatives

XNET example source is MIT. Apple Foundation Models and Windows OS models remain governed by their platform agreements and access conditions; they are not redistributed or relicensed as MIT. Retain platform guardrails. [Apple developer terms](https://developer.apple.com/support/terms/apple-developer-program-license-agreement/), [Apple Foundation Models requirements](https://developer.apple.com/support/terms/acceptable-use-requirements-for-the-foundation-models-framework/)

An optional custom model can later use a caller-owned MLX Swift/MLX Swift LM adapter on Apple hardware, or another supported local runtime. Its weights, tokenizer/template, license, memory fit and HALO profile require separate identification and testing. No alternative is loaded automatically when a built-in provider is unavailable. [MLX Swift LM](https://github.com/ml-explore/mlx-swift-lm)
