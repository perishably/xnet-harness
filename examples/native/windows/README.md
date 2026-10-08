# Windows local language-model bridge example

**Build status: NOT COMPILED. No matching SDK, packaged app or native inference has been validated.**

This C# source targets a caller-owned application using `Microsoft.Windows.AI.Text.LanguageModel`. It does not automate the consumer Copilot app or assume that app exposes an inference API.

Call `Preflight()` to read `LanguageModel.GetReadyState()`. Only `Ready` permits the separate caller-invoked `AnswerAsync` method. `NotReady`, unsupported hardware, missing package access or unavailable SDKs remain explicit failures. The example never calls `EnsureReadyAsync`, installs a component or uses a cloud fallback.

The host needs a compatible Windows App SDK, architecture, OS/hardware, package identity/capability and any required Microsoft Limited Access Feature authorization. These are deployment requirements, not changes this example makes to the user's computer. The current model transition and hardware differences are described in [native-intelligence.md](../../../docs/native-intelligence.md).

Records use `source_id`, exact `utf8` text, full lowercase `sha256` and explicit `classification`. Supply trusted pins and classifications independently from the caller's verified store. The bridge verifies original bytes before prompt wrapping; this presentation JSON is not an HCE wire encoder.

This reference constructs its own native prompt. It does not parse or assert byte compatibility with `xnet.native_context_v1`'s strict canonical request. A caller wrapper must inspect that full request and its trusted expected wire hash before mapping approved records into these types.

`GetUsablePromptLength` is a prompt index fit check. It is not a tokenizer count or an output reserve. Token occupancy is recorded as unmeasured, HALO calibration stays inactive, and the caller must choose smaller safe UTF-8 slices when a prompt does not fit. SDK status, errors and completed output remain available for private receipt capture and independent grading.

The caller owns cancellation/deadlines, storage, scope, source classification, UI display, output verification and learning gates. No tools or external actions are registered.
