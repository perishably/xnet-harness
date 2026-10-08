# XNET Home for iPhone and Apple on-device bridge

**Build status: NOT COMPILED. The Swift/Xcode metadata check passes, but no Swift tests, app installation, physical-device inference, or performance run has been completed.**

This directory now contains a SwiftUI source app scaffold plus the standalone bridge. The app imports or pastes approved UTF-8 sources, retains exact originals in its protected sandbox, creates deterministic byte slices, lets the user review the selected cards, and explicitly calls `SystemLanguageModel.default`. It registers no tools and selects no cloud model. The proposed measured-token path targets iOS 26.4 or later and needs a matching Xcode SDK on macOS.

The metadata-only check is safe to run on Windows or Linux:

```sh
python examples/native/apple/validate_project.py
```

That check parses the authored Xcode project, scheme, privacy manifest, source membership, and test declarations. It does not compile Swift or establish device support.

## Frozen iPhone-first routing ceiling

The generic model policy keeps the optional device-qualified BYOM lane named `xnet-4b`. The remote-host mobile wire is a separate, fixed **Apple native -> home 4B -> home 14B** path. `xnet-4b` is invalid on that wire. A caller can record an explicit, evidence-carrying adapter choice from generic `xnet-4b` intent to `home-4b`; no gateway code silently aliases a phone-local outcome to a home-host result. Every off-device send remains a visible user action.

1. **Apple native first.** Use the on-device `SystemLanguageModel` for grounded retrieval answers, extraction, classification, summarization, and other short home tasks when the OS reports it ready. Apple's current documentation reports a 4K system-model context, so retrieval cards and measured headroom matter more than stuffing the window.
2. **Qualified phone-local `xnet-4b`.** A user-selected phone-local model is a builder option only after its exact weights, tokenizer, template, runtime, memory fit, context behavior, and license pass a device-specific lane-card and HALO calibration. This scaffold does not yet contain that runner. A desktop 4B pin does not transfer to an iPhone.
3. **Remote `home-4b`, then `home-14b`.** Coding or reasoning can be sent, only after explicit user action, to an authenticated XNET gateway on the user's own home computer. The gateway requires a trusted exact Apple-native outcome before `home-4b` and its exact immediately prior 4B response before `home-14b`. Neither model is loaded on the phone, and there is no public cloud fallback.

The app source now exposes minimal pairing, remote lane selection, send, and byte-identical pending retry controls. The client keeps its bearer in the this-device-only Keychain and retains uncertain canonical request bytes in memory for explicit retry. The host protocol and pure gateway gate are included, but a caller still owns the TLS listener, trusted Apple-outcome/HCE/source stores, and model dispatcher. None of this has been compiled or exercised end to end.

Call `AppleNativeContextBridge.preflight()` first. It only reports availability. Unsupported hardware, disabled Apple Intelligence or a model that is not ready must stay unavailable; the example does not enable features or download models.

Only an explicit caller invocation of `answer` performs inference. Supply reviewed source records with `source_id`, exact `utf8` text, full lowercase `sha256` and explicit `classification`, plus trusted source pins and classifications obtained independently from the caller's verified source store. A digest supplied only by the same untrusted packet is insufficient admission evidence.

This reference constructs its own native prompt. It does not parse or assert byte compatibility with `xnet.native_context_v1`'s strict canonical request. A caller wrapper must inspect that full request and its trusted expected wire hash before mapping approved records into these types.

The bridge checks original UTF-8 bytes before wrapping them as untrusted source context. That wrapper is presentation JSON, not an HCE wire encoder. The caller owns durable HCE records, source classification, safe UTF-8 slice selection, receipts, cancellation, grading and learning promotion. A fresh session is used for each call.

Token counts are the SDK-visible prompt/instruction component measurements. A caller-declared padding reserve leaves room for framework overhead; the native context-size error still needs caller handling. No HALO pin is activated. Completed output is returned intact with a display-budget flag, not clipped or labeled correct.

Build, run and profile on the actual supported iPhone before reporting this integration as active. The source-only app entry point is `XNETHome/App/XNETHomeApp.swift`; its deterministic source core is packaged separately by `Package.swift` so it can be tested on macOS without a device. Refer to [native-intelligence.md](../../../docs/native-intelligence.md) for requirements and acceptance gates.
