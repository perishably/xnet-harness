# Release provenance and maintainer attestation

This file is the chain-of-title statement prepared for human review for the XNET~ Harness public source release. It complements the root [MIT license](LICENSE), [third-party notices](THIRD_PARTY_NOTICES.md), retained license texts under [third_party](third_party/) and the machine-readable [source manifest](source-manifest.json).

Repository history can show who recorded changes, but it does not independently prove ownership or the right to relicense them. The statement below becomes an attestation only when Felix Xavier Lopez reviews the final release contents and signs it.

## Maintainer statement for review

On signing, I, Felix Xavier Lopez, state to the best of my knowledge after review of this release:

1. Except for material identified below or in the third-party notices, I created the XNET-specific source and documentation in this repository and hold the rights needed to publish that work under the MIT License.
2. Where XNET adapts ideas, interface patterns or portions from an identified MIT-licensed upstream project, I used them under that upstream license, credited the upstream project and retained the applicable MIT notice.
3. Compatibility adapters and references do not transfer ownership of Jcode, OpenClaw, NullClaw, Hermes Agent or any other external application to XNET.
4. I do not knowingly include private user data, provider credentials, model weights, restricted benchmark answers or third-party source lacking redistribution permission in the public release.
5. This attestation grants rights only in the material covered by the repository's license and notices. It does not relicense external models, SDKs, services, datasets, applications or transitive dependencies.

Human sign-off recorded before publication:

~~~text
Reviewed and affirmed by: Felix Xavier Lopez
Date: 2026-10-07
Signed-off-by: Felix Xavier Lopez <perishably@users.noreply.github.com>
~~~

The commit ID and `source-manifest.json` SHA-256 are recorded after the
one-commit snapshot exists, in the published release tag and external release
record. They cannot be embedded into this tracked attestation without
changing the commit and manifest identities they name. Publication must verify
that the signed candidate tree is byte-identical to that recorded snapshot.

## Provenance map

| Material | Relationship | Copyright and license treatment |
| --- | --- | --- |
| XNET-specific Python, Rust, native reference source, tests and documentation | Original implementation unless a file or notice says otherwise | Copyright 2026 Felix Xavier Lopez; released under the root MIT License |
| Procedural-memory interface patterns | The source acknowledges adaptation from Jcode typed recall and Hermes progressive disclosure; the implementation remains XNET-specific | Jcode and Hermes Agent are MIT licensed; notices are retained in third_party and credited in THIRD_PARTY_NOTICES.md |
| Jcode adapters and proposed context-provider boundary | XNET-authored compatibility and integration code; the full Jcode application is not bundled | XNET code uses the root MIT License; Jcode's MIT notice is retained |
| OpenClaw and Hermes adapters | XNET-authored, source-only integration contracts; the upstream applications are not bundled | XNET code uses the root MIT License; upstream MIT notices are retained |
| Local NullClaw controls and xnet-nullclaw crate | XNET-authored defensive controls, distinct from the upstream Zig NullClaw agent | XNET code uses the root MIT License; the upstream NullClaw notice is retained for clear attribution |
| Files in third_party | Verbatim license notices, not bundled application source | Each notice retains its named upstream copyright and MIT terms |
| Native SDK calls, provider APIs, models, weights, services and optional toolchains | External, separately obtained components | Their vendor or upstream terms apply; they are not relicensed by this repository |

Retaining a notice can be broader than the minimum legal requirement and must not be read as a claim that the complete upstream codebase was copied. The exact scope statements in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) control the repository's attribution description.

## Contributions after this attestation

This project uses inbound-equals-outbound licensing under MIT. Contributors keep ownership of their work and grant the permissions needed to distribute their contribution under the repository license; no copyright assignment is requested.

Each pull request must identify copied, adapted and materially generated content, its source and its license. Contributors must not submit code or data they cannot redistribute. Maintainers should update the third-party notices and this provenance map when a merge changes the release's chain of title.

Once signed, the attestation is a provenance record, not a warranty that every upstream dependency is fit for a particular purpose or that a named compatibility target has accepted the integration.
