# Third-party notices

XNET's released project source is licensed under the root MIT license.

## Jcode

The optional Jcode peers and Rust adapter are XNET integration code. The full
Jcode application is external and is not bundled in this source release.
Jcode is copyright (c) 2025 Jeremy Huang and licensed under MIT:
https://github.com/1jehuang/jcode/blob/439a243bb49a78456923f4abd412ddd8d815bac1/LICENSE.
Its MIT notice is retained in third_party/jcode-LICENSE.txt for attribution
and any applicable adaptations. The license revision was verified at
439a243bb49a78456923f4abd412ddd8d815bac1 (Jcode v0.91.0) on 2026-10-07.

## Claw and Hermes integrations

The upstream licenses below were verified on 2026-10-07. Exact MIT notices are
retained under `third_party/`. These notices do not mean the complete external
applications are bundled or that their transitive dependencies share one license.

| Upstream | Verified revision | License | Retained notice and pinned source |
|---|---|---|---|
| NullClaw | d8a802fd967962be5d4f819ccd0cf1592a98f39c | MIT; copyright 2026 nullclaw contributors | [Notice](third_party/nullclaw-LICENSE.txt); [upstream](https://github.com/nullclaw/nullclaw/blob/d8a802fd967962be5d4f819ccd0cf1592a98f39c/LICENSE) |
| OpenClaw | 6cc8bb1a4b9e97b4461c5cbd9006adf4630b9ccc | MIT; copyright 2026 OpenClaw Foundation | [Notice](third_party/openclaw-LICENSE.txt); [upstream](https://github.com/openclaw/openclaw/blob/6cc8bb1a4b9e97b4461c5cbd9006adf4630b9ccc/LICENSE) |
| Hermes Agent | bf867d3c7451cbc849a56ed5b5f8222ec37909b9 | MIT; copyright 2025 Nous Research | [Notice](third_party/hermes-agent-LICENSE.txt); [upstream](https://github.com/NousResearch/hermes-agent/blob/bf867d3c7451cbc849a56ed5b5f8222ec37909b9/LICENSE) |

XNET's `nullclaw.py` and Rust `xnet-nullclaw` are local defensive control
components; they are not a vendored copy of the upstream Zig NullClaw agent.
The OpenClaw and Hermes peers are source-only integration contracts. They do not
bundle those upstream applications. Model weights, model runners, cloud clients
and hosted providers are obtained and licensed separately.

Felix Xavier Lopez has authorized and, subject to final human review of the
release provenance statement, attests MIT licensing for his XNET source,
including previously proprietary project code. Private data, secrets and model
assets are excluded from the source release and receive no license from this
file.

## Build dependencies

Python utility code uses the standard library. Setuptools is a build dependency,
not vendored project source. Rust dependencies are declared in Cargo.toml and
resolved by the retained Cargo.lock files; their original licenses apply.
No downloaded toolchain or third-party dependency source is included.

## Native provider and storage references

The authored Swift/C# reference bridges are XNET source under MIT. They call
external Apple/Microsoft SDK interfaces; the SDKs and OS-managed models retain
their vendor terms and are not bundled or relicensed here. Hardware and API
availability must be checked by the application.

The Proton Drive blueprint links to the official separate client. Proton's
Windows repository primarily uses GPL-3.0-or-later with some MIT portions.
No Proton client implementation is copied into this distribution.
The reference was verified at revision
c2836bb1938240c570d8cb94297635aea395b439 on 2026-10-07. See the
[pinned official source](https://github.com/ProtonDriveApps/windows-drive/tree/c2836bb1938240c570d8cb94297635aea395b439).
