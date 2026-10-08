# XNET~ component inventory and update checks

XNET~ v0.1.0 provides one read-only surface for component inventory and release
checks. The reviewed registry is installed as the package resource
`xnet/data/components.json`, so the same manifest is used from a source tree,
an sdist, or an installed wheel. It records each component's official origin,
stable channel, reviewed release policy, platform allowlist, and retained
license notice.

Every v0.1.0 registry entry has `update_supported: false`. Jcode uses
`update_mode: check-only` because XNET can verify its pinned release metadata,
checksums, and platform selection without downloading or installing the
artifact. XNET source releases use `update_mode: report-only`. The accompanying
`update_reason` is the authoritative explanation for each disabled mutation
path.

## Jcode release pin

The reviewed Jcode release is
[v0.91.0](https://github.com/1jehuang/jcode/releases/tag/v0.91.0), commit
`439a243bb49a78456923f4abd412ddd8d815bac1`. The release uses annotated tag
object `d2ffcd62c9bc540dd913a046d62cdc0307b5e189`. The tag is unsigned, so XNET
does not present it as signed provenance. The registry instead pins the
official GitHub repository, release and tag, release identifier, publication
time, exact uploaded asset names and sizes, every artifact SHA-256, and the
SHA-256 of the release's `SHA256SUMS` file.

The checked targets are FreeBSD x86_64; Linux x86_64 and aarch64; macOS x86_64
and aarch64; and Windows x86_64 and aarch64. Windows release metadata contains
both raw executables and archives. The platform allowlist identifies the raw
`.exe`, but v0.1.0 does not fetch or stage it.

Jcode is copyright 2025 Jeremy Huang and licensed under MIT. The source
distribution retains the complete notice at `third_party/jcode-LICENSE.txt`
and the package metadata includes that license. The component registry pins
the notice hash for a future installation design.

## Supported operations

1. **Inventory** reads the packaged registry and returns a deterministic view
   of every registered component. It performs no network, process, or write
   operation.
2. **Check** receives an explicit current version and a caller-owned fetcher.
   It validates stable GitHub release metadata. For Jcode it also validates the
   complete pinned `SHA256SUMS` and the selected platform record. Check writes
   no local state and does not fetch the selected artifact.
3. **Version probe** is a separate explicit method. It passes the fixed probe
   argument tuple to a caller-owned process callback and parses a bounded
   result. Inventory and check never invoke that callback.

From a source checkout or installed package, the public CLI exposes the local
inventory operation directly:

```sh
xnet updates inventory
```

It prints one canonical JSON receipt and makes zero network calls.

`stage`, `apply`, and `rollback` are deliberately disabled in v0.1.0. Each
entry point raises `ComponentUpdateRefusal` with reason `mutation-disabled`
before it validates a stage path, reads or writes update state, calls a
fetcher, or starts any other work. Jcode download, installation, activation,
and rollback remain operator-owned or application-owned responsibilities.

## Fetch callback boundary

`xnet.component_updates` contains no HTTP client. A caller must inject a
fetcher for each check and is responsible for all transport controls:

- validate TLS certificates and hostnames;
- set connection and response timeouts;
- enforce response limits while streaming, before buffering or decompressing
  an attacker-controlled body; and
- disable redirects or validate every redirect hop and the effective final
  origin before forwarding credentials or reading a response.

The update center still rejects a `FetchedResource.url` that differs from the
exact requested URL and rejects an already materialized body over its local
limit. That string equality is defense in depth only. A callback can copy the
requested URL into the result after following a redirect, so equality cannot
attest redirect history or replace redirect policy in the fetcher.

The process callback must execute without a shell. It should map the registry's
component command name to an operator-controlled absolute executable path;
blind current-directory or `PATH` lookup is outside the trusted probe model.
No check or inventory operation invokes the process callback.

## Trust and refusal rules

The packaged registry is part of the trusted XNET distribution. Supplying or
installing a different manifest changes the trust root; a manifest digest in a
check receipt is an identifier, not a signature or authorization record.

Checks fail closed on draft or prerelease metadata, release or asset URLs
outside the exact official origin, an unallowlisted or traversal-shaped asset
name, missing or malformed checksums, digest or size mismatch, a reported
downgrade, an unsupported OS or architecture, duplicate JSON keys, and an
oversized materialized response. Hash agreement establishes byte identity
against the reviewed release pins. It does not establish signed provenance or
make an upstream binary safe to execute.
