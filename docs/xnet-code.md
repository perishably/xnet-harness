# XNET Code and the Jcode lineage

`xnet code` is the planned XNET product surface for interactive coding. Jcode is an optional attributed engine behind that surface. XNET owns the surrounding model-neutral system: provider identity, routing, scope, RAG, HCE, HALO, Oroboros circulation, evidence, bounded evaluation, learning gates and benchmark tooling.

The current source release contains XNET-authored Jcode adapters and policy crates. It does not yet bundle the full Jcode application. A future one-clone distribution should import a pristine pinned Jcode revision as a history-preserving Git subtree, followed by separate reviewed XNET modification commits.

```text
xnet-harness/
|-- xnet/                         XNET control plane
|-- rust/crates/                  XNET runtime, policy and scope
|-- adapters/
|   |-- openai-compatible/        local model backend
|   `-- jcode/                    XNET/Jcode boundary
|-- components/jcode/             attributed pinned subtree (planned)
|-- templates/local-4b/           secret-free profile
`-- component-manifest.json       origins, versions, hashes and licenses
```

## Product rules

- Users invoke XNET commands: `xnet code`, `xnet run`, `xnet dojo`, `xnet benchmark`.
- Model backends are interchangeable and report identity, capabilities, health, token counting, completion, cancellation and reconciliation.
- Upstream Jcode crate names remain inside its component boundary so updates and authorship stay visible.
- XNET-owned policy, scope and adapter crates use XNET names. Compatibility crates may re-export them during migration.
- No local dirty worktree, credentials, `.jcode` state, model weight or compiled binary enters the source release by bulk copy.

## Attribution

MIT permits modification, combination, redistribution, rebranding and commercial use. It also requires preservation of the original copyright and permission notice.

An accurate combined-product statement is:

> XNET is authored by Felix Xavier Lopez. This distribution may include a modified fork of Jcode, originally copyright 2025 Jeremy Huang, distributed under the MIT License. XNET-specific adapters and modifications are copyright 2026 Felix Xavier Lopez.

The complete user experience can be called XNET. The upstream Jcode implementation remains credited to its authors. See `THIRD_PARTY_NOTICES.md` and `third_party/jcode-LICENSE.txt`.
