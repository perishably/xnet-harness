# XNET~ v0.1.0 public release checklist

- Release author and authority: **Felix Xavier Lopez**
- License: [MIT](LICENSE)
- Release notes: [docs/release-notes-v0.1.0.md](docs/release-notes-v0.1.0.md)
- Build timeline: [docs/build-timeline.md](docs/build-timeline.md)

Every item below is a blocking release gate. Retain command output, exact
commit identities, scanner versions, artifact hashes, and the human sign-off
with the private release record. A green check without its evidence is not a
pass.

## 1. Freeze the claims

- [ ] Review the release notes against the [coverage inventory](docs/coverage.md),
  [verification record](docs/verification.md), and [security policy](SECURITY.md).
- [ ] Confirm the spent-board wording says 7/8 in one sealed run and 8/8 only
  across separate chains, and does not call the result unseen or SWE-bench.
- [ ] Verify the Blind Repair 50 table against the sealed grade, summary,
  choices, hidden-suite commitment, and environment identities. Confirm it
  reports Raw 32/50, Retrieval only 27/50, and Full XNET 29/50, retains the
  zero-credit status-599 transport failure, and states that the initial gate
  failed and no harness uplift was shown.
- [ ] Confirm iPhone and Windows examples remain labeled source-only and
  unverified on real devices.
- [ ] Confirm Legions is described as the implemented transport-free contract
  core; network, discovery, sandboxing, scheduling, quorum, and aggregation
  remain future work.
- [ ] Confirm the timeline labels private reports, reported-only milestones,
  planned work, and public reproducible evidence separately.

## 2. Human provenance and license sign-off

- [x] Felix Xavier Lopez completed the dated human signature block in
  [PROVENANCE.md](PROVENANCE.md) and authorized the MIT public release on
  2026-10-07. After the one-commit snapshot is created, record its commit and
  `source-manifest.json` SHA-256 in the external release record and immutable
  tag; verify that snapshot is byte-identical to the reviewed candidate.
- [ ] Review [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), every retained
  file under `third_party/`, and dependency lockfiles against the final tree.
- [ ] Confirm copied, adapted, or materially generated content has an identified
  source and compatible license.
- [ ] Confirm the release contains no private user data, restricted benchmark
  answers, credentials, model weights, provider responses, or third-party
  source without redistribution permission.

The provenance signature is complete. The snapshot identity binding and every
other unchecked gate below remain blocking until their evidence is recorded.

## 3. Clean one-commit public snapshot

- [ ] Build the publication repository from the reviewed candidate without
  private development history.
- [ ] `git status --porcelain=v1` returns no output.
- [ ] `git rev-list --count HEAD` returns `1` in the publication clone.
- [ ] Inspect `git for-each-ref` and confirm no extra branch, tag, replace, note,
  pull-request, or other ref exposes pre-release history.
- [ ] `git fsck --full` completes successfully.
- [ ] The single commit tree matches the human-reviewed inventory. Record the
  commit identity in the external release record and published tag, and bind
  that record to the dated maintainer attestation.

## 4. Secret, private-data, and large-file scan

- [ ] Run the approved secret scanner over the worktree **and the complete
  reachable one-commit Git object set**. Record scanner name, version, rules,
  command, and zero unresolved findings.
- [ ] Search for private machine paths, usernames, home directories, API keys,
  bearer tokens, invitation codes, private endpoints, provider responses,
  hidden benchmark material, and personal data. Review matches manually.
- [ ] List every tracked file by byte size. Review all files above the approved
  threshold and reject model weights, binaries, archives, logs, caches,
  database files, generated runtime roots, and unexplained large assets.
- [ ] Confirm private receipts cited by filename and hash in the release notes
  and timeline are **not** present unless the final source inventory explicitly
  admits them after provenance review.
- [ ] Confirm `.gitignore` does not substitute for scanning already tracked or
  reachable objects.

## 5. Tests and platform evidence

- [ ] Run the complete applicable Python suite:

  ```sh
  python -m unittest discover -s tests -v
  ```

- [ ] Run the locked Rust workspace and build the native CLI:

  ```sh
  cargo test --locked --workspace --manifest-path rust/Cargo.toml
  cargo build --locked --manifest-path rust/Cargo.toml -p xnet-cli
  ```

- [ ] Run the separate locked Jcode Rust adapter workspace:

  ```sh
  cargo test --locked --workspace --manifest-path adapters/jcode/rust/Cargo.toml
  ```

- [ ] Run the portable demonstration and the Apple metadata-only validator:

  ```sh
  python -m xnet demo
  python examples/native/apple/validate_project.py
  ```

- [ ] Run focused release, refusal, updater, inventory, benchmark-protocol, and
  Legions checks required by the final diff.
- [ ] Hosted Windows and Ubuntu CI pass at the exact release commit. Inspect
  individual job logs, test counts, expected skips, and every Rust command;
  an overall green conclusion alone is insufficient.
- [ ] Record every skip and platform limitation. Do not count an unbuilt native
  binary, unavailable device, or unsupported SDK as a pass.

## 6. Exact inventory

- [ ] Review Git's tracked and non-ignored candidate list. Every path is a
  regular file with a safe relative name; no symlink, junction, or path escape
  is admitted.
- [ ] Ensure `docs/release-notes-v0.1.0.md`, `docs/build-timeline.md`, and
  `RELEASE_CHECKLIST.md` are included in the final reviewed inventory.
- [ ] The release owner refreshes `MANIFEST.in` and `source-manifest.json` from
  the final tree, then runs:

  ```sh
  python scripts/release_inventory.py --check
  ```

- [ ] The inventory check reports `release inventory verified` without changing
  either file.
- [ ] Independently recompute every `source-manifest.json` size and SHA-256,
  confirm it does not hash itself, and record the manifest file's own SHA-256
  in the release record.

## 7. Artifact inspection

- [ ] Build the approved source artifact from the clean one-commit snapshot in
  an empty output directory. If a wheel is also produced, treat it as a
  separate artifact with its own inspection and hash.
- [ ] List archive members before extraction and reject absolute paths, `..`,
  links, duplicate normalized names, device names, or case-colliding members.
- [ ] Extract into a fresh temporary directory and verify all files against the
  reviewed source manifest.
- [ ] Confirm the MIT license, third-party notices, provenance statement,
  release notes, timeline, security policy, contributing guide, source, tests,
  benchmark protocol/corpus, and release checklist are present as intended.
- [ ] Repeat the secret and large-file scans against the extracted artifact.
- [ ] Install or run only from the extracted artifact and repeat the portable
  smoke test. Do not rely on imports from the original checkout.
- [ ] Record artifact filenames, byte sizes, member counts, and SHA-256 hashes.

## 8. Fresh public-clone verification

- [ ] Make the repository public only after gates 1–7 pass and the final action
  is explicitly authorized by Felix Xavier Lopez.
- [ ] From an empty directory with no credentials or original-repository path
  on `PYTHONPATH`, clone the public URL and verify the expected remote URL,
  default branch, final commit, and one-commit history.
- [ ] Confirm an unauthenticated reader can fetch the repository, license,
  notices, release notes, and source manifest.
- [ ] Run the editable installation, portable demo, inventory check, and the
  applicable test commands from the public clone.
- [ ] Compare the public clone's tree and source-manifest SHA-256 with the signed
  release record and inspected artifact.
- [ ] Inspect the public Git host for unexpected branches, tags, releases,
  Actions artifacts, caches, pull refs, or attachments that expose excluded
  material.
- [ ] If any identity, inventory, provenance, scan, test, or clone check fails,
  stop distribution, preserve the failure evidence, correct the candidate, and
  repeat every affected gate.

## 9. Final release record

- [ ] Record the public URL, final commit, signed provenance identity,
  `source-manifest.json` SHA-256, artifact hashes, CI run URLs, scanner reports,
  inventory result, and public-clone verification result.
- [ ] Record the exact Blind Repair 50 grade, summary, choices, hidden-suite,
  environment, failed-attempt, and same-configuration restart identities.
- [ ] Publish no broader performance, safety, device, cloud, or distributed
  compute claim than the evidence in the final source release supports.
