# Contributing to XNET~ Harness

XNET~ Harness welcomes focused fixes, documentation, adapters and evidence-backed experiments. The project is an MIT-licensed utility harness: applications keep control of models, credentials, tools, sessions and external services.

By submitting a contribution, you agree that it may be distributed under the repository's [MIT license](LICENSE). You retain copyright in work you create. You must have the right to submit every code, data and documentation fragment in the change and must preserve applicable upstream notices. See [PROVENANCE.md](PROVENANCE.md).

## Start with the contract

Open an issue before a large change, a new protocol or schema, a new dependency, or work that reaches an external service. Describe the behavior, trust boundary, versioned interface and a small acceptance test. A focused pull request is easier to verify than a combined integration.

Use the issue form that matches the work:

- [Bug report](https://github.com/perishably/xnet-harness/issues/new?template=bug-report.yml)
- [Feature or extension proposal](https://github.com/perishably/xnet-harness/issues/new?template=feature-request.yml)
- [Benchmark evidence](https://github.com/perishably/xnet-harness/issues/new?template=benchmark-evidence.yml)
- [Legions distributed-compute design](https://github.com/perishably/xnet-harness/issues/new?template=legions-design.yml)

Report vulnerabilities through the private route in [SECURITY.md](SECURITY.md), without putting exploit details or secrets in an issue.

## Development setup

Use Python 3.11 or later in a virtual environment:

~~~sh
python -m pip install -e .
python -m unittest discover -s tests -v
python -m xnet demo
~~~

The Python core has no runtime dependency outside the standard library. Do not add a dependency when a small standard-library implementation is sufficient. Explain the license, purpose and operational cost of any proposed dependency.

For changes to the optional Rust workspace:

~~~sh
cargo test --locked --workspace --manifest-path rust/Cargo.toml
cargo build --locked --manifest-path rust/Cargo.toml -p xnet-cli
~~~

For changes to the optional Jcode Rust adapter:

~~~sh
cargo test --locked --workspace --manifest-path adapters/jcode/rust/Cargo.toml
~~~

Run the smallest relevant tests while developing and the complete applicable suite before requesting review. Use synthetic local fixtures, temporary directories and inert callbacks. Tests must not depend on a live model, account, device or network service.

## Extension points

The supported contribution seams and their acceptance criteria are documented in [docs/extension-points.md](docs/extension-points.md):

- model and provider adapters;
- retrieval and context selection;
- HALO evidence and proposed certificates;
- evaluators;
- storage transports;
- Claw source and defensive-control adapters; and
- the Legions protocol core and proposed distributed-compute runtime.

There is no global plugin registry. Extend a narrow callable, schema or adapter boundary and leave lifecycle ownership with the caller. Existing applications and external projects retain independent release and contribution processes.

## Invariants every change must preserve

- Treat retrieved text, model output and proposal packets as data with no tool authority.
- Apply scope admission before the operation it controls.
- Bind evidence to complete source hashes and versioned schemas. A matching hash establishes byte identity against an expected value; it does not establish authorship, permission or truth.
- Keep model, process, credential, session, scheduler and tool decisions with the caller.
- Preserve completed output and immutable records during recovery.
- Record uncertain callback or transport outcomes and require reconciliation before retry.
- Reject path escapes, link traversal, duplicate fields and unexpected fields at trust boundaries.
- Keep generated candidate code out of the host interpreter unless a separately reviewed isolation boundary explicitly permits execution.
- State what a test proves and what it does not prove.

## Frozen benchmark material

Treat released benchmark sources, corpus, manifests, hidden material and protocol as frozen evidence. Ordinary contributions must not edit them. Propose a new version or a separate synthetic fixture when an evaluation contract needs to change. Do not weaken admission checks to make a candidate pass.

Never commit hidden answers, private runtime state, invitation tokens, provider responses, model weights, user history, credentials or personal machine paths. Do not derive a public fixture from private or restricted material. An issue or pull request that includes benchmark results must use the benchmark evidence form and retain enough public information to reproduce the claim.

## Performance and capability claims

A claim needs:

1. the exact public fixture or manifest identity;
2. engine, model, runner, tokenizer, template and launch configuration;
3. frozen choices before held-out grading;
4. retained outputs and machine-readable receipts;
5. the grader and decision rule;
6. complete token, retry, time and monetary cost accounting; and
7. failures, exclusions, uncertainty and conflicting results.

Separate utility contract tests from model evaluations. Separate retrieval recall from reasoning quality. Name adapted, partial and synthetic benchmarks accurately. A completed workflow, valid citation or hash match is not a model solve.

## Provenance and generated assistance

In the pull request, list copied, adapted or generated material and link its source and license. Retain copyright and permission notices for MIT upstream work. Do not paste code, tests, datasets or prose whose redistribution terms are unknown or incompatible.

Disclose generated assistance that materially shaped the change and explain how a human verified it. The contributor remains responsible for correctness, security, provenance and license compatibility. This project uses an inbound-equals-outbound model under MIT; it does not require copyright assignment.

## Review checklist

Before requesting review:

- link the issue or explain why the change is self-contained;
- describe the caller and trust boundaries affected;
- add meaningful regression tests for changed behavior;
- update the relevant versioned contract and documentation;
- run and report the applicable commands;
- confirm that frozen benchmark and private material are unchanged;
- identify new dependencies and upstream material; and
- record limitations and unresolved evidence.

Maintainers may ask for a smaller interface, a synthetic fixture or a separate versioned schema when a change crosses multiple trust boundaries.
