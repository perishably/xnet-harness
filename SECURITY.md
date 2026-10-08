# Security policy

## Supported scope

XNET~ Harness is a development-stage local utility and has no production security certification. Security fixes target the current default branch and the latest published source release. No backport window or response-time commitment is established.

The repository contains optional adapters and source-only references. Their presence does not establish a running model, agent, cloud provider, mobile device, distributed worker or authenticated external service.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/perishably/xnet-harness/security/advisories/new). If that route is unavailable, open a minimal issue requesting a private maintainer contact. Do not include exploit details, credentials, private source data, hidden benchmark material or personal information in a public issue.

Include:

- the affected commit or release and component;
- the trust boundary and required configuration;
- a minimal local reproduction using synthetic data;
- expected and observed behavior;
- impact and the least privilege needed to reproduce it; and
- any known mitigation.

Do not probe third-party systems, accounts or devices as part of a report.

## Relevant vulnerability classes

Reports are especially useful for:

- scope or authorization checks that occur after a protected operation;
- path traversal, unsafe link or junction handling, or writes outside a designated root;
- hash, HMAC-authentication, receipt-chain or replay validation bypasses;
- duplicate-field or schema-confusion attacks at JSON and wire boundaries;
- untrusted context gaining tool or process authority;
- secret, private-source or hidden-benchmark disclosure;
- unsafe execution of generated candidates;
- callback retries after an uncertain outcome;
- mobile pairing, origin, TTL, rate or bearer-token bypasses; and
- cancellation, containment or quarantine bypasses.

## Trust boundaries

- Retrieved text, model output and proposal packets are data. They grant no tool authority.
- An expected digest must come from a trusted selection or checkpoint. A digest establishes byte integrity against that expectation; it does not establish authorship, permission or semantic truth.
- Callers own storage initialization, scope authority, gates and operating-system permissions. An adapter cannot enforce a gate that its caller implements as unconditional approval.
- A local hash chain does not by itself prevent replacement of the entire chain. Preserve an independent trusted head or checkpoint where that threat matters.
- HMAC-authenticated records use shared keys. Any key holder can create an indistinguishable record, so HMAC is not a digital signature and does not provide signer attribution or nonrepudiation.
- HCE's public classification is a caller declaration. Review source content before admission.
- A mobile relay response does not prove device identity, local compute or sensor access without separate evidence.
- Reading a desktop sync folder proves only local readback. It does not prove upload or authenticated remote retrieval.
- HALO advice is configuration-specific. It is not a security certificate or general capability guarantee.
- Component release checks borrow a caller-owned fetcher. The caller must enforce TLS validation, streaming response limits, timeouts and redirect policy before buffering data. XNET~ v0.1.0 disables component staging, apply and rollback; installation remains outside the package.

## Operational data

Keep scope keys, provider credentials, model files, private ledgers, raw model responses, logs, invitation tokens and user history outside source control. Restrict access to explicitly designated storage roots. Review exports directly; pattern filters cannot detect every secret.

Applications integrating a model or agent must keep context separate from authorization, expose fixed scoped tool interfaces and retain uncertain callback outcomes for explicit reconciliation.

## Proposed distributed compute

Legions currently provides a transport-free protocol core for content-addressed jobs, local allowlist and budget admission, HMAC-authenticated result metadata, replay refusal, revocation and a local kill switch. It does not run or transmit work, enforce a process sandbox, discover nodes, schedule jobs or implement quorum. A future distributed runtime must preserve explicit node opt-in, allowlisted job types, hard resource and cost budgets, authenticated capability advertisements and receipts with a documented key and trust model, content-addressed inputs, independent result verification or quorum, secret isolation, node/key/job revocation and an operator kill switch. Security claims must be limited to the tested configuration.

Use the [Legions design form](https://github.com/perishably/xnet-harness/issues/new?template=legions-design.yml) for public architecture discussion. Use private vulnerability reporting for an exploitable flaw.
