## Summary

Describe the behavior changed and why. Link the issue or explain why the change is self-contained.

Closes #

## Contract and boundaries

- Extension point or component:
- Versioned inputs/outputs changed:
- Caller that owns authorization, lifecycle, credentials, and external services:
- Failure, timeout, cancellation, and uncertain-outcome behavior:

## Verification

List exact commands and results. Include focused regression tests and the complete applicable suite.

~~~text
command
result
~~~

For a performance or capability claim, link a completed benchmark-evidence issue with the manifest, configuration, retained outputs, grader, costs, failures, and interpretation limits.

## Provenance

- Original material added:
- Copied or adapted material, source, copyright, and license:
- Materially generated assistance and human verification:
- New dependencies and licenses:

## Checklist

- [ ] I have the right to submit this contribution under the repository's MIT license.
- [ ] I preserved applicable upstream copyright and license notices.
- [ ] I kept model, credential, tool, session, scheduler, and external-service control with the caller.
- [ ] I applied authorization before protected operations and added a denial test that observes no protected call.
- [ ] I used synthetic or redistributable fixtures and included no credentials, private data, hidden answers, model weights, or personal paths.
- [ ] I did not edit frozen benchmark sources, corpus, manifests, protocol, or hidden material.
- [ ] I added meaningful tests for changed behavior and reported the commands above.
- [ ] I documented limitations and what the evidence does not establish.
- [ ] I updated SECURITY.md, THIRD_PARTY_NOTICES.md, PROVENANCE.md, and versioned schemas when the change requires it.
