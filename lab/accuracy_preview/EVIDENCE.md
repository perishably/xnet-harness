# Evidence history

The thirteen files listed in `origin-verification.json` remain byte-identical to
the audited source delivery. Package wrappers and the optional feedback extension
are additive and have separate identities.

`evidence/package-acceptance-r01.json` is a historical packaging snapshot. Its
wrapper and documentation hashes are not current. An earlier in-place portable
test also replaced the baseline offline receipt with a later successful 25-case
receipt. The historical record is preserved; the current distribution snapshot
is `evidence/package-acceptance-r02.json`.

The public offline CLI and portable test launcher now copy the lab into a
temporary directory. Running those checks cannot replace distributed evidence.
The CLI isolation regression check exercises that property without running a
model or worker. The optional feedback suite can be checked without writing
evidence:

```sh
python -B -m unittest -v lab.accuracy_preview.test_feedback_preview
```

`run_feedback_checks.py` is an authoring utility that intentionally writes its
named receipt and log. Its historical source-bound record describes the bytes
at the recorded time. Do not use it as a read-only distribution check. Intentional
new evidence requires a new named record and a rebuilt release inventory.

Offline checks use authored fixtures and fake transports. Live practice results
are listed separately in `../../docs/loopback-development-evidence.md`; no test
count here is a coding solve rate, unseen transfer result or official SWE-bench
score.
