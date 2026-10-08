# XNET Blind Repair 50

XNET Blind Repair 50 is a custom frozen multi-file Python repair comparison. It is designed to measure what the XNET harness adds around one unchanged local model. It is not official SWE-bench and its score must not be presented as a SWE-bench Verified score.

## Comparison arms

Every task is attempted by the same model under three counterbalanced arms:

| Arm | Model-visible input |
|---|---|
| Raw | Public issue, source, tests, fixed evaluator capability declaration and strict changed-file schema |
| Retrieval | Raw plus cards selected deterministically from one frozen public corpus |
| Full XNET | Retrieval plus compact HCE card identities, the XNET repair route and an accordion retry that expands context only after a public failure |

All arms receive at most one retry with bounded public-test feedback. Hidden feedback never enters a prompt. The full arm starts with one retrieved card and may expand to three on retry; retrieval uses the same two cards on both attempts. All arms share strict candidate parsing, no-op rejection and the same bounded evaluator, so those safety checks cannot inflate one arm relative to another.

The common response adapter may perform only two recorded, payload-preserving envelope repairs before strict schema validation: unwrap one complete `json` Markdown fence, and append at most two unambiguous missing terminal `}` or `]` characters when parsing failed at end of input. It never edits source text, quotes, commas, keys or values. Prose around a fence, mismatched delimiters, unterminated strings, duplicate keys and every other malformed response remain rejected. The same adapter is applied to all three arms, and each accepted repair is stored in the sealed attempt receipt.

The raw arm still uses the common output schema and bounded evaluator. Those are measurement and safety infrastructure. “Raw” means the model receives no retrieved repair card or XNET route.

The primary score is a cold-prompt comparison. The pinned llama.cpp server starts with prompt caching and cache RAM disabled (`--no-cache-prompt --cache-ram 0 --no-cache-idle-slots --slot-prompt-similarity 0.0`). Its exact launch configuration is sealed with the run evidence. The v2 environment receipt also carries an explicit `performance_controls` object for thread counts, batch and microbatch sizes, K/V cache types, flash attention, GPU layers, device, and speculative decoding. The object has an exact field set and typed bounds, and it is covered by `environment_sha256`; a launch hash alone is not treated as readable disclosure of those controls. Warm prefix reuse is useful product telemetry, but it is measured separately and never folded into the cold benchmark latency claim.

## Freeze boundary

`prepare` copies only the public task set, protocol, retrieval corpus and provider profile into a fresh run root. It records a SHA-256 commitment to the separate held-out suite but does not open that file.

`run` can read only the frozen public root. It stores an immutable reservation before each inference call. If the transport outcome is uncertain, the reservation remains pending and the harness refuses to send it a second time.

`freeze` selects candidate bundles from public results. `grade` opens the exact precommitted held-out file only after all choices are immutable. It performs zero model calls. Candidate Python is never imported; the fixed XNET AST interpreter evaluates its restricted language in a bounded worker.

## One-clone workflow

XNET connects to an already running OpenAI-compatible local server. It does not download weights, accept a model license, store credentials or start a process.

```powershell
git clone https://github.com/perishably/xnet-harness.git
cd xnet-harness
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .

xnet init `
  --path .\xnet.local.json `
  --base-url http://127.0.0.1:18096/v1 `
  --model local-4b `
  --model-sha256 <64-hex-weight-hash> `
  --runtime-sha256 <64-hex-server-hash> `
  --context-tokens 8192 `
  --max-output-tokens 650

xnet doctor --profile .\xnet.local.json
```

Benchmark maintainers then use a separately authored public suite and held-out commitment:

```powershell
xnet benchmark prepare --root <new-run-root> `
  --public-suite <public-suite.json> `
  --hidden-suite-sha256 <64-hex-commitment> `
  --protocol benchmarks\blind-repair50\v1\protocol.json `
  --corpus benchmarks\blind-repair50\v1\retrieval-corpus.json `
  --profile .\xnet.local.json `
  --environment .\benchmark-environment.json

xnet benchmark run --root <run-root> --profile .\xnet.local.json
xnet benchmark freeze --root <run-root>
xnet benchmark grade --root <run-root> --hidden-suite <held-out-suite.json>
xnet benchmark report --root <run-root> --profile .\xnet.local.json `
  --source-commit <git-commit> --output RELEASE-NOTES-BENCHMARK.md
```

## Token accounting

HCE and QR-style identifiers provide integrity and addressing. They do not compress a model prompt by themselves. XNET records the complete archived bytes, selected card bytes, prompt tokens, output tokens, retrieval cost and wall time. A token saving is claimed only when the pinned provider tokenizer reports fewer input tokens.

The “accordion” is a concrete budget policy: start with one small relevant card, then expand only after a public failure. “Swarm” in this benchmark means deterministic internal roles such as retrieval, admission and grading; it does not mean several simultaneous model processes. No Mayan-math token encoding is claimed until a reversible codec beats ordinary text under the pinned tokenizer without reducing accuracy.

## Claim rules

The frozen protocol sets the acceptance gates before inference. A failed gate remains a null or negative result. Release notes include model and runtime hashes, XNET commit, hardware, all three scores, paired outcomes, token and latency costs, retries, invalid proposals and limitations.

The spent task set and receipts may be published after grading for reproducibility. A future confirmation must use another unseen set; replaying the spent set is regression testing.
