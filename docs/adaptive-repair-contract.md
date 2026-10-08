# Adaptive repair contract r04

`xnet.adaptive_repair_contract` is the portable, public-only boundary between a
caller-owned model transport and XNET's bounded repair evaluator. Importing or
calling it starts no model process, opens no port, and executes no candidate
source.

The module is the byte-identical release copy of the reviewed public-only r04
contract. The older sealed run remains evidence only and is not modified by
this module.

## Flow

1. `prepare_request()` accepts a public task and returns model messages, a
   task-specific strict JSON Schema, a GBNF fallback, and harness-only request
   provenance. Send one provider constraint, never both.
2. The model returns exactly `replacements` and `lesson_id`. It does not return
   a complete bundle, QR, HCE, hashes, or lesson metadata.
3. `admit_response()` strictly decodes the response, rejects unknown or
   duplicate fields and no-op edits, merges changed editable files into the
   frozen bundle, and adds harness-owned provenance. This step only parses ASTs
   to detect semantic no-ops; it does not execute source.
4. Grade the admitted complete bundle with `evaluate_bundle()`. Freeze the
   original file allowlist and import graph before accepting a revision.

```python
from xnet.adaptive_repair_contract import admit_response, prepare_request
from xnet.swe_repair_evaluator import declared_import_graph, evaluate_bundle

original_files = task["files"]
import_graph = declared_import_graph(original_files)
prepared = prepare_request(task, phase="adaptive", attempt=1)

# response_text comes from a caller-owned transport.
admitted = admit_response(response_text, prepared=prepared, task=task)
if admitted["status"] == "admitted":
    report = evaluate_bundle(
        admitted["candidate"]["files"],
        task["entry_file"],
        task["entry_function"],
        task["public_cases"],
        allowed_files=original_files,
        import_graph=import_graph,
    )
```

`evaluate_bundle()` uses the isolated bounded AST interpreter and fixed local
linker. Candidate modules never enter Python's import system. Public retry
feedback must come only from the displayed public F2P cases. Hidden cases stay
host-side until choices are frozen, and metamorphic probes remain diagnostic and
excluded from solve and lesson-promotion metrics.

Admission and evaluator limits are independent. R04 admission allows one to
eight files and up to 65,536 bytes per replacement; the current bundle evaluator
requires two to four modules, limits each module to 32,768 bytes, and limits the
complete bundle to 65,536 bytes. An admitted response can therefore still be
rejected by the evaluator.

## Verify

```powershell
python -B -m unittest discover -s tests -p test_adaptive_repair_contract.py -v
```
