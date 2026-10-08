"""Run only authored fixtures and write source-bound offline acceptance receipts."""
from datetime import datetime, timezone
import io
from pathlib import Path
import time
import unittest

from controller import source_pins, adapter, canonical, digest


def main():
    here = Path(__file__).resolve().parent
    initial = source_pins()
    tests = digest((here / "test_alignment.py").read_bytes())
    runner = digest(Path(__file__).read_bytes())
    log = io.StringIO(); started = time.monotonic()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.discover(str(here), "test_alignment.py"))
    elapsed = time.monotonic() - started
    stable = initial == source_pins() and tests == digest((here / "test_alignment.py").read_bytes())
    output = log.getvalue().encode("utf-8")
    evidence = here / "evidence"
    adapter.atomic_write(evidence / "offline-checks-r01.log", output)
    receipt = {"schema":"xnet.accuracy-preview-offline-checks.v1", "created_at_utc":datetime.now(timezone.utc).isoformat(),
        "success":result.wasSuccessful() and stable, "tests_run":result.testsRun, "failures":len(result.failures),
        "errors":len(result.errors), "skipped":len(result.skipped), "elapsed_seconds":round(elapsed,6),
        "source_pins":initial, "test_source_sha256":tests, "runner_source_sha256":runner,
        "source_stability_confirmed":stable, "log_sha256":digest(output),
        "operations":{"live_model":0,"live_worker":0,"ssh":0,"docker":0,"network":0,"hidden_grader":0},
        "fixtures":"operator-authored public Git, fake model/tokenizer/public-worker callbacks; local Python/Git only"}
    adapter.atomic_write(evidence / "offline-checks-r01.json", canonical(receipt))
    print(log.getvalue())
    print(canonical({"success":receipt["success"],"tests_run":result.testsRun,"elapsed_seconds":round(elapsed,6),
                     "receipt_sha256":digest(canonical(receipt))}).decode())
    return 0 if receipt["success"] else 1


if __name__ == "__main__": raise SystemExit(main())
