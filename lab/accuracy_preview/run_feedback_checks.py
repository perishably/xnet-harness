"""Write only feedback-extension receipts; leave baseline evidence unchanged."""
from datetime import datetime, timezone
import io
from pathlib import Path
import time
import unittest

from . import verify_sources, adapter


def pins():
    here = Path(__file__).resolve().parent
    return {name:adapter.digest((here / name).read_bytes()) for name in (
        "feedback_preview.py","test_feedback_preview.py","run_feedback_checks.py","__init__.py","README.md")}


def main():
    here = Path(__file__).resolve().parent
    origin = verify_sources(); before = pins(); stream = io.StringIO(); started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromName("lab.accuracy_preview.test_feedback_preview")
    result = unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    elapsed = time.monotonic()-started
    stable = before == pins() and origin == verify_sources()
    log = stream.getvalue().encode("utf-8")
    receipt = {"schema":"xnet.feedback-preview-offline-checks.v1",
        "created_at_utc":datetime.now(timezone.utc).isoformat(),"success":result.wasSuccessful() and stable,
        "tests_run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
        "elapsed_seconds":round(elapsed,6),"extension_source_pins":before,"unchanged_origin_files":origin,
        "source_stability_confirmed":stable,"log_sha256":adapter.digest(log),
        "operations":{"model":0,"worker":0,"network":0,"hidden_grader":0},
        "fixtures":"authored public Git and seeded immutable public JSON; no review/transport dispatch",
        "scope":"optional source-checkout feedback visibility; no budget/tool/policy/acceptance change"}
    adapter.atomic_write(here / "evidence/feedback-preview-checks-r01.log",log)
    adapter.atomic_write(here / "evidence/feedback-preview-checks-r01.json",adapter.canonical(receipt))
    print(stream.getvalue())
    print(adapter.canonical({"success":receipt["success"],"tests_run":result.testsRun,
        "receipt_sha256":adapter.digest(adapter.canonical(receipt)),"elapsed_seconds":round(elapsed,6)}).decode())
    return 0 if receipt["success"] else 1


if __name__ == "__main__": raise SystemExit(main())
