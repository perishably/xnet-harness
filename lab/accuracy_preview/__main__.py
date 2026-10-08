"""Source-checkout CLI; offline checks run in a separate Python process."""
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile

from . import load_cli, verify_sources


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--offline-checks"]:
        verify_sources()
        here = Path(__file__).resolve().parent
        # The copied origin runner writes its receipt beside itself. Keep the
        # distributed historical evidence immutable while checking a new copy.
        with tempfile.TemporaryDirectory(prefix="xnet-preview-checks-") as scratch:
            copy = Path(scratch) / "accuracy_preview"
            shutil.copytree(here, copy, ignore=shutil.ignore_patterns("__pycache__"))
            return subprocess.run([sys.executable, "-B", str(copy / "run_offline_checks.py")],
                                  cwd=copy, timeout=300).returncode
    return load_cli().main(args)


if __name__ == "__main__": raise SystemExit(main())
