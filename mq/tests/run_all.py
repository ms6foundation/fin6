"""Run every test module and report one combined pass/fail.

    python3 tests/run_all.py      # or: python3 -m tests  (cwd: repo root)

Exits non-zero if any check fails, listing the failures by name.
"""
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
_tests = Path(__file__).resolve().parent
sys.path.insert(0, str(_root))   # repo root -> ms6, vs6
sys.path.insert(0, str(_tests))  # tests/   -> harness, test_* modules

import bench                   # noqa: E402
import test_adversarial        # noqa: E402
import test_completeness       # noqa: E402
import test_forge_hardened_fold      # noqa: E402
import test_forge_hardened_fold_gq   # noqa: E402
import test_forge_unknownoder        # noqa: E402
import test_leak               # noqa: E402
import test_modulus            # noqa: E402
import test_params             # noqa: E402
import test_parity             # noqa: E402
import test_query_governance   # noqa: E402
import test_roundtrip          # noqa: E402
import test_sealtree           # noqa: E402
import test_sizing             # noqa: E402
import test_updatability       # noqa: E402
from harness import Checker    # noqa: E402

MODULES = [
    ("round trip",              test_roundtrip),
    ("updatability",            test_updatability),
    ("modulus",                 test_modulus),
    ("seal tree",               test_sealtree),
    ("params",                  test_params),
    ("copy parity",             test_parity),
    ("sizing",                  test_sizing),
    ("completeness",            test_completeness),
    ("adversarial",             test_adversarial),
    ("leak",                    test_leak),
    ("query governance",        test_query_governance),
    ("forge: hardened fold",    test_forge_hardened_fold),
    ("forge: hardened fold GQ", test_forge_hardened_fold_gq),
    ("forge: unknown-order",    test_forge_unknownoder),
]


def main():
    check = Checker()
    for title, mod in MODULES:
        print(f"\n{title}")
        mod.run(check)
    print("\nbenchmark (informational, never fails the run)")
    bench.run()
    return check.report("checks")


if __name__ == "__main__":
    raise SystemExit(main())
