"""The test runner, shared by all three packages.

    python3 -m chain.tests.run_all      the ledger
    python3 -m wallet.tests.run_all     the user's side
    python3 -m client.tests.run_all     what talks to a node
    python3 -m fin6.tests               all of it

Every test is a plain `def test_*()` that asserts, so pytest runs them too.
It lives under `chain/` because `chain` is the package the other two depend on;
a runner in `fin6/` would make the packages depend on the command line.
"""
from __future__ import annotations

import importlib
import time
import traceback


def run(package: str, modules, pattern: str | None = None) -> int:
    """Run one package's tests.  Returns the number of failures."""
    return report(*collect(package, modules, pattern))


def collect(package: str, modules, pattern: str | None = None):
    passed, failed, t0 = [], [], time.time()
    for name in modules:
        mod = importlib.import_module(f"{package}.{name}")
        tests = [(n, f) for n, f in vars(mod).items()
                 if n.startswith("test_") and callable(f)]
        shown = False
        for tname, fn in tests:
            if pattern and pattern not in tname and pattern not in name:
                continue
            if not shown:
                print(f"\n\033[1m{package}.{name}\033[0m  ({len(tests)} tests)")
                shown = True
            t = time.time()
            try:
                fn()
            except Exception:
                failed.append((f"{package}.{name}", tname,
                               traceback.format_exc()))
                print(f"  \033[31mFAIL\033[0m {tname}")
            else:
                passed.append(tname)
                print(f"  \033[32mok\033[0m   {tname}  ({time.time() - t:.2f}s)")
    return passed, failed, t0


def report(passed, failed, t0) -> int:
    print(f"\n{'─' * 62}")
    print(f"{len(passed)} passed, {len(failed)} failed in {time.time() - t0:.1f}s")
    for mod, tname, tb in failed:
        print(f"\n\033[31m{mod}.{tname}\033[0m\n{tb}")
    return len(failed)
