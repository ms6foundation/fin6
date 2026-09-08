"""Run the chain test suite without pytest.

    python3 -m chain.tests.run_all [pattern]

Every test is a plain `def test_*()` that asserts, so pytest runs them too.
"""
from __future__ import annotations

import importlib
import sys
import time
import traceback

MODULES = ["test_notes", "test_transaction", "test_state", "test_grid",
           "test_ceremony", "test_e2e",
           # tiered design
           "test_proofs", "test_mq_backends", "test_register", "test_tiers",
           # storage
           "test_archive", "test_persistence",
           # genesis
           "test_genesis", "test_growth",
           # the network
           "test_net",
           # hardening
           "test_hardening"]


def main(pattern: str | None = None) -> int:
    passed, failed, t0 = [], [], time.time()
    for name in MODULES:
        mod = importlib.import_module(f"chain.tests.{name}")
        tests = [(n, f) for n, f in vars(mod).items()
                 if n.startswith("test_") and callable(f)]
        print(f"\n\033[1m{name}\033[0m  ({len(tests)} tests)")
        for tname, fn in tests:
            if pattern and pattern not in tname and pattern not in name:
                continue
            t = time.time()
            try:
                fn()
            except Exception:
                failed.append((name, tname, traceback.format_exc()))
                print(f"  \033[31mFAIL\033[0m {tname}")
            else:
                passed.append(tname)
                print(f"  \033[32mok\033[0m   {tname}  ({time.time()-t:.2f}s)")

    print(f"\n{'─' * 62}")
    print(f"{len(passed)} passed, {len(failed)} failed in {time.time()-t0:.1f}s")
    for mod, tname, tb in failed:
        print(f"\n\033[31m{mod}.{tname}\033[0m\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
