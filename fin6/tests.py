"""Every package's tests, in dependency order.

    python3 -m fin6.tests [pattern]

Dependency order on purpose: if the ledger is broken there is no point being
told that the wallet built on it is broken too, and the first failure printed
should be the one worth reading.
"""
from __future__ import annotations

import sys

from chain.tests import run_all as chain_tests
from chain.tests.runner import collect, report
from client.tests import run_all as client_tests
from wallet.tests import run_all as wallet_tests

SUITES = (("chain.tests", chain_tests.MODULES),
          ("wallet.tests", wallet_tests.MODULES),
          ("client.tests", client_tests.MODULES))


def main(pattern: str | None = None) -> int:
    passed, failed, t0 = [], [], None
    for package, modules in SUITES:
        p, f, t = collect(package, modules, pattern)
        t0 = t if t0 is None else t0
        passed += p
        failed += f
    return 1 if report(passed, failed, t0) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
