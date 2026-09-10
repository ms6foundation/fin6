"""The wallet's tests.

    python3 -m wallet.tests.run_all [pattern]
"""
from __future__ import annotations

import sys

from chain.tests.runner import run

MODULES = ["test_wallet", "test_disclosure"]


def main(pattern: str | None = None) -> int:
    return 1 if run("wallet.tests", MODULES, pattern) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
