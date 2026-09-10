"""The ledger's tests.

    python3 -m chain.tests.run_all [pattern]
"""
from __future__ import annotations

import sys

from .runner import run

MODULES = ["test_notes", "test_transaction", "test_state", "test_grid",
           "test_ceremony", "test_e2e",
           # tiered design
           "test_proofs", "test_mq_backends", "test_register", "test_tiers",
           # storage
           "test_archive", "test_persistence",
           # the two trees, and the spine
           "test_seal_trees",
           # genesis
           "test_genesis", "test_growth",
           # the network, and what it will do for a stranger
           "test_net", "test_handshake", "test_gate", "test_limits",
           "test_budget",
           "test_catchup",
           # hardening
           "test_hardening"]


def main(pattern: str | None = None) -> int:
    return 1 if run("chain.tests", MODULES, pattern) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
