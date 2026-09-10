"""Phase H — hardening an agreed block into network history.

The ceremony decides what is true; hardening decides that it stays true.  A
block leaves the supreme mempool agreed but reversible, and enters history when
turns from a finite, single-use pool have burned themselves on it.

    pool.py    the era — 70,000 one-time turns in a Merkle tree
    draw.py    which turns stamp a block, and why nobody chooses
    stamp.py   the puzzle, the one-time signature, verification
    history.py cumulative weight, the spent-turn set, fork choice
    params.py  the 12-hour era and what it forces about the block interval
"""
from .draw import PoolExhausted, blocks_left, draw_turns, max_fork_depth
from .history import (GENESIS, HardenedBlock, HardeningError,
                      NetworkHistory, hardened_from_row)
from .params import DEMO, FAST, PRESETS, PRODUCTION, HardeningParams
from .pool import Era, EraSpec, new_era, next_era, verify_membership
from .stamp import (MiningFailed, Stamp, anchor_bytes, equivocation_evidence,
                    mine, verify_stamp)

__all__ = [
    "HardeningParams", "PRODUCTION", "FAST", "DEMO", "PRESETS",
    "Era", "EraSpec", "new_era", "next_era", "verify_membership",
    "draw_turns", "max_fork_depth", "blocks_left", "PoolExhausted",
    "Stamp", "mine", "verify_stamp", "anchor_bytes", "equivocation_evidence",
    "MiningFailed",
    "NetworkHistory", "HardenedBlock", "HardeningError", "GENESIS",
    "hardened_from_row",
]
