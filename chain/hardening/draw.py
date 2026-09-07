"""Which turns stamp a block, and why nobody gets to choose.

The committee for height h is derived from the *previous hardened block*, not
from h.  Seeding from h would let whoever assembles it grind until the draw
landed on turns they control; seeding from the previous block costs one block of
foreknowledge and removes grinding entirely.

A drawn turn is consumed whether or not it stamps.  Otherwise an attacker could
stall selectively until a committee it owned came up — consuming on draw means
denial cannot steer the selection, only burn the pool faster.
"""
from __future__ import annotations

import hashlib

from .pool import EraSpec


class PoolExhausted(Exception):
    """The era is out of unspent turns; roll over."""


def _seed(prev_hash: str, height: int, root: bytes) -> bytes:
    d = hashlib.sha256()
    d.update(b"fin6-draw")
    d.update(prev_hash.encode())
    d.update(height.to_bytes(8, "big"))
    d.update(root)
    return d.digest()


def draw_turns(spec: EraSpec, spent, height: int, prev_hash: str,
               width: int) -> list:
    """The `width` turns that may stamp this block, in draw order."""
    seed = _seed(prev_hash, height, spec.root)
    chosen, seen = [], set()
    probe = 0
    limit = 64 * (width + 1) + 4 * spec.turns
    while len(chosen) < width:
        if probe > limit:
            raise PoolExhausted(
                f"could not draw {width} unspent turns at height {height}: "
                f"{len(spent)}/{spec.turns} already spent")
        idx = int.from_bytes(
            hashlib.sha256(seed + probe.to_bytes(4, "big")).digest(), "big"
        ) % spec.turns
        probe += 1
        if idx in seen or idx in spent:
            continue
        seen.add(idx)
        chosen.append(idx)
    return chosen


def remaining(spec: EraSpec, spent) -> int:
    return spec.turns - len(spent)


def blocks_left(spec: EraSpec, spent, width: int) -> int:
    return remaining(spec, spent) // max(1, width)


def max_fork_depth(unspent_held: int, width: int) -> int:
    """The ceiling on a rewrite.

    An attacker can only stamp with turns it owns and has not spent, so the
    deepest branch it can ever build is that many turns divided by the width.
    Not a probability — a bound, after which it has nothing left.
    """
    return unspent_held // max(1, width)
