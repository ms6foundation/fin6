"""A stamp — one turn, spent.

    anchor = H(block_hash, cumulative_weight(h-1), era_root)
    puzzle = H(anchor, leaf_index, nonce)  <  target
    stamp  = { leaf_index, nonce, auth_path, ots_signature over the puzzle }

The signature covers the puzzle output, so it commits to the anchor and the
nonce together: a turn cannot move its work to another block, and stamping two
blocks means signing two messages with one one-time key, which leaks it.

Verification does membership and signature in a single step.  The public key is
*recovered* from the signature and then opened against the era root — so a bad
signature recovers a key that is simply not in the tree, and there is no separate
check to forget.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import wots
from .pool import EraSpec, verify_membership


class MiningFailed(Exception):
    """No nonce found inside the budget."""


def anchor_bytes(block_hash: str, cumulative_weight: int, era_root: bytes) -> bytes:
    d = hashlib.sha256()
    d.update(b"fin6-anchor")
    d.update(block_hash.encode())
    d.update(cumulative_weight.to_bytes(16, "big"))
    d.update(era_root)
    return d.digest()


def target_for(bits: int) -> int:
    if not 0 <= bits < 256:
        raise ValueError("difficulty must be in [0, 256)")
    return 1 << (256 - bits)


def puzzle_hash(anchor: bytes, leaf_index: int, nonce: int) -> bytes:
    d = hashlib.sha256()
    d.update(b"fin6-puzzle")
    d.update(anchor)
    d.update(leaf_index.to_bytes(4, "big"))
    d.update(nonce.to_bytes(8, "big"))
    return d.digest()


def meets(digest: bytes, bits: int) -> bool:
    return int.from_bytes(digest, "big") < target_for(bits)


@dataclass(frozen=True)
class Stamp:
    leaf_index: int
    nonce: int
    auth_path: tuple
    signature: bytes

    def digest(self) -> str:
        d = hashlib.sha256()
        d.update(b"fin6-stamp")
        d.update(self.leaf_index.to_bytes(4, "big"))
        d.update(self.nonce.to_bytes(8, "big"))
        d.update(self.signature)
        for node in self.auth_path:
            d.update(node)
        return d.hexdigest()

    def size(self) -> int:
        return len(self.signature) + 32 * len(self.auth_path) + 12

    def __repr__(self):
        return f"Stamp(turn {self.leaf_index}, nonce {self.nonce})"


def mine(era, leaf_index: int, anchor: bytes, bits: int,
         max_tries: int = 1 << 26) -> Stamp:
    """Do the work, then spend the turn on the result."""
    nonce = 0
    while nonce < max_tries:
        ph = puzzle_hash(anchor, leaf_index, nonce)
        if meets(ph, bits):
            return Stamp(leaf_index=leaf_index, nonce=nonce,
                         auth_path=era.auth_path(leaf_index),
                         signature=era.sign(leaf_index, ph))
        nonce += 1
    raise MiningFailed(f"no nonce for turn {leaf_index} at {bits} bits "
                       f"in {max_tries} tries")


def verify_stamp(spec: EraSpec, stamp: Stamp, anchor: bytes, bits: int):
    """(ok, reason).  Never raises."""
    try:
        if not 0 <= stamp.leaf_index < spec.turns:
            return False, f"turn {stamp.leaf_index} is not in circulation"
        ph = puzzle_hash(anchor, stamp.leaf_index, stamp.nonce)
        if not meets(ph, bits):
            return False, "puzzle not solved"
        recovered = wots.public_key_from_signature(
            stamp.signature, spec.pub_seed, stamp.leaf_index, ph)
        if not verify_membership(spec, stamp.leaf_index, recovered,
                                 stamp.auth_path):
            return False, "signature does not open to a turn in this era"
        return True, "ok"
    except Exception as exc:
        return False, f"malformed stamp: {exc.__class__.__name__}"


def equivocation_evidence(spec: EraSpec, a: Stamp, b: Stamp, anchor_a: bytes,
                          anchor_b: bytes, bits: int):
    """Two valid stamps from one turn on different anchors.

    Self-substantiating: anyone can check both, and the pair is proof that the
    one-time key has been used twice — which, for a Winternitz key, means it can
    now be forged with.  No reporter, no register, no future needed.
    """
    if a.leaf_index != b.leaf_index:
        return None
    if anchor_a == anchor_b:
        return None
    ok_a, _ = verify_stamp(spec, a, anchor_a, bits)
    ok_b, _ = verify_stamp(spec, b, anchor_b, bits)
    if ok_a and ok_b:
        return (a.leaf_index, a, b)
    return None
