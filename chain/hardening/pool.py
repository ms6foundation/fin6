"""The era — a finite population of single-use turns.

70,000 turns live in a Merkle tree of one-time keys.  A turn proves it belongs by
opening its leaf to the era root, and spends itself by signing once.  The pool is
the hardening budget: it is consumed, not rented, which is the whole reason a
failed attack here is permanently disarming.

Leaves beyond `turns` are retired constants rather than keys, so a 2^17 tree
carrying 70,000 turns costs 70,000 key generations rather than 131,072.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import wots


def _h(tag: bytes, *parts: bytes) -> bytes:
    d = hashlib.sha256()
    d.update(len(tag).to_bytes(4, "big"))
    d.update(tag)
    for p in parts:
        d.update(len(p).to_bytes(4, "big"))
        d.update(p)
    return d.digest()


def _node(left: bytes, right: bytes) -> bytes:
    return _h(b"fin6-merkle-node", left, right)


def _retired(era_id: int, index: int) -> bytes:
    """A leaf that is never a turn: present in the tree, unopenable."""
    return _h(b"fin6-retired", str(era_id).encode(), str(index).encode())


@dataclass(frozen=True)
class EraSpec:
    """Everything a verifier needs.  Carries no secret."""
    era_id: int
    tree_height: int
    turns: int
    pub_seed: bytes
    root: bytes

    @property
    def leaves(self) -> int:
        return 1 << self.tree_height

    def digest(self) -> str:
        return _h(b"fin6-era", str(self.era_id).encode(),
                  str(self.tree_height).encode(), str(self.turns).encode(),
                  self.pub_seed, self.root).hex()

    def __repr__(self):
        return (f"EraSpec(#{self.era_id}, {self.turns:,} turns of "
                f"{self.leaves:,} leaves, root={self.root.hex()[:12]}…)")


class Era:
    """The operator side: holds the master seed, so it can spend turns.

    In a deployment the seed is not one secret in one place — each operator holds
    the seed material for its own slice of the pool, and `holder_of` is the map
    that decides whether a committee of 32 is 32 independent witnesses or three.
    That distribution is the security parameter, so it is modelled explicitly
    rather than assumed.
    """

    def __init__(self, era_id: int, master_seed: bytes, tree_height: int,
                 turns: int, holders=None):
        if turns > (1 << tree_height):
            raise ValueError(f"{turns} turns will not fit in 2^{tree_height} leaves")
        self.era_id = era_id
        self.master_seed = master_seed
        self.tree_height = tree_height
        self.turns = turns
        self.pub_seed = _h(b"fin6-pubseed", master_seed, str(era_id).encode())
        self._holders = list(holders) if holders else ["pool"]
        self._levels = self._build()

    # ── the tree ─────────────────────────────────────────────────────────────

    def _leaf(self, index: int) -> bytes:
        if index >= self.turns:
            return _retired(self.era_id, index)
        return wots.public_key(self.master_seed, self.pub_seed, index)

    def _build(self):
        level = [self._leaf(i) for i in range(1 << self.tree_height)]
        levels = [level]
        while len(level) > 1:
            level = [_node(level[i], level[i + 1])
                     for i in range(0, len(level), 2)]
            levels.append(level)
        return levels

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    @property
    def spec(self) -> EraSpec:
        return EraSpec(era_id=self.era_id, tree_height=self.tree_height,
                       turns=self.turns, pub_seed=self.pub_seed, root=self.root)

    def leaf_pk(self, index: int) -> bytes:
        return self._levels[0][index]

    def auth_path(self, index: int) -> tuple:
        path, i = [], index
        for level in self._levels[:-1]:
            path.append(level[i ^ 1])
            i >>= 1
        return tuple(path)

    # ── spending ─────────────────────────────────────────────────────────────

    def sign(self, index: int, message: bytes) -> bytes:
        """Spend turn `index`.  Calling this twice with different messages is
        what leaks the key — the caller is responsible for never doing it, and
        the network is what catches it if they do."""
        if index >= self.turns:
            raise ValueError(f"turn {index} is retired, not in circulation")
        return wots.sign(self.master_seed, self.pub_seed, index, message)

    # ── distribution ─────────────────────────────────────────────────────────

    def holder_of(self, index: int) -> str:
        return self._holders[index % len(self._holders)]

    def turns_held_by(self, holder: str) -> int:
        n = len(self._holders)
        try:
            offset = self._holders.index(holder)
        except ValueError:
            return 0
        return len(range(offset, self.turns, n))

    def __repr__(self):
        return (f"Era(#{self.era_id}, {self.turns:,} turns, "
                f"{len(self._holders)} holders, root={self.root.hex()[:12]}…)")


# ═══════════════════════════════════════════════════════════════════════════════
# Verification side
# ═══════════════════════════════════════════════════════════════════════════════

def merkle_root_from_path(index: int, leaf: bytes, auth_path) -> bytes:
    node, i = leaf, index
    for sibling in auth_path:
        node = _node(sibling, node) if i & 1 else _node(node, sibling)
        i >>= 1
    return node


def verify_membership(spec: EraSpec, index: int, leaf: bytes, auth_path) -> bool:
    if not 0 <= index < spec.leaves or len(auth_path) != spec.tree_height:
        return False
    return merkle_root_from_path(index, leaf, auth_path) == spec.root


def new_era(era_id: int, master_seed: bytes, tree_height: int, turns: int,
            holders=None) -> Era:
    return Era(era_id, master_seed, tree_height, turns, holders=holders)


def next_era(previous: EraSpec, master_seed: bytes, holders=None) -> Era:
    """Roll over.  The new root is published in a block hardened by the outgoing
    era, so eras chain and provenance never rests on an announcement."""
    return Era(previous.era_id + 1,
               _h(b"fin6-era-seed", master_seed, previous.root),
               previous.tree_height, previous.turns, holders=holders)
