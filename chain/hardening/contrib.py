"""Era 0 as a ceremony, not as a secret somebody had.

`Era` derives every leaf in the pool from one master seed. That is the right
shape for a test and the wrong shape for a launch, and the review says why
(A4): `max fork depth = attacker's unspent turns / width` is a *bound* rather
than a probability, so **a holder's share of the pool is its rewrite ceiling,
exactly**. One master seed means one party's ceiling is the whole chain's
history, and era n+1 is authorised by era n, so era 0 is the anchor for
everything after it. `hardening_design.md` has called the distribution "the
most important unanswered question" since part three.

A contributed era answers it the only way that survives someone looking at it
later. Each holder generates the keys for its own slice of the pool from its own
secret, publishes the public leaves, and signs a claim to exactly that slice
with the key the genesis document names it by. The era root is the Merkle root
over everybody's leaves in index order, so:

  * no party can sign a turn outside its own slice — it does not have the
    material, and the leaf it would have to match is somebody else's public key;
  * the map from turns to holders is *attested*, by the same keys that ratify
    the document, inside the bytes the chain id is the hash of;
  * and the concentration is visible before launch rather than inferred after a
    rewrite.

What it still cannot do is prove two holders are not the same operator. Nothing
cryptographic can; it is an identity question, and the honest thing is to make
the claim explicit and signed so the assumption has a name attached to it.

The public seed is a randomiser, not a secret: it is derived from the network
and the document's first seed so that it is nobody's choice either.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import wots
from .pool import EraSpec, _h, _node, _retired


class ContributionError(Exception):
    """A slice that is not a slice, or a set of them that is not an era."""


def pub_seed_for(network: str, first_seed: str, era_id: int = 0) -> bytes:
    """Public randomiser, derived rather than chosen."""
    return _h(b"fin6-pubseed-contributed", network.encode(),
              first_seed.encode(), str(era_id).encode())


def deal(holders, turns: int) -> list:
    """Contiguous slices, as even as the arithmetic allows.

    Contiguous rather than striped because a slice is what a holder publishes
    and signs, and `(first, count)` is a claim a reader can check in one line.
    It costs nothing in committee diversity: `draw_turns` is uniform over the
    whole pool, so a holder's expected share of any committee is its share of
    the turns however the indices are arranged.
    """
    holders = list(holders)
    if not holders:
        raise ContributionError("an era needs at least one holder")
    if turns < len(holders):
        raise ContributionError(
            f"{turns} turns cannot be dealt to {len(holders)} holders")
    base, extra = divmod(turns, len(holders))
    out, first = [], 0
    for i, holder in enumerate(holders):
        count = base + (1 if i < extra else 0)
        out.append((holder, first, count))
        first += count
    return out


@dataclass(frozen=True)
class Contribution:
    """One holder's public commitment to its own slice of the pool."""
    holder: str
    first: int
    count: int
    digest: str                 # over the holder's leaves, in index order
    signature: str = ""         # by the holder's roster key, over `message`

    def as_tuple(self):
        return (self.holder, self.first, self.count, self.digest,
                self.signature)

    @staticmethod
    def message(network: str, holder: str, first: int, count: int,
                digest: str, root: str, scheme: str) -> bytes:
        """What a holder signs: this slice, in this era, in this scheme.

        The era root is in it, so a holder is not attesting to its own slice in
        isolation — it is attesting to the pool that slice is part of. That
        makes the ceremony two rounds (publish, then sign), which is the
        correct number: a holder that signed before seeing the others would be
        vouching for an era nobody had assembled yet.
        """
        return _h(b"fin6-turn-claim", network.encode(), holder.encode(),
                  str(first).encode(), str(count).encode(), digest.encode(),
                  root.encode(), scheme.encode())


def leaf_digest(leaves) -> str:
    """One holder's leaves as one value, order-sensitive."""
    return _h(b"fin6-turn-block", str(len(leaves)).encode(), *leaves).hex()


@dataclass(frozen=True)
class HolderSlice:
    """The operator side of one contribution. Holds a secret, and only its own.

    The seed never leaves the holder. Everything else here is publishable, and
    publishing it is the ceremony.
    """
    holder: str
    first: int
    count: int
    seed: bytes
    pub_seed: bytes

    def owns(self, index: int) -> bool:
        return self.first <= index < self.first + self.count

    def leaves(self) -> list:
        return [wots.public_key(self.seed, self.pub_seed, i)
                for i in range(self.first, self.first + self.count)]

    def contribution(self) -> Contribution:
        return Contribution(self.holder, self.first, self.count,
                            leaf_digest(self.leaves()))

    def sign_turn(self, index: int, message: bytes) -> bytes:
        if not self.owns(index):
            raise ContributionError(
                f"{self.holder} holds turns {self.first}–"
                f"{self.first + self.count - 1}, not {index}")
        return wots.sign(self.seed, self.pub_seed, index, message)


class ContributedEra:
    """An era assembled from published leaves.

    A verifier builds one of these with no secrets at all — which is the
    difference from `Era`, where holding the object means being able to spend
    every turn in the pool. Signing needs a `HolderSlice`, and a holder only
    has its own.
    """

    def __init__(self, era_id: int, pub_seed: bytes, tree_height: int,
                 turns: int, leaves, slices=(), scheme: str = wots.SCHEME):
        if len(leaves) != turns:
            raise ContributionError(
                f"{len(leaves)} leaves for {turns} turns")
        if turns > (1 << tree_height):
            raise ContributionError(
                f"{turns} turns will not fit in 2^{tree_height} leaves")
        self.era_id = era_id
        self.pub_seed = pub_seed
        self.tree_height = tree_height
        self.turns = turns
        self.scheme = scheme
        self._slices = {s.holder: s for s in slices}
        self._leaves = list(leaves)
        self._levels = self._build()

    def _build(self):
        level = list(self._leaves) + [
            _retired(self.era_id, i)
            for i in range(self.turns, 1 << self.tree_height)]
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
                       turns=self.turns, pub_seed=self.pub_seed,
                       root=self.root, scheme=self.scheme)

    def leaf_pk(self, index: int) -> bytes:
        return self._levels[0][index]

    def auth_path(self, index: int) -> tuple:
        path, i = [], index
        for level in self._levels[:-1]:
            path.append(level[i ^ 1])
            i >>= 1
        return tuple(path)

    def sign(self, index: int, message: bytes) -> bytes:
        """Spend a turn — only possible for a slice this process holds."""
        if index >= self.turns:
            raise ContributionError(f"turn {index} is retired")
        for s in self._slices.values():
            if s.owns(index):
                return s.sign_turn(index, message)
        raise ContributionError(
            f"turn {index} belongs to another holder; this process holds "
            f"{sorted(self._slices) or 'nothing'}")

    def __repr__(self):
        return (f"ContributedEra(#{self.era_id}, {self.turns:,} turns from "
                f"{len(self._slices)} local slice(s), "
                f"root={self.root.hex()[:12]}…)")


# ── assembling one ───────────────────────────────────────────────────────────

def slices_for(holders, turns: int, pub_seed: bytes, seed_of) -> list:
    """Operator-side slices for a whole pool. `seed_of(holder) -> bytes`.

    Used by the simulation and by tests, where one process legitimately stands
    in for every holder. A real ceremony runs this once per machine, with one
    holder each, and the seeds never meet.
    """
    return [HolderSlice(holder, first, count, seed_of(holder), pub_seed)
            for holder, first, count in deal(holders, turns)]


def assemble(era_id: int, pub_seed: bytes, tree_height: int, turns: int,
             slices) -> ContributedEra:
    slices = sorted(slices, key=lambda s: s.first)
    check_coverage([s.contribution() for s in slices], turns)
    leaves = [leaf for s in slices for leaf in s.leaves()]
    return ContributedEra(era_id, pub_seed, tree_height, turns, leaves,
                          slices=slices)


def check_coverage(contributions, turns: int):
    """Every turn claimed exactly once, in order. Raises on anything else."""
    at = 0
    for c in sorted(contributions, key=lambda c: c.first):
        if c.count < 1:
            raise ContributionError(f"{c.holder} claims {c.count} turns")
        if c.first != at:
            raise ContributionError(
                f"turns {at}–{c.first - 1} are claimed by nobody"
                if c.first > at else
                f"{c.holder}'s slice overlaps the one before it")
        at += c.count
    if at != turns:
        raise ContributionError(f"the slices cover {at} turns, the era has "
                                f"{turns}")


def shares(contributions, turns: int) -> dict:
    """holder -> fraction of the pool. Summed per holder, so a holder that
    contributed twice is counted once — which is the number that matters."""
    out = {}
    for c in contributions:
        out[c.holder] = out.get(c.holder, 0) + c.count / turns
    return out
