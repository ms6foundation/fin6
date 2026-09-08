"""Network history — hardened blocks, spent turns, and fork choice.

A block leaves the supreme mempool agreed but reversible.  It enters history when
enough turns have burned themselves on it, and it becomes harder to displace as
later blocks pile weight on top.  The fork-choice rule is Bitcoin's — greatest
cumulative weight — with one change that does most of the work:

    a branch that reuses a turn spent on its own history is invalid outright,

and turns are consumed per branch.  So an attacker cannot re-cast the turns the
honest chain already burned; it can only spend its own, which puts a hard ceiling
on how deep it can ever reach:

    max fork depth = (attacker's unspent turns) / width

That is a bound, not a probability, and the turns spent failing are gone — so
every failed attempt permanently shrinks the next one.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..seal import seal_root
from .draw import PoolExhausted, draw_turns, max_fork_depth
from .params import HardeningParams
from .pool import Era, EraSpec
from .stamp import MiningFailed, Stamp, anchor_bytes, mine, verify_stamp

GENESIS = "nb:genesis"


@dataclass(frozen=True)
class HardenedBlock:
    """One block, and the turns that burned themselves on it."""
    block_hash: str
    height: int
    prev_hash: str
    era_id: int
    drawn: tuple                    # every turn consumed, stamped or not
    stamps: tuple = ()
    weight: int = 0
    cumulative: int = 0
    spent_root: int = 0
    block: object = field(default=None, repr=False)

    def hash(self) -> str:
        return self.block_hash

    def stamped(self) -> tuple:
        return tuple(s.leaf_index for s in self.stamps)

    def bytes_of_stamps(self) -> int:
        return sum(s.size() for s in self.stamps)

    def __repr__(self):
        return (f"HardenedBlock(h={self.height}, {len(self.stamps)}/"
                f"{len(self.drawn)} stamped, weight={self.weight:,}, "
                f"cumulative={self.cumulative:,}, {self.block_hash[:13]}…)")


class HardeningError(Exception):
    pass


class NetworkHistory:
    """The hardened chain.  Holds every branch it has seen and picks the heaviest."""

    def __init__(self, spec: EraSpec, params: HardeningParams,
                 genesis: str = GENESIS):
        self.spec = spec
        self.params = params
        self.genesis = genesis
        self.blocks: dict = {}
        self.children: dict = {}
        self.tip_hash = genesis

    # ── branch walking ───────────────────────────────────────────────────────

    def _branch(self, block_hash: str):
        """From the given block back to genesis, newest first."""
        out, cur = [], block_hash
        while cur != self.genesis:
            hb = self.blocks.get(cur)
            if hb is None:
                break
            out.append(hb)
            cur = hb.prev_hash
        return out

    def spent_upto(self, block_hash: str) -> set:
        """Turns consumed on this branch — per branch, never global."""
        spent = set()
        for hb in self._branch(block_hash):
            spent.update(hb.drawn)
        return spent

    def cumulative_at(self, block_hash: str) -> int:
        if block_hash == self.genesis:
            return 0
        hb = self.blocks.get(block_hash)
        return hb.cumulative if hb else 0

    def height_at(self, block_hash: str) -> int:
        if block_hash == self.genesis:
            return 0
        hb = self.blocks.get(block_hash)
        return hb.height if hb else 0

    # ── producing ────────────────────────────────────────────────────────────

    def harden(self, block, era: Era, prev_hash: str | None = None,
               participation: float = 1.0, absent=(), owned=None) -> HardenedBlock:
        """Draw the committee, mine the stamps, and assemble the hardened block.

        `absent` names drawn turns that do not answer.  They are consumed anyway
        — otherwise stalling could roll the draw forward until a friendly
        committee came up.

        `owned` restricts stamping to turns whose keys the caller actually holds.
        This is what an attacker faces: it does not choose the committee, so it
        can only stamp the drawn turns that happen to be its own.  With a
        threshold of two thirds, that means it needs two thirds of the whole pool
        before it can harden even one block — a stronger bar than out-racing the
        honest chain on weight, and the reason the ceiling below is a second line
        of defence rather than the first.
        """
        prev_hash = self.tip_hash if prev_hash is None else prev_hash
        height = self.height_at(prev_hash) + 1
        spent = self.spent_upto(prev_hash)
        p = self.params

        drawn = draw_turns(self.spec, spent, height, prev_hash, p.width)
        anchor = anchor_bytes(block.hash(), height, self.spec.root)

        absent = set(absent)
        if participation < 1.0:
            keep = max(0, int(round(len(drawn) * participation)))
            absent |= set(drawn[keep:])

        stamps = []
        for idx in drawn:
            if idx in absent:
                continue
            if owned is not None and idx not in owned:
                continue        # cannot stamp a turn whose key it does not hold
            try:
                stamps.append(mine(era, idx, anchor, p.difficulty_bits))
            except MiningFailed:
                continue

        weight = len(stamps) * p.stamp_weight
        return HardenedBlock(
            block_hash=block.hash(), height=height, prev_hash=prev_hash,
            era_id=self.spec.era_id, drawn=tuple(drawn), stamps=tuple(stamps),
            weight=weight, cumulative=self.cumulative_at(prev_hash) + weight,
            spent_root=seal_root("turns", sorted(spent | set(drawn))),
            block=block)

    def assemble(self, block, stamps, prev_hash: str | None = None):
        """Build a hardened block from stamps that came from several places.

        `harden` mines and assembles in one step, which is right for one
        operator holding the whole pool and wrong for a network where each node
        can only stamp its own turns.  On a network the stamps arrive
        separately and somebody has to put them together; this does that, and
        `check` then verifies the result exactly as if it had been mined here.

        Stamps that are not on the draw, or that repeat a turn, are dropped
        rather than refused — the assembler is combining what it was sent, and
        a peer sending rubbish should cost the block nothing.
        """
        prev_hash = self.tip_hash if prev_hash is None else prev_hash
        height = self.height_at(prev_hash) + 1
        spent = self.spent_upto(prev_hash)
        drawn = draw_turns(self.spec, spent, height, prev_hash,
                           self.params.width)
        allowed, seen, keep = set(drawn), set(), []
        for stamp in sorted(stamps, key=lambda s: s.leaf_index):
            if stamp.leaf_index in allowed and stamp.leaf_index not in seen:
                seen.add(stamp.leaf_index)
                keep.append(stamp)
        weight = len(keep) * self.params.stamp_weight
        return HardenedBlock(
            block_hash=block.hash() if hasattr(block, "hash") else str(block),
            height=height, prev_hash=prev_hash, era_id=self.spec.era_id,
            drawn=tuple(drawn), stamps=tuple(keep), weight=weight,
            cumulative=self.cumulative_at(prev_hash) + weight,
            spent_root=seal_root("turns", sorted(spent | set(drawn))),
            block=block if hasattr(block, "hash") else None)

    def drawn_for(self, block_hash: str, prev_hash: str | None = None):
        """Which turns this block's committee is — deterministic, so a node can
        know what to expect before any stamp arrives."""
        prev_hash = self.tip_hash if prev_hash is None else prev_hash
        height = self.height_at(prev_hash) + 1
        spent = self.spent_upto(prev_hash)
        return draw_turns(self.spec, spent, height, prev_hash,
                          self.params.width)

    def anchor_for(self, block_hash: str, prev_hash: str | None = None):
        prev_hash = self.tip_hash if prev_hash is None else prev_hash
        return anchor_bytes(block_hash, self.height_at(prev_hash) + 1,
                            self.spec.root)

    # ── accepting ────────────────────────────────────────────────────────────

    def check(self, hb: HardenedBlock):
        """(ok, reason).  Everything a third party can verify for itself."""
        p = self.params
        if hb.era_id != self.spec.era_id:
            return False, f"block is hardened under era {hb.era_id}"
        if hb.prev_hash != self.genesis and hb.prev_hash not in self.blocks:
            return False, f"prev block {hb.prev_hash[:13]}… is unknown"
        if hb.height != self.height_at(hb.prev_hash) + 1:
            return False, f"height {hb.height} does not follow its parent"

        spent = self.spent_upto(hb.prev_hash)
        expected = draw_turns(self.spec, spent, hb.height, hb.prev_hash, p.width)
        if tuple(expected) != tuple(hb.drawn):
            return False, "the committee is not the one the draw produces"

        for idx in hb.drawn:
            if idx in spent:
                return False, f"turn {idx} was already spent on this branch"

        anchor = anchor_bytes(hb.block_hash, hb.height, self.spec.root)
        seen = set()
        for stamp in hb.stamps:
            if stamp.leaf_index in seen:
                return False, f"turn {stamp.leaf_index} stamped twice"
            if stamp.leaf_index not in set(hb.drawn):
                return False, f"turn {stamp.leaf_index} was not drawn"
            ok, why = verify_stamp(self.spec, stamp, anchor, p.difficulty_bits)
            if not ok:
                return False, f"turn {stamp.leaf_index}: {why}"
            seen.add(stamp.leaf_index)

        if len(seen) < p.threshold:
            return False, (f"{len(seen)} stamps, threshold is {p.threshold}")
        if hb.weight != len(seen) * p.stamp_weight:
            return False, "weight does not match the stamps"
        if hb.cumulative != self.cumulative_at(hb.prev_hash) + hb.weight:
            return False, "cumulative weight does not follow its parent"
        if hb.spent_root != seal_root("turns", sorted(spent | set(hb.drawn))):
            return False, "spent-turn root does not match"
        return True, "ok"

    def accept(self, hb: HardenedBlock):
        ok, why = self.check(hb)
        if not ok:
            return False, why
        self.blocks[hb.block_hash] = hb
        self.children.setdefault(hb.prev_hash, []).append(hb.block_hash)
        self._retip()
        return True, "ok"

    # ── fork choice ──────────────────────────────────────────────────────────

    def _retip(self):
        best, best_w = self.genesis, 0
        for h, hb in self.blocks.items():
            if hb.cumulative > best_w or (hb.cumulative == best_w and h < best):
                best, best_w = h, hb.cumulative
        self.tip_hash = best

    @property
    def tip(self):
        return self.blocks.get(self.tip_hash)

    @property
    def cumulative_weight(self) -> int:
        return self.cumulative_at(self.tip_hash)

    @property
    def height(self) -> int:
        return self.height_at(self.tip_hash)

    def canonical(self):
        return list(reversed(self._branch(self.tip_hash)))

    def confirmations(self, block_hash: str) -> int:
        if block_hash not in self.blocks:
            return 0
        return self.height - self.blocks[block_hash].height + 1

    # ── the ceiling ──────────────────────────────────────────────────────────

    def remaining_turns(self) -> int:
        return self.spec.turns - len(self.spent_upto(self.tip_hash))

    def rewrite_ceiling(self, attacker_turns: int) -> int:
        """How deep an attacker holding this many unspent turns could ever reach."""
        return max_fork_depth(attacker_turns, self.params.width)

    def blocks_left_in_era(self) -> int:
        return self.remaining_turns() // self.params.width

    def __repr__(self):
        return (f"NetworkHistory(era {self.spec.era_id}, height {self.height}, "
                f"weight {self.cumulative_weight:,}, "
                f"{self.remaining_turns():,} turns left)")
