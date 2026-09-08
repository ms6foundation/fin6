"""Hardening parameters.

The finite pool couples two things that are independent in Bitcoin: spending
`width` turns per block against 70,000 fixes the era at 70,000/width blocks, so
choosing an era duration fixes the block interval.

    block_interval = era_seconds * width / turns

At two eras a day — era_seconds = 43,200 — and width 32, that is 2,187 blocks of
19.75 s each.  Wide hardening, fast blocks, long eras: pick two.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HardeningParams:
    name: str = "production"

    turns: int = 70_000            # the whole pool, spent once each
    era_seconds: int = 43_200      # 12 hours — two eras a day
    width: int = 32                # turns spent per block
    threshold_num: int = 2
    threshold_den: int = 3
    difficulty_bits: int = 20      # expected 2^bits hashes per stamp
    tree_height: int = 17          # 131,072 leaves covers 70,000 turns

    def __post_init__(self):
        if self.turns > (1 << self.tree_height):
            raise ValueError(
                f"{self.turns:,} turns need a tree taller than {self.tree_height}")
        if self.width < 1:
            raise ValueError("width must be at least 1")

    @property
    def blocks_per_era(self) -> int:
        return self.turns // self.width

    @property
    def block_interval(self) -> float:
        return self.era_seconds * self.width / self.turns

    @property
    def threshold(self) -> int:
        """Stamps needed before a block enters history."""
        return max(1, -(-(self.width * self.threshold_num) // self.threshold_den))

    @property
    def stamp_weight(self) -> int:
        return 1 << self.difficulty_bits

    def max_fork_depth(self, attacker_share: float) -> int:
        """The ceiling on a rewrite, from the attacker's share of the pool."""
        return int(self.turns * attacker_share) // self.width

    def summary(self) -> str:
        return (f"{self.name}: {self.turns:,} turns, width {self.width}, "
                f"threshold {self.threshold}, era {self.era_seconds / 3600:.0f} h "
                f"= {self.blocks_per_era:,} blocks of "
                f"{self.block_interval:.2f} s")


# Two eras a day, as specified.
PRODUCTION = HardeningParams()

# Ten-second blocks at the same era length, at half the hardening width.
FAST = HardeningParams(name="fast", width=16)

# Sized for a laptop.  Production's 2^17-leaf era tree costs 0.89 ms a leaf to
# build — 117 s per node at boot and again at every rollover — which is not a
# testnet, it is a coffee break.  This builds in 0.91 s, gives 5-second blocks
# and a rollover every ten minutes, and puts the rewrite ceiling at 35 blocks
# for an adversary holding two sevenths of the pool: a three-minute experiment
# rather than a three-and-a-half-hour one.
LOCAL = HardeningParams(name="local", turns=1_000, era_seconds=625, width=8,
                        difficulty_bits=16, tree_height=10)

# Small enough to build a tree and mine in a test.
DEMO = HardeningParams(name="demo", turns=192, era_seconds=43_200, width=8,
                       difficulty_bits=10, tree_height=8)

PRESETS = {p.name: p for p in (PRODUCTION, FAST, LOCAL, DEMO)}
