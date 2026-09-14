"""How deep a rewrite this node will follow, and what it does past that.

Review C3. Undo records stop at the rewrite ceiling — 729 blocks at a third of
the pool under the shipped parameters — and past that a node that cannot roll
back diverges permanently from one that can, with no reconciliation path but a
snapshot. The divergence was silent, which is the part that matters:
divergence that announces itself is an incident, and divergence that does not
is two networks that each believe they are the network.

The bound is arithmetic, not policy. `max fork depth = attacker's unspent
turns / width`, so a branch deeper than the ceiling is not one an adversary
inside the assumption could have built. Meeting one means the assumption is
wrong — a pool more concentrated than the era-0 ceremony claims, or turns
compromised — and the honest response is to stop and say what would reconcile
it, rather than to pick the heavier side and carry on.
"""
import dataclasses

from ..hardening.history import (DEFAULT_SHARE, GENESIS, NetworkHistory,
                                 ReorgBeyondCeiling)
from ..hardening.params import ASSUMED_ATTACKER_SHARE, DEMO, PRODUCTION
from ..hardening.pool import Era
from ..store.undo import retention_depth
from .test_hardening import FakeBlock, era_and_history


def _chain(hist, era, tags, prev_hash=None):
    """Harden a run of blocks, returning the last hash."""
    last = prev_hash
    for tag in tags:
        hb = hist.harden(FakeBlock(tag), era, prev_hash=last)
        ok, why = hist.accept(hb)
        assert ok, (tag, why)
        last = hb.block_hash
    return last


# ── one number, in one place ─────────────────────────────────────────────────

def _production_history():
    """Production *parameters* over a demo era's spec.

    The spec is only an identity here — what is being tested is the ceiling,
    which comes from the parameters — and building a real 70,000-turn era costs
    a minute of WOTS key generation per test.
    """
    era, _ = era_and_history()
    return NetworkHistory(era.spec, PRODUCTION)


def test_storage_and_fork_choice_agree_about_what_is_reversible():
    """The bug this closes is not a deep reorg — it is keeping undo records for
    one depth and following forks to another."""
    assert _production_history().reorg_limit == retention_depth(PRODUCTION) \
        == 729
    assert DEFAULT_SHARE == ASSUMED_ATTACKER_SHARE == 1 / 3


def test_the_ceiling_is_the_pools_arithmetic_and_not_a_setting():
    assert _production_history().reorg_limit == PRODUCTION.max_fork_depth(1 / 3)
    assert PRODUCTION.max_fork_depth(1 / 3) == 70_000 // 3 // 32


# ── measuring a reorg ────────────────────────────────────────────────────────

def test_extending_the_tip_is_not_a_reorg():
    era, hist = era_and_history()
    tip = _chain(hist, era, ["a1", "a2", "a3"])
    assert hist.reorg_depth(tip) == 0
    assert hist.tip_hash == tip


def test_the_depth_is_measured_from_the_common_ancestor():
    era, hist = era_and_history()
    fork = _chain(hist, era, ["a1"])
    _chain(hist, era, ["a2", "a3"], prev_hash=fork)
    # A branch from a1 replaces two blocks, whether or not it wins.
    rival = hist.harden(FakeBlock("z2"), era, prev_hash=fork)
    hist.accept(rival)
    assert hist.reorg_depth(rival.block_hash) == 2
    assert hist.common_ancestor(hist.tip_hash, rival.block_hash) == fork


def test_two_branches_that_share_nothing_fork_at_genesis():
    era, hist = era_and_history()
    _chain(hist, era, ["a1", "a2"])
    rival = hist.harden(FakeBlock("z1"), era, prev_hash=GENESIS)
    hist.accept(rival)
    assert hist.common_ancestor(hist.tip_hash, rival.block_hash) == GENESIS
    assert hist.reorg_depth(rival.block_hash) == 2


# ── inside the ceiling, fork choice is unchanged ─────────────────────────────

def test_a_heavier_branch_inside_the_ceiling_is_followed_as_before():
    era, hist = era_and_history()
    fork = _chain(hist, era, ["a1"])
    _chain(hist, era, ["a2", "a3"], prev_hash=fork)
    first = hist.tip_hash
    rival = _chain(hist, era, ["z2", "z3", "z4"], prev_hash=fork)
    assert hist.tip_hash == rival != first, "the heaviest branch still wins"
    assert hist.halt is None


# ── past it, the node stops ──────────────────────────────────────────────────

def _shallow():
    """A history whose ceiling is two blocks, so a deep reorg is cheap to
    stage. Nothing about the rule depends on the number."""
    era = Era(0, b"seed", tree_height=DEMO.tree_height, turns=DEMO.turns)
    return era, NetworkHistory(era.spec, DEMO, reorg_limit=2)


def test_a_branch_past_the_ceiling_is_not_followed():
    era, hist = _shallow()
    _chain(hist, era, ["a1", "a2", "a3", "a4"])
    honest = hist.tip_hash
    rival = hist.harden(FakeBlock("z1"), era, prev_hash=GENESIS, owned=set(
        range(DEMO.turns)))
    for tag in ("z2", "z3", "z4", "z5", "z6"):
        ok, why = hist.accept(rival)
        rival = hist.harden(FakeBlock(tag), era, prev_hash=rival.block_hash,
                            owned=set(range(DEMO.turns)))
    hist.accept(rival)
    assert hist.tip_hash == honest, "the node did not follow it"
    assert hist.halt is not None


def test_the_halt_says_what_happened_and_what_would_fix_it():
    era, hist = _shallow()
    _chain(hist, era, ["a1", "a2", "a3", "a4"])
    deep = hist.harden(FakeBlock("z1"), era, prev_hash=GENESIS,
                       owned=set(range(DEMO.turns)))
    hist.accept(deep)
    for tag in ("z2", "z3", "z4", "z5", "z6", "z7"):
        nxt = hist.harden(FakeBlock(tag), era, prev_hash=deep.block_hash,
                          owned=set(range(DEMO.turns)))
        hist.accept(nxt)
        deep = nxt
    halt = hist.halt
    assert isinstance(halt, ReorgBeyondCeiling)
    assert halt.depth > halt.limit
    said = str(halt)
    assert "rewrite ceiling" in said
    assert "snapshot" in said, "an operator needs the reconciliation path"
    assert halt.fork_hash and halt.fork_height >= 0


def test_the_block_is_kept_because_it_is_the_evidence():
    """A stopped node with nothing to look at is a worse outcome than a
    stopped node holding the branch that stopped it."""
    era, hist = _shallow()
    _chain(hist, era, ["a1", "a2", "a3", "a4"])
    deep = hist.harden(FakeBlock("z1"), era, prev_hash=GENESIS,
                       owned=set(range(DEMO.turns)))
    hist.accept(deep)
    for tag in ("z2", "z3", "z4", "z5", "z6", "z7"):
        nxt = hist.harden(FakeBlock(tag), era, prev_hash=deep.block_hash,
                          owned=set(range(DEMO.turns)))
        ok, why = hist.accept(nxt)
        deep = nxt
    assert hist.halt is not None
    assert deep.block_hash in hist.blocks
    assert not ok and "rewrite ceiling" in why


def test_a_deep_branch_that_never_wins_does_not_stop_anything():
    """The check is on being *followed*, not on arriving. A losing branch can
    fork as deep as it likes: nobody has to undo anything for it."""
    era, hist = _shallow()
    _chain(hist, era, ["a1", "a2", "a3", "a4", "a5", "a6"])
    loser = hist.harden(FakeBlock("z1"), era, prev_hash=GENESIS)
    ok, why = hist.accept(loser)
    assert ok, why
    assert hist.halt is None
    assert hist.reorg_depth(loser.block_hash) == 6 > hist.reorg_limit
