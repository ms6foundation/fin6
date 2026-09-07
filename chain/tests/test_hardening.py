"""Phase H — hardening an agreed block into network history."""
import hashlib
import random
from dataclasses import replace

from ..hardening import wots
from ..hardening.draw import PoolExhausted, draw_turns, max_fork_depth
from ..hardening.history import GENESIS, NetworkHistory
from ..hardening.params import DEMO, FAST, PRODUCTION, HardeningParams
from ..hardening.pool import Era, next_era, verify_membership
from ..hardening.stamp import (Stamp, anchor_bytes, equivocation_evidence,
                               meets, mine, puzzle_hash, verify_stamp)


class FakeBlock:
    def __init__(self, tag):
        self.tag = tag

    def hash(self):
        return f"nb:{self.tag}"


def era_and_history(params=DEMO, seed=b"seed"):
    era = Era(0, seed, tree_height=params.tree_height, turns=params.turns)
    return era, NetworkHistory(era.spec, params)


# ── parameters: two eras a day ───────────────────────────────────────────────

def test_the_era_is_twelve_hours():
    assert PRODUCTION.era_seconds == 43_200
    assert 2 * PRODUCTION.era_seconds == 86_400, "two eras a day"


def test_the_pool_fixes_the_block_interval():
    """With a finite pool, interval and era length are the same knob."""
    assert PRODUCTION.blocks_per_era == 70_000 // 32 == 2187
    assert abs(PRODUCTION.block_interval - 19.75) < 0.01
    # halving the width halves the interval and doubles the blocks per era
    assert abs(FAST.block_interval - PRODUCTION.block_interval / 2) < 0.01
    assert FAST.blocks_per_era == 2 * PRODUCTION.blocks_per_era + 1


def test_threshold_and_weight():
    assert PRODUCTION.threshold == 22          # ceil(32 * 2/3)
    assert PRODUCTION.stamp_weight == 1 << 20


def test_a_pool_too_small_for_its_tree_is_refused():
    try:
        HardeningParams(name="bad", turns=1000, tree_height=8)
    except ValueError:
        return
    raise AssertionError("70,000 turns should not fit in 256 leaves")


# ── one-time signatures ──────────────────────────────────────────────────────

def test_wots_round_trip():
    ms, ps = b"m", b"p"
    msg = hashlib.sha256(b"x").digest()
    pk = wots.public_key(ms, ps, 3)
    assert wots.verify(wots.sign(ms, ps, 3, msg), ps, 3, msg, pk)


def test_wots_rejects_a_different_message_or_index():
    ms, ps = b"m", b"p"
    msg = hashlib.sha256(b"x").digest()
    pk, sig = wots.public_key(ms, ps, 3), wots.sign(ms, ps, 3, msg)
    assert not wots.verify(sig, ps, 3, hashlib.sha256(b"y").digest(), msg and pk)
    assert not wots.verify(sig, ps, 4, msg, pk)


def test_two_signatures_leak_more_of_the_key_than_one():
    """Why a turn is one-time.

    A Winternitz signature hands over each chain at the position its digit names,
    and anyone can walk a chain *forward*.  So a signature lets a forger sign any
    message whose digits are all at least as large.  A second signature under the
    same key lowers that bar at every index to the minimum of the two, which is
    what "reuse leaks the key" means concretely.  Measured, not asserted by
    assumption.
    """
    ms, ps = b"m", b"p"
    d1 = wots._digits(hashlib.sha256(b"first").digest())
    d2 = wots._digits(hashlib.sha256(b"second").digest())
    rng = random.Random(11)
    one = two = 0
    for _ in range(200):
        target = wots._digits(hashlib.sha256(str(rng.random()).encode()).digest())
        one += sum(1 for t, a in zip(target, d1) if t >= a)
        two += sum(1 for t, a, b in zip(target, d1, d2) if t >= min(a, b))
    assert two > one, "a second signature must expose more of the key, not less"


# ── the era pool ─────────────────────────────────────────────────────────────

def test_membership_opens_to_the_era_root():
    era = Era(0, b"s", tree_height=6, turns=40)
    assert verify_membership(era.spec, 7, era.leaf_pk(7), era.auth_path(7))
    assert not verify_membership(era.spec, 8, era.leaf_pk(7), era.auth_path(7))


def test_retired_leaves_cannot_be_spent():
    era = Era(0, b"s", tree_height=6, turns=40)
    try:
        era.sign(50, b"x")
    except ValueError:
        return
    raise AssertionError("a retired leaf was spendable")


def test_the_root_is_deterministic():
    a = Era(0, b"s", tree_height=6, turns=40)
    b = Era(0, b"s", tree_height=6, turns=40)
    assert a.root == b.root
    assert Era(0, b"other", tree_height=6, turns=40).root != a.root


def test_rollover_produces_a_fresh_pool():
    era = Era(0, b"s", tree_height=6, turns=40)
    nxt = next_era(era.spec, b"s")
    assert nxt.era_id == 1 and nxt.root != era.root


def test_a_signature_recovers_the_leaf_it_belongs_to():
    """Verification is membership and signature in one step."""
    era = Era(0, b"s", tree_height=6, turns=40)
    msg = hashlib.sha256(b"anchor").digest()
    sig = era.sign(11, msg)
    good = wots.public_key_from_signature(sig, era.spec.pub_seed, 11, msg)
    assert verify_membership(era.spec, 11, good, era.auth_path(11))
    other = wots.public_key_from_signature(
        sig, era.spec.pub_seed, 11, hashlib.sha256(b"else").digest())
    assert not verify_membership(era.spec, 11, other, era.auth_path(11))


# ── the draw ─────────────────────────────────────────────────────────────────

def test_the_draw_is_deterministic_and_ungrindable():
    era = Era(0, b"s", tree_height=6, turns=40)
    a = draw_turns(era.spec, set(), 1, "nb:prev", 8)
    assert a == draw_turns(era.spec, set(), 1, "nb:prev", 8)
    assert a != draw_turns(era.spec, set(), 1, "nb:other", 8), \
        "a different previous block must redraw"
    assert a != draw_turns(era.spec, set(), 2, "nb:prev", 8)


def test_the_draw_skips_spent_turns():
    era = Era(0, b"s", tree_height=6, turns=40)
    first = draw_turns(era.spec, set(), 1, "nb:p", 8)
    second = draw_turns(era.spec, set(first), 1, "nb:p", 8)
    assert not set(first) & set(second)


def test_an_exhausted_pool_raises():
    era = Era(0, b"s", tree_height=6, turns=16)
    try:
        draw_turns(era.spec, set(range(15)), 1, "nb:p", 8)
    except PoolExhausted:
        return
    raise AssertionError("an exhausted pool should refuse to draw")


def test_the_ceiling_is_arithmetic():
    assert max_fork_depth(7_000, 32) == 218
    assert PRODUCTION.max_fork_depth(0.10) == 218


# ── stamps ───────────────────────────────────────────────────────────────────

def test_a_stamp_verifies_and_is_bound_to_its_anchor():
    era = Era(0, b"s", tree_height=6, turns=40)
    a = anchor_bytes("nb:a", 0, era.root)
    st = mine(era, 5, a, 10)
    assert verify_stamp(era.spec, st, a, 10)[0]
    assert not verify_stamp(era.spec, st, anchor_bytes("nb:b", 0, era.root), 10)[0]


def test_a_stamp_is_bound_to_its_nonce_and_difficulty():
    era = Era(0, b"s", tree_height=6, turns=40)
    a = anchor_bytes("nb:a", 0, era.root)
    st = mine(era, 5, a, 10)
    moved = Stamp(st.leaf_index, st.nonce + 1, st.auth_path, st.signature)
    assert not verify_stamp(era.spec, moved, a, 10)[0]
    assert not verify_stamp(era.spec, st, a, 30)[0], "harder target must reject"


def test_stamping_two_blocks_is_self_incriminating():
    era = Era(0, b"s", tree_height=6, turns=40)
    a1 = anchor_bytes("nb:a", 0, era.root)
    a2 = anchor_bytes("nb:b", 0, era.root)
    ev = equivocation_evidence(era.spec, mine(era, 5, a1, 10),
                               mine(era, 5, a2, 10), a1, a2, 10)
    assert ev is not None and ev[0] == 5
    st = mine(era, 5, a1, 10)
    assert equivocation_evidence(era.spec, st, st, a1, a1, 10) is None


# ── the hardened chain ───────────────────────────────────────────────────────

def test_blocks_enter_history_and_weight_accumulates():
    era, hist = era_and_history()
    prev = 0
    for i in range(4):
        ok, why = hist.accept(hist.harden(FakeBlock(f"b{i}"), era))
        assert ok, why
        assert hist.cumulative_weight > prev
        prev = hist.cumulative_weight
    assert hist.height == 4
    assert hist.confirmations("nb:b0") == 4


def test_turns_are_consumed_on_draw_even_when_they_do_not_stamp():
    era, hist = era_and_history()
    hb = hist.harden(FakeBlock("b0"), era, absent=[hist.harden(
        FakeBlock("b0"), era).drawn[0]])
    assert len(hb.stamps) < len(hb.drawn)
    assert hist.accept(hb)[0]
    assert len(hist.spent_upto(hist.tip_hash)) == len(hb.drawn), \
        "an absent turn must still be consumed, or stalling could steer the draw"


def test_below_threshold_is_refused():
    era, hist = era_and_history()
    hb = hist.harden(FakeBlock("b0"), era)
    thin = replace(hb, stamps=hb.stamps[:DEMO.threshold - 1],
                   weight=(DEMO.threshold - 1) * DEMO.stamp_weight)
    ok, why = hist.check(thin)
    assert not ok and "threshold" in why


def test_a_substituted_committee_is_refused():
    era, hist = era_and_history()
    hb = hist.harden(FakeBlock("b0"), era)
    ok, why = hist.check(replace(hb, drawn=tuple(reversed(hb.drawn))))
    assert not ok and "committee" in why


def test_inflated_weight_is_refused():
    era, hist = era_and_history()
    hb = hist.harden(FakeBlock("b0"), era)
    ok, why = hist.check(replace(hb, weight=hb.weight * 10))
    assert not ok and "weight" in why


def test_a_branch_cannot_reuse_its_own_spent_turns():
    era, hist = era_and_history()
    hist.accept(hist.harden(FakeBlock("b0"), era))
    hb = hist.harden(FakeBlock("b1"), era)
    stale = replace(hb, drawn=hist.blocks["nb:b0"].drawn)
    ok, why = hist.check(stale)
    assert not ok, "reusing a spent turn must be refused"


def test_fork_choice_follows_the_heaviest_branch():
    era, hist = era_and_history()
    hist.accept(hist.harden(FakeBlock("a1"), era))
    hist.accept(hist.harden(FakeBlock("a2"), era))
    assert hist.tip_hash == "nb:a2"
    # a competing branch from genesis, two blocks deep, cannot pass it while
    # it is only as heavy — three blocks does
    hist.accept(hist.harden(FakeBlock("z1"), era, prev_hash=GENESIS))
    assert hist.tip_hash == "nb:a2", "an equal-weight branch must not displace the tip"


# ── what an attacker faces ───────────────────────────────────────────────────

def test_a_minority_of_the_pool_cannot_harden_a_single_block():
    """The committee is redrawn every block, so the threshold compounds.

    An attacker does not choose which turns stamp its fork — the draw does — so
    it can only stamp the drawn turns it happens to own.  Clearing a 2/3
    threshold on a fresh unbiased draw is the bar, every block, and it is a much
    higher bar than out-racing the honest chain on average weight.
    """
    era, hist = era_and_history()
    hist.accept(hist.harden(FakeBlock("b0"), era))
    rng = random.Random(3)
    for share in (0.10, 0.25):
        owned = set(rng.sample(range(DEMO.turns), int(DEMO.turns * share)))
        hb = hist.harden(FakeBlock("evil"), era, prev_hash=GENESIS, owned=owned)
        ok, why = hist.check(hb)
        assert not ok and "threshold" in why, (share, why)


def test_holding_the_whole_pool_still_cannot_reuse_spent_turns():
    era, hist = era_and_history()
    hist.accept(hist.harden(FakeBlock("b0"), era))
    everything = set(range(DEMO.turns))
    hb = hist.harden(FakeBlock("evil"), era, prev_hash=GENESIS, owned=everything)
    ok, _ = hist.check(hb)
    assert ok, "a total adversary can of course harden its own fork"
    assert hist.rewrite_ceiling(DEMO.turns) == DEMO.turns // DEMO.width
