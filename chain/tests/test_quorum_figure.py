"""What a certificate had to reach, and who gets to say so.

Review B4. A quorum is a fraction of the *attesters*, and standing moves: the
roll of epoch e-1 is applied when block e lands, so by the time anybody checks
block e's certificate, the register has standing the ceremony did not have.
Membership survives a roll and standing does not, so across a founding — where
a cohort's standing changes — the attester count differs and the figure a
verifier derives is wrong.

Wrong in either direction, which is the part that matters. Too high refuses a
block that had its quorum; too low **accepts a certificate that was short**.
The light client's own docstring had recorded this as a known residual since
part eight.

So the number travels with the block that needed it. A full node checks it
against the register it ran the ceremony under and refuses a mismatch — so
among full nodes it is verified rather than announced — and everybody
downstream reads it instead of re-deriving it from a register that has moved.
"""
import dataclasses

from ..params import DEMO
from ..register import Standing
from ..tiered import NetworkBlock
from ..tiers import bootstrap_world, run_tiered_epoch

PARAMS = dataclasses.replace(DEMO, attend_threshold=2, grid_size=7, row_size=5)
ENDOW = {"alice": [1000, 900, 800], "bob": [100]}

_CACHE = {}


def _world(n=7):
    regions = {f"n{i:02d}": "genesis" for i in range(n)}
    return bootstrap_world(regions, ENDOW, PARAMS)


def _one_epoch():
    if "run" not in _CACHE:
        world, _ = _world()
        result = run_tiered_epoch(world, epoch=1, base_seed="seed")
        assert result.finalised, result.reason
        _CACHE["run"] = (world, result)
    return _CACHE["run"]


# ── the number is in the block ───────────────────────────────────────────────

def test_the_block_says_what_its_certificate_had_to_reach():
    world, result = _one_epoch()
    gid = world.topology.grid_ids()[0]
    assert result.block.header.quorum == world.quorum_for(gid) == 5, \
        "seven attesters, two thirds"
    for child in result.block.ceremony_blocks():
        assert child.header.quorum == world.quorum_for(child.header.grid_id)


def test_the_figure_is_inside_the_block_hash():
    world, result = _one_epoch()
    moved = dataclasses.replace(result.block.header, quorum=1)
    assert moved.hash() != result.block.header.hash()


def test_the_certificate_really_carries_that_many():
    world, result = _one_epoch()
    assert len(result.block.quorum_cert) >= result.block.header.quorum


# ── and a full node checks it ────────────────────────────────────────────────

def test_a_block_claiming_a_quorum_it_did_not_need_is_refused():
    """The check that makes the committed number worth reading: a leader that
    could write any figure could write 1, and a certificate with one signature
    would then be a finalised block."""
    from ..ceremony import HonestLeader
    from ..tiered import NetworkBlockHeader

    class Understates(HonestLeader):
        name = "understates"

        def propose(self, leader, grid, meta, limit=None, workload=None):
            block = workload.build(leader, meta, limit=limit)
            if isinstance(block.header, NetworkBlockHeader):
                block = dataclasses.replace(
                    block, header=dataclasses.replace(block.header, quorum=1))
            sp = leader.propose(block, meta.epoch, meta.grid_seed)
            return {**{n: sp for n in (grid.rows[0] if grid.rows else [])},
                    leader.id: sp}

    world, _ = _world()
    liars = {nid: Understates() for nid in world.nodes}
    res = run_tiered_epoch(world, 1, "seed", behaviours=liars)
    assert not res.finalised, "a block understating its quorum was finalised"


def test_the_ceremony_header_is_checked_the_same_way():
    """The same rule one tier down, where `GridWorkload.validate` is what
    refuses it — and where the number tier 1 later reads comes from."""
    from ..tiers import GridWorkload

    world, result = _one_epoch()
    child = next(result.block.ceremony_blocks())
    gid = child.header.grid_id
    workload = GridWorkload(world, gid, 1, PARAMS.backend_for(0))
    node = world.nodes[sorted(world.nodes)[0]]
    bad = dataclasses.replace(
        child, header=dataclasses.replace(child.header, quorum=2))
    ok, why = workload.validate(node, bad)
    assert not ok and "quorum" in why, why


# ── which is the point: standing moves ───────────────────────────────────────

def test_the_register_a_verifier_holds_is_not_the_one_that_signed():
    """The mechanism behind B4, asserted directly rather than argued.

    An apprentice that crosses the attendance threshold becomes an attester
    when the roll is applied — so the attester count, and therefore the
    quorum, is one thing during the ceremony and another immediately after.
    """
    world, _ = _world()
    gid = world.topology.grid_ids()[0]
    register = world.registers[gid]
    before = world.quorum_for(gid)

    world.admit("n07", "genesis")               # an apprentice joins
    assert register.standing_of("n07") == Standing.APPRENTICE
    assert world.quorum_for(gid) == before, "apprentices hold seats, not votes"

    # Two ceremonies is the threshold in these parameters, so the third roll
    # promotes it and the quorum moves under anybody still asking the register.
    for epoch in (1, 2, 3):
        res = run_tiered_epoch(world, epoch, "seed")
        if not res.finalised:
            break
        during = res.block.header.quorum
        world.apply_network_block(res.block)
        after = world.quorum_for(gid)
        if after != during:
            # Exactly the situation B4 names: a verifier deriving the figure
            # now would get `after` for a certificate that needed `during`.
            assert res.block.header.quorum == during
            return
    raise AssertionError("standing never moved; the fixture proves nothing")
