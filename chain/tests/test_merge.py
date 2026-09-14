"""Grids that fold away.  Review C4.

Splitting worked and merging did not exist, so the topology could only ever
grow.  A network that shrinks kept grids it could not fill: seats that cannot
reach quorum, owning a nullifier partition that nothing else may include, which
is a partition of the ledger nobody can spend in.

The mechanism mirrors `plan_foundings` — derived from committed state, carried
in the block, re-derived by every seat — with two deliberate differences.  A
founding moves a *selected cohort*, so its selection must be seeded; a merge
moves **everyone**, so there is nothing to select and nothing to launder.  And
a merge renumbers the partitions, which a founding does not.
"""
import dataclasses

from ..locality import Topology
from ..params import DEMO
from ..register import GridRegister, Standing
from ..tiered import GridMerge
from ..tiers import (_check_merges, bootstrap_world, plan_merges,
                     run_tiered_epoch)

PARAMS = dataclasses.replace(DEMO, attend_threshold=2, grid_size=7, row_size=5,
                             founding_cohort=4, admit_num=2, admit_den=1)
ENDOW = {"alice": [1000, 900, 800, 700], "bob": [100]}


def _world(n=14, region="genesis"):
    regions = {f"n{i:02d}": region for i in range(n)}
    return bootstrap_world(regions, ENDOW, PARAMS)


def _quieten(world, grid_id, how_many):
    """Suspend members until the grid is below viability.

    Standing is set directly here; on a live network `chain/faults.py` and the
    roll are what put a member in this state.  What matters for the merge is
    only that it is committed register state every seat holds.
    """
    reg = world.registers[grid_id]
    for nid in sorted(reg.members)[:how_many]:
        reg.members[nid].standing = Standing.SUSPENDED
    return reg


# ── the register primitive ───────────────────────────────────────────────────

def test_absorb_takes_the_members_release_refuses():
    """`release` exists to refuse apprentices and the suspended.  A merge is
    obliged to carry exactly those, which is why it is a separate primitive."""
    a = GridRegister.genesis("g0", [f"n{i}" for i in range(4)], epoch=9)
    b = GridRegister.genesis("g1", [f"m{i}" for i in range(4)], epoch=9)
    b.admit("appr")
    b.members["m0"].standing = Standing.SUSPENDED
    b.members["m0"].faults = (4,)
    moved = a.absorb(b)
    assert len(moved) == 5 and len(b.members) == 0
    assert a.standing_of("m0") == Standing.SUSPENDED, "a suspension is not laundered"
    assert a.members["m0"].faults == (4,)
    assert a.standing_of("appr") == Standing.APPRENTICE, "served time is not deleted"
    try:
        a.release(["m0"])
    except ValueError:
        pass
    else:
        raise AssertionError("release took a suspended member")


def test_the_carried_standing_is_visible_in_the_root():
    a = GridRegister.genesis("g0", ["x"], epoch=3)
    b = GridRegister.genesis("g1", ["y"], epoch=3)
    a.absorb(b)
    assert a.members["y"].founded_from == "g1"
    plain = GridRegister.genesis("g0", ["x", "y"], epoch=3)
    assert a.root() != plain.root(), "the root must show where standing came from"
    assert GridRegister.load(a.dump()).root() == a.root()


def test_two_registers_at_different_epochs_do_not_merge():
    a = GridRegister.genesis("g0", ["x"], epoch=3)
    b = GridRegister.genesis("g1", ["y"], epoch=4)
    try:
        a.absorb(b)
    except ValueError as e:
        assert "ceremony" in str(e)
        return
    raise AssertionError("merged two registers a ceremony apart")


def test_a_member_cannot_end_up_in_one_register_twice():
    a = GridRegister.genesis("g0", ["x", "y"], epoch=1)
    b = GridRegister.genesis("g1", ["y"], epoch=1)
    try:
        a.absorb(b)
    except ValueError:
        return
    raise AssertionError("absorbed a member that was already there")


# ── the topology ─────────────────────────────────────────────────────────────

def _topology():
    return Topology.build({f"n{i:02d}": "genesis" for i in range(14)} |
                          {f"s{i:02d}": "south" for i in range(7)},
                          grid_size=7, seed="s")


def test_the_partitions_are_compacted_so_none_is_orphaned():
    """The index *is* the partition and K is the number of grids, so removing
    a grid without renumbering leaves notes nothing can ever spend."""
    topo = _topology()
    before = topo.n_partitions
    gone, into = topo.grids_in("genesis")[0], topo.grids_in("genesis")[1]
    topo.merge_grid(gone, into)
    assert topo.n_partitions == before - 1
    assert sorted(topo.partition_of(g) for g in topo.grid_ids()) == \
        list(range(topo.n_partitions)), "every partition has exactly one owner"
    assert gone not in topo.grid_ids()
    assert all(topo.grid_of(n) == into for n in topo.members(into))


def test_a_merge_will_not_cross_a_region():
    topo = _topology()
    try:
        topo.merge_grid(topo.grids_in("south")[0], topo.grids_in("genesis")[0])
    except ValueError as e:
        assert "region" in str(e)
        return
    raise AssertionError("merged a grid into another region")


def test_the_last_grid_has_nowhere_to_go():
    topo = Topology.build({f"n{i:02d}": "genesis" for i in range(4)},
                          grid_size=7, seed="s")
    try:
        topo.merge_grid("genesis-0", "genesis-0")
    except ValueError:
        return
    raise AssertionError("a lone grid merged into itself")


# ── the plan ─────────────────────────────────────────────────────────────────

def test_a_healthy_network_merges_nothing():
    world, _ = _world()
    assert len(world.topology.grid_ids()) == 2
    assert plan_merges(world, epoch=1) == ()


def test_a_grid_whose_seats_have_gone_quiet_folds_into_its_sibling():
    world, _ = _world()
    gid = world.topology.grid_ids()[0]
    _quieten(world, gid, 5)                  # two seats left of seven
    merged = plan_merges(world, epoch=1)
    assert len(merged) == 1
    assert merged[0].from_id == gid
    assert merged[0].into_id != gid
    assert set(merged[0].movers) == set(world.topology.members(gid)), \
        "everyone moves, the suspended included"


def test_the_plan_is_deterministic():
    world, _ = _world(n=21)                  # three grids
    _quieten(world, world.topology.grid_ids()[0], 5)
    a = plan_merges(world, epoch=1)
    assert len(a) == 1
    assert tuple(m.digest() for m in a) == \
        tuple(m.digest() for m in plan_merges(world, epoch=1))


def test_the_smallest_sibling_takes_it_and_the_tip_breaks_the_tie():
    """Smallest, so the merge does not create the next split.  The tie-break
    is the previous block's hash for the same reason the founding cohort is
    drawn from it: whoever assembles the block must not choose where a grid's
    members land."""
    world, _ = _world(n=21)
    gid = world.topology.grid_ids()[0]
    _quieten(world, gid, 5)
    siblings = [g for g in world.topology.grid_ids() if g != gid]
    sizes = {g: len(world.topology.members(g)) for g in siblings}
    assert len(set(sizes.values())) == 1, "this fixture has equal siblings"
    picks = {plan_merges(dataclasses.replace(world, tip=f"nb:{h:02x}" * 32),
                         epoch=1)[0].into_id for h in range(8)}
    assert picks <= set(siblings)
    assert len(picks) > 1, "a fixed tip would let the assembler choose"


def test_a_merge_that_would_immediately_split_is_not_made():
    """Otherwise K churns every other epoch: fold, overflow, found, fold."""
    world, _ = _world()                      # two grids of seven
    gid = world.topology.grid_ids()[0]
    _quieten(world, gid, 5)
    assert plan_merges(world, epoch=1), "with room, it folds"
    tight = dataclasses.replace(
        world, params=dataclasses.replace(PARAMS, grid_size=6))
    assert tight.topology.needs_merge(gid, 6, live=2), "still unviable"
    assert plan_merges(tight, epoch=1) == (), \
        "14 members is over the split threshold of 12"


def test_a_founding_and_a_merge_never_share_an_epoch():
    """Both move K, and K is the modulus in `nf mod K`: doing them together
    would re-home every transaction in flight twice for no gain.  The founding
    is stubbed because arranging a network that wants both at once is a
    fixture, not a fact — the rule under test is the precedence."""
    from .. import tiers
    world, _ = _world()
    _quieten(world, world.topology.grid_ids()[0], 5)
    assert plan_merges(world, epoch=1), "a merge is called for"
    real = tiers.plan_foundings
    tiers.plan_foundings = lambda w, e: ("a founding",)
    try:
        assert plan_merges(world, epoch=1) == ()
    finally:
        tiers.plan_foundings = real


def test_never_the_last_grid():
    world, _ = _world(n=7)
    assert len(world.topology.grid_ids()) == 1
    _quieten(world, world.topology.grid_ids()[0], 6)
    assert plan_merges(world, epoch=1) == (), \
        "one grid is the degenerate case, not an error state"


def test_at_most_one_merge_an_epoch():
    world, _ = _world(n=21)
    for gid in world.topology.grid_ids():
        _quieten(world, gid, 5)
    assert len(plan_merges(world, epoch=1)) <= 1


# ── the block ────────────────────────────────────────────────────────────────

def test_the_network_folds_a_grid_and_keeps_going():
    world, wallets = _world()
    gid = world.topology.grid_ids()[0]
    _quieten(world, gid, 5)
    before = world.topology.n_partitions
    result = run_tiered_epoch(world, epoch=1, base_seed="fold")
    assert result.finalised, result.reason
    assert len(result.block.merges) == 1, "the block carries the merge"
    world.apply_network_block(result.block)
    assert gid not in world.topology.grid_ids()
    assert gid not in world.registers
    assert world.topology.n_partitions == before - 1
    result = run_tiered_epoch(world, epoch=2, base_seed="fold")
    assert result.finalised, result.reason
    world.apply_network_block(result.block)


def test_a_leader_cannot_choose_where_a_grid_lands():
    world, _ = _world()
    gid = world.topology.grid_ids()[0]
    _quieten(world, gid, 5)
    result = run_tiered_epoch(world, epoch=1, base_seed="fold")
    assert result.finalised, result.reason
    block = result.block
    forged = GridMerge(from_id=gid, into_id=world.topology.grid_ids()[1],
                       epoch=1, movers=("n00",))
    tampered = dataclasses.replace(block, merges=(forged,))
    ok, why = _check_merges(world, 1, tampered)
    assert not ok and "merges_root" in why
    header = dataclasses.replace(block.header,
                                 merges_root=tampered.compute_merges_root())
    tampered = dataclasses.replace(tampered, header=header)
    ok, why = _check_merges(world, 1, tampered)
    assert not ok and "not the one the state calls for" in why


def test_a_merged_grid_does_not_come_back_from_the_store():
    """The register write is an upsert, so without an explicit retirement the
    grid survives in the store with members who are now in two registers."""
    import tempfile

    from ..store import ChainStore
    world, _ = _world()
    gid = world.topology.grid_ids()[0]
    _quieten(world, gid, 5)
    with tempfile.TemporaryDirectory() as tmp:
        node_id = sorted(world.nodes)[0]
        store = ChainStore(f"{tmp}/s.db")
        world.persist(store, [node_id])
        result = run_tiered_epoch(world, epoch=1, base_seed="fold")
        assert result.finalised, result.reason
        assert result.block.merges
        world.apply_network_block(result.block)
        # One more, because a block carries the roll of the epoch before it and
        # registers are only written when there is a roll to write.
        result = run_tiered_epoch(world, epoch=2, base_seed="fold")
        assert result.finalised, result.reason
        world.apply_network_block(result.block)
        back = store.load_registers()
        assert gid not in back, f"{gid} came back from the store"
        assert set(back) == set(world.registers)
        for other in back.values():
            assert other.root() == world.registers[other.grid_id].root()
