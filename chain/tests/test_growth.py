"""Growing past one grid: the founding cohort, and the deadlock it removes.

A grid of pure apprentices can never reach quorum, so it can never run the
ceremony that would promote anyone — which made a newly created grid deadlocked
permanently rather than slowly.  The fix is the same waiver genesis uses, used
again: a cohort of attesters moves across and keeps what it earned.  These
tests are mostly about the ways that could be abused.
"""
import dataclasses

from ..network import transfer
from ..params import DEMO
from ..register import GridRegister, Standing
from ..tiered import GridFounding
from ..tiers import (_check_foundings, bootstrap_world, plan_foundings,
                     run_tiered_epoch)

PARAMS = dataclasses.replace(DEMO, attend_threshold=2, grid_size=7, row_size=5,
                             founding_cohort=4)
ENDOW = {"alice": [1000, 900, 800, 700, 600, 500, 400, 300], "bob": [100]}

_RUN = {}


def fresh(params=PARAMS):
    regions = {f"n{i:02d}": "genesis" for i in range(7)}
    return bootstrap_world(regions, ENDOW, params)


def grown():
    """A world run until it has founded its second grid."""
    if "world" not in _RUN:
        world, wallets = fresh()
        for i in range(8):
            world.admit(f"m{i:02d}", "genesis")
        founded_at = None
        for e in range(1, 9):
            tx, _ = transfer(wallets["alice"], wallets["alice"], 50 + e, 1,
                             world.params)
            world.submit(tx)
            result = run_tiered_epoch(world, epoch=e, base_seed="grow")
            assert result.finalised, (e, result.reason)
            if result.block.foundings and founded_at is None:
                founded_at = e
            world.apply_network_block(result.block)
        _RUN["world"] = (world, wallets, founded_at)
    return _RUN["world"]


# ── the register rule ────────────────────────────────────────────────────────

def test_a_cohort_carries_what_it_earned():
    reg = GridRegister.genesis("g0", [f"n{i}" for i in range(8)],
                               attend_threshold=40)
    reg.members["n0"].led_count = 3
    moved = reg.release(["n0", "n1", "n2", "n3"])
    new = GridRegister.found("g1", moved, "g0", epoch=9, attend_threshold=40)
    assert len(reg.attesters()) == 4 and len(new.attesters()) == 4
    assert new.quorum(2, 3) == 3, "four attesters can still reach quorum"
    assert new.members["n0"].consecutive == 40
    assert new.members["n0"].led_count == 3
    assert new.members["n0"].standing == Standing.ATTESTER


def test_the_waiver_is_recorded_in_the_root():
    """A waiver that is not visible in the state is one nobody can audit."""
    reg = GridRegister.genesis("g0", [f"n{i}" for i in range(8)])
    moved = reg.release(["n0", "n1", "n2", "n3"])
    new = GridRegister.found("g1", moved, "g0", epoch=1)
    assert all(m.founded_from == "g0" for m in new.members.values())
    assert all(m.founded_from == "" for m in reg.members.values())
    plain = GridRegister.genesis("g1", ["n0", "n1", "n2", "n3"])
    assert new.root() != plain.root(), "the root must show where standing came from"
    assert GridRegister.load(new.dump()).root() == new.root()


def test_only_unfaulted_attesters_can_found():
    reg = GridRegister.genesis("g0", [f"n{i}" for i in range(8)])
    reg.admit("newbie")
    reg.members["n7"].faults = (3,)
    reg.members["n6"].standing = Standing.SUSPENDED
    for who, why in (("newbie", "apprentice"), ("n7", "fault"),
                     ("n6", "suspended")):
        try:
            reg.release([who])
        except ValueError:
            continue
        raise AssertionError(f"released a {why}")


# ── the plan ─────────────────────────────────────────────────────────────────

def test_no_founding_before_the_grid_is_over_size():
    world, _ = fresh()
    assert plan_foundings(world, epoch=1) == ()


def test_no_founding_that_would_strand_the_donor():
    """The half that stays has to reach its own quorum too."""
    world, _ = fresh()
    for i in range(8):
        world.admit(f"m{i:02d}", "genesis")
    gid = world.topology.grid_ids()[0]
    assert world.topology.needs_split(gid, world.params.grid_size)
    # The newcomers are still apprentices, so there are only 7 attesters —
    # one short of twice the cohort.
    assert plan_foundings(world, epoch=1) == ()


def test_the_draw_is_deterministic_and_seeded_by_the_previous_block():
    world, _, _ = grown()
    a = plan_foundings(world, epoch=99)
    b = plan_foundings(world, epoch=99)
    assert tuple(f.digest() for f in a) == tuple(f.digest() for f in b)
    moved = dataclasses.replace(world, tip="nb:" + "ff" * 32)
    c = plan_foundings(moved, epoch=99)
    if a and c:
        assert a[0].cohort != c[0].cohort, \
            "a different previous block must select a different cohort"


def test_at_most_one_founding_an_epoch():
    world, _, _ = grown()
    assert len(plan_foundings(world, epoch=99)) <= 1


def test_a_leader_cannot_choose_the_cohort():
    """The plan is a function of state every seat holds, so proposing a
    different one is not discretion — it is a lie about the state."""
    world, wallets, _ = grown()
    epoch = world.height + 1
    result = run_tiered_epoch(world, epoch=epoch, base_seed="grow")
    assert result.finalised, result.reason
    block = result.block
    forged = GridFounding(donor_id=world.topology.grid_ids()[0],
                          grid_id="genesis-9", epoch=epoch,
                          cohort=tuple(sorted(world.nodes)[:4]))
    tampered = dataclasses.replace(block, foundings=(forged,))
    ok, why = _check_foundings(world, epoch, tampered)
    assert not ok and "foundings_root" in why
    header = dataclasses.replace(block.header,
                                 foundings_root=tampered.compute_foundings_root())
    tampered = dataclasses.replace(tampered, header=header)
    ok, why = _check_foundings(world, epoch, tampered)
    assert not ok and "not the one the state calls for" in why


# ── the deadlock ─────────────────────────────────────────────────────────────

def test_the_network_grows_out_of_one_grid():
    world, _, founded_at = grown()
    assert founded_at is not None, "the grid never founded a child"
    assert len(world.topology.grid_ids()) == 2
    assert world.topology.n_partitions == 2


def test_the_new_grid_can_reach_quorum_on_its_own():
    """This is the deadlock, and the whole point of the change."""
    world, _, _ = grown()
    new = [g for g in world.topology.grid_ids()
           if any(m.founded_from for m in world.registers[g].members.values())]
    assert new, "no founded grid"
    reg = world.registers[new[0]]
    assert len(reg.attesters()) >= reg.quorum(2, 3) > 0
    assert reg.leader_candidates(), "and it can produce a leader"


def test_both_halves_keep_working_after_the_split():
    world, wallets, _ = grown()
    grids = set(world.topology.grid_ids())
    assert len(grids) == 2
    for i in range(4):
        epoch = world.height + 1
        tx, _ = transfer(wallets["alice"], wallets["alice"], 60 + i, 1,
                         world.params)
        ok, _, _ = world.submit(tx)
        assert ok, "a transaction always has a grid that owns its partition"
        result = run_tiered_epoch(world, epoch=epoch, base_seed="grow")
        assert result.finalised, (epoch, result.reason)
        assert result.tiers == 2, "two grids means a super tier"
        # Both halves run their own ceremony and both reach quorum — the donor
        # was not stranded and the founded grid is not a passenger.
        assert set(result.local.finalised) == grids, result.local.skipped
        world.apply_network_block(result.block)


def test_the_repartition_leaves_nothing_stranded():
    """K is the modulus, so a founding re-homes every transaction in flight."""
    world, wallets, _ = grown()
    world.reroute_mempools()                      # start from a clean slate
    for node in world.nodes.values():
        for txid in list(node.mempool):
            node._evict(txid)
    tx, _ = transfer(wallets["alice"], wallets["alice"], 77, 1, world.params)
    world.submit(tx)
    holders = {n for n, node in world.nodes.items() if node.mempool}
    assert holders, "the transaction landed somewhere"
    rerouted, total = world.reroute_mempools()
    assert total == 1 and rerouted == 1, (rerouted, total)
    assert {n for n, node in world.nodes.items() if node.mempool} == holders, \
        "re-routing puts it back in the same grid when K has not moved"


def test_the_cohort_does_not_end_up_in_two_registers():
    """The roll of the founding epoch still names the movers as seats of the
    grid they are leaving, and a register admits anyone a roll names."""
    world, _, _ = grown()
    seen = {}
    for gid, reg in world.registers.items():
        for nid in reg.members:
            assert nid not in seen, (f"{nid} is in both {seen.get(nid)} and "
                                     f"{gid}")
            seen[nid] = gid
    for gid in world.topology.grid_ids():
        assert set(world.topology.members(gid)) == set(world.registers[gid].members)


def test_a_founded_grid_keeps_its_own_register_afterwards():
    world, _, _ = grown()
    new = [g for g in world.topology.grid_ids()
           if any(m.founded_from for m in world.registers[g].members.values())][0]
    before = world.registers[new].root()
    result = run_tiered_epoch(world, epoch=world.height + 1, base_seed="grow")
    assert result.finalised, result.reason
    world.apply_network_block(result.block)
    assert world.registers[new].root() != before, \
        "the founded grid runs its own ceremonies and its register moves"
