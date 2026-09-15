"""Standing for what a node does above its own grid.  Review C2 §7.

Standing lives in one register per *local* grid, advanced by an attendance
roll.  Tier-1 and top-tier grids are not tier-0 grids — no persistent
membership, no register, no roll — so a node that no-showed at the top paid
nothing, while the same node missing its home ceremony lost its streak.

The incentives were therefore inverted exactly where the blast radius is
largest: the cheapest place in the network to be absent was the only place
where being absent stopped everybody.
"""
import dataclasses
import tempfile

from ..network import transfer
from ..params import DEMO
from ..register import GridRegister, Standing
from ..store import ChainStore
from ..tiered import tier_service
from ..tiers import bootstrap_world, run_tiered_epoch

PARAMS = dataclasses.replace(DEMO, attend_threshold=3, grid_size=5, row_size=5)
_RUN = {}


def _world(n=40):
    regions = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(n)}
    w, wallets = bootstrap_world(
        regions, {"alice": [1000, 800], "bob": [250]}, PARAMS)
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, PARAMS)
    w.submit(tx)
    return w, wallets


def _fresh():
    """A world and nothing else, for a run whose seating is being compared."""
    w, _ = _world()
    return (w,)


def _three_tiers():
    """One epoch of a 40-node network: 8 grids, 2 tier-1 grids, 3 tiers."""
    if "run" not in _RUN:
        w, wallets = _world()
        r = run_tiered_epoch(w, epoch=1, base_seed="s")
        assert r.finalised and r.tiers == 3, r.reason
        _RUN["run"] = (w, r)
    return _RUN["run"]


# ── what the block says ──────────────────────────────────────────────────────

def test_service_is_derived_from_the_block_and_carried_in_nothing():
    w, r = _three_tiers()
    block = r.block
    once = tier_service(block)
    assert once == tier_service(block), "the same bytes, the same answer"
    assert once, "three tiers ran and nobody was credited with anything"


def test_everyone_who_sat_above_their_grid_is_named():
    w, r = _three_tiers()
    service = tier_service(r.block)
    committee = set(r.tier2.grid.seats)
    assert committee <= set(service), "a top-tier seat that is not in the record"
    for res in r.tier1.finalised.values():
        assert set(res.grid.seats) <= set(service)
    assert all(nid in w.nodes for nid in service)


def test_attending_and_leading_are_counted_apart():
    w, r = _three_tiers()
    service = tier_service(r.block)
    led = [n for n, (_, _, l) in service.items() if l]
    assert r.block.header.leader_id in led, "the top-tier leader led something"
    for nid, (seated, attended, leading) in service.items():
        assert attended <= seated, (nid, service[nid])
        assert leading <= seated


def test_a_seat_that_did_not_sign_is_seated_and_not_attended():
    """The whole point: absence has to be *recorded*, or it is free."""
    w, r = _three_tiers()
    block = r.block
    cert = block.quorum_cert
    thin = dataclasses.replace(cert, signers=cert.signers[:1],
                               signatures=cert.signatures[:1],
                               shadow_signers=(), shadow_signatures=())
    quiet = dataclasses.replace(block, quorum_cert=thin)
    service = tier_service(quiet)
    missed = [n for n, (s, a, _) in service.items() if a < s]
    assert missed, "a certificate naming one signer leaves everyone else absent"
    honest = tier_service(block)
    for nid in missed:
        assert service[nid][0] == honest[nid][0], "seated either way"
        assert service[nid][1] < honest[nid][1], "and short one attendance"


def test_one_tier_credits_nothing():
    """One tier is one ceremony. Crediting it here would count the local roll a
    second time under another name."""
    regions = {f"n{i:02d}": "eu" for i in range(4)}
    w, wallets = bootstrap_world(
        regions, {"alice": [1000], "bob": []},
        dataclasses.replace(PARAMS, grid_size=100))
    r = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert r.finalised and r.tiers == 1
    assert tier_service(r.block) == {}


# ── what the register does with it ───────────────────────────────────────────

def test_the_counters_are_separate_from_the_local_ones():
    """A seat at the upper tiers is drawn by a lottery the member does not
    control, so folding it into `consecutive` would let a node lose the
    standing it earned at home for an epoch it was conscripted into."""
    reg = GridRegister.genesis("g0", ["a", "b"], attend_threshold=40)
    reg.members["a"].consecutive = 7
    reg.credit_service({"a": (2, 1, 1), "stranger": (5, 5, 5)})
    rec = reg.members["a"]
    assert (rec.higher_seated, rec.higher_attended, rec.higher_led) == (2, 1, 1)
    assert rec.higher_missed == 1
    assert rec.consecutive == 7, "the local streak is not a service counter"
    assert reg.epoch == 0, "service is not a ceremony of this grid"
    assert "stranger" not in reg.members


def test_service_is_in_the_root_and_survives_a_round_trip():
    reg = GridRegister.genesis("g0", ["a", "b"])
    before = reg.root()
    reg.credit_service({"a": (1, 0, 0)})
    assert reg.root() != before, "absence at the top must be visible in state"
    assert GridRegister.load(reg.dump()).root() == reg.root()


def test_an_epoch_credits_the_registers_one_block_later():
    """The same beat an attendance roll keeps: a block commits a register root
    every seat could compute before the block existed."""
    w, wallets = _world()
    first = run_tiered_epoch(w, epoch=1, base_seed="s")
    assert first.finalised, first.reason
    w.apply_network_block(first.block)
    assert w.prev_service, "the block that was applied says who served"
    credited = sum(r.higher_seated for reg in w.registers.values()
                   for r in reg.members.values())
    assert credited == 0, "not yet — it lands with the next block"

    second = run_tiered_epoch(w, epoch=2, base_seed="s")
    assert second.finalised, second.reason
    w.apply_network_block(second.block)
    credited = {n: r for reg in w.registers.values()
                for n, r in reg.members.items() if r.higher_seated}
    assert credited, "the second block should have credited the first's service"
    assert any(r.higher_led for r in credited.values())


def test_the_root_a_block_commits_is_the_root_the_block_produces():
    """Service moves the register, so it has to be inside the root the block
    commits — otherwise a snapshot folds to a different `registers_root` than
    the header says and state sync refuses a state that is perfectly good."""
    from ..tiered import registers_root

    w, wallets = _world()
    for epoch in (1, 2, 3):
        r = run_tiered_epoch(w, epoch=epoch, base_seed="s")
        assert r.finalised, r.reason
        w.apply_network_block(r.block)
        live = registers_root({g: reg.root()
                               for g, reg in w.registers.items()})
        assert live == r.block.header.registers_root, \
            f"epoch {epoch}: the live registers do not fold to the header"


def test_a_restarted_node_credits_the_same_thing():
    """Third time this lesson has arrived — after `grid_roll` and `grid_cert`.
    A node that restarts without what the next block credits computes a
    different register root from everybody else."""
    w, wallets = _world()
    with tempfile.TemporaryDirectory() as tmp:
        store = ChainStore(f"{tmp}/s.db")
        w.persist(store, [sorted(w.nodes)[0]])
        for epoch in (1, 2):
            r = run_tiered_epoch(w, epoch=epoch, base_seed="s")
            assert r.finalised, r.reason
            w.apply_network_block(r.block)
        assert w.prev_service
        assert store.load_service() == w.prev_service


# ── views at the top ─────────────────────────────────────────────────────────

def test_a_silent_top_tier_leader_costs_a_view_and_not_the_epoch():
    """Review C2, Road C.  The tier below can lose a grid and carry on; this
    one cannot lose anything, so a leader that does not propose used to end the
    epoch for every partition on the network.

    Silenced at the top tier only.  A bare node id would silence it in its
    own grid too, which changes which grids finalise, which changes the
    committee — and the experiment would be measuring something else.
    """
    from ..ceremony import SilentLeader

    w, r = _three_tiers()
    bad = r.tier2.grid.leader
    assert r.top_views == 1

    world, _ = _world()
    result = run_tiered_epoch(world, epoch=1, base_seed="s",
                              behaviours={(2, bad): SilentLeader()})
    assert result.finalised, result.reason
    assert result.top_views == 2, "one view lost, the next one carried it"
    assert result.tier2.grid.leader != bad, \
        "a view that reseats the same leader is not a view change"
    assert set(result.tier2.grid.seats) == set(r.tier2.grid.seats), \
        "the committee is the same one; only the seating moved"
    assert result.block.header.leader_id == result.tier2.grid.leader


def test_the_view_budget_is_a_budget_and_not_a_guarantee():
    """If every view fails the epoch produces nothing, exactly as it did
    before, and the chain recovers at the next one."""
    from ..ceremony import SilentLeader

    world, _ = _world()
    quiet = {(2, n): SilentLeader() for n in world.nodes}
    result = run_tiered_epoch(world, epoch=1, base_seed="s", behaviours=quiet)
    assert not result.finalised
    assert "top tier" in result.reason, result.reason
    assert result.top_views == 3, "it spent the whole budget first"
    assert result.tier0.finalised and result.tier1.finalised, \
        "the tiers below did their work and lost it, which is C2 exactly"


def test_one_view_is_the_behaviour_this_replaced():
    from ..ceremony import SilentLeader

    w, r = _three_tiers()
    world, _ = _world()
    result = run_tiered_epoch(
        world, epoch=1, base_seed="s", max_views=1,
        behaviours={(2, r.tier2.grid.leader): SilentLeader()})
    assert not result.finalised and result.top_views == 1


def test_a_behaviour_can_still_be_aimed_at_a_node_everywhere():
    from ..ceremony import SilentLeader
    from ..tiers import _behaviour

    assert _behaviour({}, 2, "n01").name == "honest"
    assert _behaviour({"n01": SilentLeader()}, 0, "n01").name == "silent"
    assert _behaviour({(2, "n01"): SilentLeader()},
                      0, "n01").name == "honest"
