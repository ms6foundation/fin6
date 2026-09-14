"""The admission rate limit, and what it is a bound on.  Review C5.

The 40-ceremony gate is per *node*.  On its own it is not a bound on anything
a grid cares about: an adversary admits a hundred nodes on one day, waits out
one gate, and they are all attesters together — the grid's composition changed
in a single step and the apprenticeship cost nothing, because the hundred
served it in parallel.

The admission rate is the missing half.  A grid runs at most that fraction of its own
attester count in apprenticeships at once, so the population it eventually
promotes into is the population that authorised the intake.  Capture still
happens if nobody is watching; it now takes k gates in the open instead of one.
"""
import dataclasses

from ..params import DEMO
from ..register import GridRegister, Standing
from ..tiers import bootstrap_world

PARAMS = dataclasses.replace(DEMO, attend_threshold=2, grid_size=7, row_size=5)
ENDOW = {"alice": [1000, 900, 800], "bob": [100]}


def _world(n=8, regions=None):
    regions = regions or {f"n{i:02d}": "genesis" for i in range(n)}
    return bootstrap_world(regions, ENDOW, PARAMS)[0]


# ── the cap itself ───────────────────────────────────────────────────────────

def test_the_cap_is_a_fraction_of_the_attesters():
    reg = GridRegister.genesis("g0", [f"n{i}" for i in range(8)])
    assert reg.apprentice_cap(1, 4) == 2
    assert reg.apprentice_cap(1, 2) == 4
    assert reg.apprentice_cap(1, 1) == 8


def test_a_small_grid_is_never_closed_to_newcomers():
    """3 // 4 is zero, and a grid nobody can join is a club."""
    reg = GridRegister.genesis("g0", ["a", "b", "c"])
    assert reg.apprentice_cap(1, 4) == 1
    assert reg.has_room(1, 4)


def test_room_runs_out_and_promotion_opens_it_again():
    reg = GridRegister.genesis("g0", [f"n{i}" for i in range(8)])
    reg.admit("x"); reg.admit("y")
    assert not reg.has_room(1, 4), "two apprentices is the cap at eight attesters"
    reg.members["x"].standing = Standing.ATTESTER
    assert reg.has_room(1, 4), "promotion makes room, which is the point"


def test_suspending_a_member_does_not_close_the_grid():
    """Otherwise an adversary shuts a grid to honest newcomers by getting its
    own nodes suspended — a fault that buys the faulter something."""
    reg = GridRegister.genesis("g0", [f"n{i}" for i in range(8)])
    reg.admit("x")
    reg.members["x"].standing = Standing.SUSPENDED
    assert reg.has_room(1, 4)
    assert reg.apprentice_cap(1, 4) == 2


# ── what it costs an adversary ───────────────────────────────────────────────

def test_a_cohort_cannot_arrive_together():
    """The whole of C5 in one assertion."""
    world = _world(n=7)                     # one grid, seven attesters
    gid = world.topology.grid_ids()[0]
    assert world.registers[gid].apprentice_cap(PARAMS.admit_num,
                                                       PARAMS.admit_den) == 1
    world.admit("evil-0", "genesis")
    try:
        world.admit("evil-1", "genesis")
    except ValueError as e:
        assert "apprenticeship" in str(e)
    else:
        raise AssertionError("a second apprentice joined a grid with room for one")
    assert "evil-1" not in world.nodes, "a refused newcomer is not half-admitted"
    assert "evil-1" not in world.topology.assignment
    world.registers[gid].members["evil-0"].standing = Standing.ATTESTER
    world.admit("evil-1", "genesis")         # a gate later, there is room


def test_capture_costs_a_gate_per_generation():
    """Growth is geometric, not a step: reaching parity with eight honest
    attesters takes four gates of visible apprenticeship, not one."""
    reg = GridRegister.genesis("g0", [f"n{i}" for i in range(8)])
    honest, gates, added = 8, 0, 0
    while added < honest:
        room = reg.apprentice_cap(1, 4)
        for i in range(room):
            reg.admit(f"e{added + i}")
        for nid in reg.apprentices():          # one gate passes
            reg.members[nid].standing = Standing.ATTESTER
        added += room
        gates += 1
    assert gates >= 4, f"parity in {gates} gates is not a rate limit"


# ── it narrows the draw without directing it ─────────────────────────────────

def test_the_seed_still_chooses_among_the_grids_with_room():
    world = _world(regions={f"n{i:02d}": "genesis" for i in range(8)} |
                           {f"s{i:02d}": "south" for i in range(8)})
    south = [g for g in world.topology.grid_ids()
             if world.topology.spec(g).region == "south"]
    assert len(south) >= 1
    seen = {world.admit(f"j{i}", "south") for i in range(2)}
    assert seen <= set(south), "a newcomer is seated in its own region"


def test_a_full_region_refuses_rather_than_overflowing_elsewhere():
    """Locality is not negotiable: a full region does not spill into another,
    because a grid's members are supposed to be near each other."""
    world = _world(regions={f"n{i:02d}": "genesis" for i in range(8)} |
                           {f"s{i:02d}": "south" for i in range(4)})
    world.admit("j0", "south")
    try:
        world.admit("j1", "south")
    except ValueError:
        pass
    else:
        raise AssertionError("the south grid took a second apprentice")
    assert all(world.topology.grid_of(n).startswith("genesis")
               for n in world.topology.members(world.topology.grids_in("genesis")[0]))


# ── the parameter ────────────────────────────────────────────────────────────

def test_a_rate_of_zero_is_refused_outright():
    try:
        dataclasses.replace(DEMO, admit_num=0)
    except ValueError:
        return
    raise AssertionError("a rate of zero would close every grid forever")


def test_the_rate_is_an_exact_ratio_not_a_float():
    """A consensus parameter every node must round the same way, in a document
    that has to re-encode to the same bytes, is not a floating point number."""
    assert isinstance(DEMO.admit_num, int) and isinstance(DEMO.admit_den, int)
    from ..store import codec
    codec.encode(DEMO.fingerprint())         # a float raises CodecError here


def test_a_high_rate_is_a_caveat_not_a_silent_default():
    _, caveats = dataclasses.replace(DEMO, admit_num=9, admit_den=10).assess()
    assert any("admission rate" in c for c in caveats)
    _, quiet = dataclasses.replace(DEMO, admit_num=1, admit_den=4).assess()
    assert not any("admission rate" in c for c in quiet)
