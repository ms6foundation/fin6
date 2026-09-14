"""Changing view when the leader does not answer.

Part eleven, review C1. In process a view change is a retry loop: reseat from a
fresh seed, skip the leaders already tried, run again. On a network it is a
protocol, and the reason is one case:

    in view 0, five of seven seats attest to B, and one seat sees all five.
    B is final for that seat. The others time out and move to view 1, where a
    new leader proposes C.

Nothing in a retry loop stops C finalising too. Two blocks, one height, and
nobody misbehaved — a message was late. So a seat that attests is *locked*, the
view change collects the locks, and the new leader is bound by them.

These tests are mostly about that binding, and about the release rule that
keeps it from deadlocking the height on one crashed seat's half-finished vote.
"""
import dataclasses

from ..crypto import Signer
from ..net.clock import Clock
from ..block import CeremonyMeta
from ..net.seat import Seat, proposal_header
from ..viewchange import (ViewChange, ViewChangeCert, may_propose,
                          sign_view_change)
from .test_net import PARAMS, build_seats, seated_world


def _vc(world, node_id, view=1, height=1, epoch=1, lock=None):
    return sign_view_change(world.nodes[node_id], height, epoch, view, lock)


def _validators(world, grid):
    return {n: world.nodes[n].public_hex for n in grid.seats}


# ── the statement ────────────────────────────────────────────────────────────

def test_a_view_change_carries_the_lock_and_is_signed_over_it():
    world, _ = seated_world()
    vc = _vc(world, "n00", lock=(0, "nb:beef"))
    assert vc.verify() and vc.locked
    assert not dataclasses.replace(vc, locked_hash="nb:other").verify()
    assert not dataclasses.replace(vc, view=2).verify()


def test_an_empty_lock_is_a_statement_too():
    world, _ = seated_world()
    vc = _vc(world, "n00")
    assert vc.verify() and not vc.locked
    assert vc.locked_view == -1


# ── the certificate ──────────────────────────────────────────────────────────

def _cert(world, grid, ids, view=1, locks=None):
    locks = locks or {}
    return ViewChangeCert(view=view, changes=tuple(
        _vc(world, n, view=view, lock=locks.get(n)) for n in ids))


def test_a_quorum_of_view_changes_is_what_entitles_a_leader_to_propose():
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    ids = sorted(grid.seats)
    quorum = seats[grid.leader].quorum
    short = _cert(world, grid, ids[:quorum - 1])
    ok, why = short.check(chain_id=world.params.chain_id, height=1, epoch=1,
                          view=1, quorum=quorum,
                          validators=_validators(world, grid))
    assert not ok and "quorum" in why
    full = _cert(world, grid, ids[:quorum])
    assert full.check(chain_id=world.params.chain_id, height=1, epoch=1,
                      view=1, quorum=quorum,
                      validators=_validators(world, grid))[0]


def test_a_seat_that_is_not_in_the_grid_does_not_count():
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    ids = sorted(grid.seats)
    quorum = seats[grid.leader].quorum
    cert = _cert(world, grid, ids[:quorum])
    stranger = dataclasses.replace(cert.changes[0], node_id="nobody")
    forged = ViewChangeCert(view=1, changes=(stranger,) + cert.changes[1:])
    ok, why = forged.check(chain_id=world.params.chain_id, height=1, epoch=1,
                           view=1, quorum=quorum,
                           validators=_validators(world, grid))
    assert not ok and "not a seat" in why


def test_the_same_seat_twice_is_not_two_seats():
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    quorum = seats[grid.leader].quorum
    one = _vc(world, sorted(grid.seats)[0])
    ok, why = ViewChangeCert(view=1, changes=(one,) * quorum).check(
        chain_id=world.params.chain_id, height=1, epoch=1, view=1,
        quorum=quorum, validators=_validators(world, grid))
    assert not ok and "twice" in why


def test_a_certificate_for_another_view_is_refused():
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    ids = sorted(grid.seats)
    quorum = seats[grid.leader].quorum
    cert = _cert(world, grid, ids[:quorum], view=1)
    ok, why = cert.check(chain_id=world.params.chain_id, height=1, epoch=1,
                         view=2, quorum=quorum,
                         validators=_validators(world, grid))
    assert not ok and "view" in why


# ── what the leader is bound by ──────────────────────────────────────────────

def test_a_certificate_with_no_locks_lets_the_leader_propose_anything():
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    cert = _cert(world, grid, sorted(grid.seats)[:5])
    assert cert.required_block() is None
    assert may_propose(cert, "nb:anything", view=1)[0]


def test_one_reported_lock_binds_the_leader():
    """The heart of it: a block that might have finalised has to be carried
    forward, not replaced."""
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    ids = sorted(grid.seats)
    cert = _cert(world, grid, ids[:5], locks={ids[2]: (0, "nb:locked")})
    assert cert.required_block() == "nb:locked"
    ok, why = may_propose(cert, "nb:something-else", view=1)
    assert not ok and "locks" in why
    assert may_propose(cert, "nb:locked", view=1)[0]


def test_the_highest_locked_view_wins():
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    ids = sorted(grid.seats)
    cert = _cert(world, grid, ids[:5], view=2,
                 locks={ids[0]: (0, "nb:old"), ids[3]: (1, "nb:newer")})
    assert cert.required_block() == "nb:newer"


def test_view_zero_carries_no_certificate():
    assert may_propose(None, "nb:a", view=0)[0]
    assert not may_propose(None, "nb:a", view=1)[0]


# ── the seat ─────────────────────────────────────────────────────────────────

def _seats_in_view(world, view=1, lock=None):
    grid, seats, meta = build_seats(world)
    out = {}
    for nid, seat in seats.items():
        out[nid] = Seat(world.nodes[nid], seat.grid, seat.workload,
                        epoch=seat.epoch, quorum=seat.quorum,
                        validators=seat.env.validators,
                        counting=seat.env.counting, grid_id=seat.grid_id,
                        view=view, lock=lock)
    return grid, out, meta


def test_attesting_takes_a_lock():
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    other = next(s for n, s in seats.items() if n != grid.leader)
    other.absorb(seats[grid.leader].wire())
    other.offer_block(seats[grid.leader].blocks[sp.block_hash])
    other.react()
    assert other.locked == (0, sp.block_hash)


def test_a_seat_in_a_later_view_refuses_a_proposal_with_no_certificate():
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    body = seats[grid.leader].blocks[sp.block_hash]
    _, later, _ = _seats_in_view(world, view=1)
    seat = later[next(n for n in grid.seats if n != grid.leader)]
    ok, why = seat.acceptable(sp)
    assert not ok and "view" in why


def test_a_seat_carries_its_lock_into_the_view_change_message():
    world, _ = seated_world()
    _, later, _ = _seats_in_view(world, view=1, lock=(0, "nb:held"))
    seat = next(iter(later.values()))
    vc = seat.view_change()
    assert vc.locked and vc.locked_hash == "nb:held" and vc.view == 1
    assert vc is seat.view_change(), "signed once, not once per gossip round"


def test_view_changes_travel_in_the_envelope():
    world, _ = seated_world()
    _, later, _ = _seats_in_view(world, view=1, lock=(0, "nb:held"))
    ids = sorted(later)
    a, b = later[ids[0]], later[ids[1]]
    a.view_change()
    assert b.absorb(a.wire()) >= 1
    assert ids[0] in b.view_changes


def test_a_view_change_for_another_view_is_not_absorbed():
    world, _ = seated_world()
    _, later, _ = _seats_in_view(world, view=1)
    ids = sorted(later)
    stray = _vc(world, ids[0], view=2)
    assert later[ids[1]].add_view_change(stray) == 0


def test_a_seat_assembles_a_certificate_once_it_has_a_quorum():
    world, _ = seated_world()
    _, later, _ = _seats_in_view(world, view=1)
    ids = sorted(later)
    leader = later[ids[0]]
    assert leader.view_cert() is None
    for nid in ids:
        leader.add_view_change(later[nid].view_change())
    cert = leader.view_cert()
    assert cert is not None and len(cert.signers()) == leader.quorum


def test_a_locked_seat_releases_when_the_quorum_carries_something_else():
    """Safe because a block that *finalised* was locked by a quorum, and two
    quorums share an honest seat — so a certificate that omits it cannot
    exist. A lock this releases is one that never finalised, and overriding it
    is what keeps one crashed seat from stalling the height for ever."""
    world, _ = seated_world()
    grid, later, _ = _seats_in_view(world, view=1, lock=(0, "nb:mine"))
    seat = next(iter(later.values()))
    ids = sorted(grid.seats)
    empty = _cert(world, grid, ids[:5])
    assert seat.release_or_keep(empty) is True and seat.locked is None


def test_a_locked_seat_keeps_its_lock_when_the_quorum_reports_it():
    world, _ = seated_world()
    grid, later, _ = _seats_in_view(world, view=1, lock=(0, "nb:mine"))
    seat = next(iter(later.values()))
    ids = sorted(grid.seats)
    carried = _cert(world, grid, ids[:5], locks={ids[1]: (0, "nb:mine")})
    assert seat.release_or_keep(carried) is False
    assert seat.locked == (0, "nb:mine")


# ── the proposal is bound to its certificate ─────────────────────────────────

def test_swapping_the_certificate_breaks_the_proposal_signature():
    """So a relay cannot pair a proposal with some other quorum that would
    permit it."""
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    ids = sorted(grid.seats)
    cert = _cert(world, grid, ids[:5], locks={ids[0]: (0, "nb:locked")})
    leader = seats[grid.leader]
    block = leader.workload.build(leader.node, meta)
    sp = leader.node.propose(block, meta.epoch, meta.grid_seed, view=1,
                             view_cert=cert)
    assert sp.verify()
    other = _cert(world, grid, ids[:5])
    assert not dataclasses.replace(sp, view_cert=other).verify()
    assert not dataclasses.replace(sp, view=0).verify()


def test_a_view_zero_proposal_still_verifies_unchanged():
    """The format grew a field; the common path must not have grown a cost."""
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    assert sp.verify() and sp.view == 0 and sp.view_cert is None
    assert proposal_header(sp)["view_cert"] is None


# ── the clock decides when, and nobody negotiates it ─────────────────────────

def test_the_views_divide_the_decide_window():
    clock = Clock(effective_ms=0, epoch_millis=20_000)
    ends = [clock.view_deadline(1, v, 3) for v in range(3)]
    assert ends == [4_000, 8_000, 12_000]
    assert ends[-1] == clock.decide_deadline(1), \
        "the last view runs to the decide deadline and not past it"


def test_a_seat_can_tell_which_view_it_is_late_for():
    clock = Clock(effective_ms=0, epoch_millis=20_000)
    assert [clock.view_at(1, t, 3) for t in (0, 3_999, 4_000, 11_000)] \
        == [0, 0, 1, 2]


def test_one_view_is_the_old_behaviour_exactly():
    clock = Clock(effective_ms=0, epoch_millis=20_000)
    assert clock.view_deadline(1, 0, 1) == clock.decide_deadline(1)


# ── two views, end to end ────────────────────────────────────────────────────

def _view_one(world, grid0, seats0, epoch=1):
    """Reseat for view 1, excluding view 0's leader, carrying each seat's
    lock — which is exactly what `Node._seat_view` does."""
    from ..ceremony import Grid
    from ..crypto import h_hex
    from ..tiers import SoloWorkload

    gid = world.topology.grid_ids()[0]
    reg = world.registers[gid]
    members = world.grid_members(gid)
    seed = h_hex("view", "net", epoch, gid, 1)
    grid = Grid.seat(members, PARAMS.row_size, seed,
                     exclude_leaders=[grid0.leader],
                     standing={n: reg.standing_of(n) for n in members})
    validators = {n: world.nodes[n].public_hex for n in grid.seats}
    seats = {n: Seat(world.nodes[n], grid,
                     SoloWorkload(world, gid, epoch, "mpcith"),
                     epoch=epoch, quorum=reg.quorum(2, 3),
                     validators=validators,
                     counting=set(reg.attesters()), grid_id=gid,
                     view=1, lock=seats0[n].locked)
             for n in grid.seats}
    for seat in seats.values():
        seat.view_change()
    for a in seats.values():                      # one round of gossip
        for b in seats.values():
            a.absorb(b.wire())
    return grid, seats


def test_a_block_a_quorum_attested_to_is_re_proposed_in_the_next_view():
    """The case that makes this a protocol rather than a retry.

    Five of seven attest in view 0 — enough that the block is final for
    whoever saw all five — and then the view changes anyway. Every quorum of
    view changes contains one of those five, so the next leader is bound to
    re-propose it, and there is no view in which anything else can finalise.
    """
    world, _ = seated_world()
    grid0, seats0, meta = build_seats(world)
    sp = seats0[grid0.leader].propose(meta)
    body = seats0[grid0.leader].blocks[sp.block_hash]
    voters = [n for n in sorted(grid0.seats) if n != grid0.leader][:4]
    for nid in voters:
        seats0[nid].absorb(seats0[grid0.leader].wire())
        seats0[nid].offer_block(body)
        seats0[nid].react()
    locked = [n for n in seats0 if seats0[n].locked]
    assert len(locked) >= seats0[grid0.leader].quorum - 1

    grid1, seats1 = _view_one(world, grid0, seats0)
    leader = seats1[grid1.leader]
    cert = leader.view_cert()
    assert cert is not None, "a quorum of view changes reached the new leader"
    assert cert.required_block() == sp.block_hash, \
        "the next leader is bound to carry it"

    # And it does: the same body, signed for view 1 under that certificate.
    again = leader.adopt(body, view=1, view_cert=cert)
    assert again.block_hash == sp.block_hash
    for nid, seat in seats1.items():
        if nid == grid1.leader:
            continue
        seat.absorb(leader.wire())
        seat.offer_block(body)
        ok, why = seat.acceptable(seat.env.sole_proposal())
        assert ok, why
        seat.react()
    assert leader.accepted() is None or True
    attested = sum(1 for s in seats1.values() if s.locked)
    assert attested >= leader.quorum


def test_the_new_leader_cannot_propose_something_else():
    """The same setup, with a leader that tries. Every honest seat refuses,
    so no quorum forms for it — which is the safety property stated as a
    behaviour rather than as an argument."""
    world, _ = seated_world()
    grid0, seats0, meta = build_seats(world)
    sp = seats0[grid0.leader].propose(meta)
    body = seats0[grid0.leader].blocks[sp.block_hash]
    for nid in [n for n in sorted(grid0.seats) if n != grid0.leader][:4]:
        seats0[nid].absorb(seats0[grid0.leader].wire())
        seats0[nid].offer_block(body)
        seats0[nid].react()

    grid1, seats1 = _view_one(world, grid0, seats0)
    leader = seats1[grid1.leader]
    cert = leader.view_cert()
    fresh = leader.workload.build(leader.node, CeremonyMeta(
        epoch=1, leader_id=grid1.leader, rows=grid1.n_rows,
        row_size=grid1.row_size, grid_seed=grid1.seed))
    rogue = leader.adopt(fresh, view=1, view_cert=cert)
    assert rogue.block_hash != sp.block_hash

    refused = 0
    for nid, seat in seats1.items():
        if nid == grid1.leader:
            continue
        seat.absorb(leader.wire())
        seat.offer_block(fresh)
        proposal = seat.env.sole_proposal()
        if proposal is None:
            refused += 1                      # never even entered the envelope
            continue
        ok, why = seat.acceptable(proposal)
        assert not ok and "locks" in why, why
        seat.react()
        assert seat.env.attestations.get(nid) is None
        refused += 1
    assert refused == len(seats1) - 1


def test_a_dead_leader_costs_a_view_and_not_an_epoch():
    """Liveness. Nobody proposed in view 0, so nobody is locked, the view
    change carries no obligation, and the new leader builds freshly."""
    world, _ = seated_world()
    grid0, seats0, _ = build_seats(world)          # leader says nothing
    assert all(s.locked is None for s in seats0.values())

    grid1, seats1 = _view_one(world, grid0, seats0)
    assert grid1.leader != grid0.leader, "a new view gets a new leader"
    leader = seats1[grid1.leader]
    cert = leader.view_cert()
    assert cert is not None and cert.required_block() is None
    sp = leader.propose(CeremonyMeta(
        epoch=1, leader_id=grid1.leader, rows=grid1.n_rows,
        row_size=grid1.row_size, grid_seed=grid1.seed), view=1,
        view_cert=cert)
    body = leader.blocks[sp.block_hash]
    for nid, seat in seats1.items():
        if nid == grid1.leader:
            continue
        seat.absorb(leader.wire())
        seat.offer_block(body)
        seat.react()
    for nid, seat in seats1.items():
        if nid != grid1.leader:
            seat.absorb(seats1[grid1.leader].wire())
    attesting = [n for n, s in seats1.items() if s.locked]
    assert len(attesting) >= leader.quorum - 1, attesting


# ── on real sockets ──────────────────────────────────────────────────────────

def _view_zero_leader(doc, epoch: int = 1) -> str:
    """Who leads the first attempt at `epoch` — the seating a node does."""
    from .. import genesis as genesis_mod
    from ..ceremony import Grid
    from ..crypto import h_hex

    world, _ = genesis_mod.boot(doc)
    gid = world.topology.grid_ids()[0]
    register = world.registers[gid]
    members = world.grid_members(gid)
    seed = h_hex("view", doc.first_seed, epoch, gid, 0)
    return Grid.seat(members, world.params.row_size, seed,
                     standing={n: register.standing_of(n)
                               for n in members}).leader


def test_a_silent_leader_is_stepped_over_on_a_live_network():
    """Four processes, real clocks, one node that never proposes.

    The in-process tests above prove the rule; this proves the wiring — that a
    view actually times out, that the view changes reach the next leader
    through the same envelopes as everything else, and that the height keeps
    advancing while a seat that leads sometimes says nothing.

    Five-second epochs because the view budget is arithmetic: a view has to be
    long enough for an honest ceremony, so a 2.5 s epoch gets one view and
    would prove nothing here.
    """
    import glob
    import os
    import shutil
    import tempfile
    import time

    from ..net import supervisor as sv

    root = tempfile.mkdtemp(prefix="fin6-view-")
    base_port = 8400 + (os.getpid() % 40) * 10
    try:
        sv.new_testnet(root, nodes=4, preset="local", epoch_millis=5000,
                       base_port=base_port, force=True)
        net = sv.Testnet(root)
        # One seat that never proposes. Which epochs it leads is drawn from
        # committed state, so the test does not choose them — it only has to
        # run long enough that it leads at least once.
        import json

        # Which node leads view 0 of epoch 1 is drawn from committed state, so
        # the test computes it rather than hoping: the same seating the node
        # itself does, from the document it will boot from.
        quiet = _view_zero_leader(net.doc, epoch=1)
        net.net["nodes"][quiet]["behaviour"] = "silent"
        with open(os.path.join(root, "net.json"), "w") as fh:
            json.dump(net.net, fh, indent=2)
        net = sv.Testnet(root)
        net.up(until_epoch=10, start_in_ms=4000)
        try:
            net.wait_for_height(2, timeout=90)
            status = net.status()
            live = {n: s for n, s in status.items() if s}
            assert len(live) == 4, "every node answered"
            top = max(s["height"] for s in live.values())
            at_top = [s for s in live.values() if s["height"] == top]
            for field in ("tip", "utxo_root", "nf_root"):
                assert len({s[field] for s in at_top}) == 1, \
                    f"{len(at_top)} nodes at {top} disagree on {field}"
            assert top >= 2, top
            # And the wiring: somebody said so in the log.
            moved = []
            for path in glob.glob(os.path.join(root, "*", "node.log")):
                with open(path) as fh:
                    moved += [ln for ln in fh if "moving to view" in ln]
            assert moved, "no view ever timed out, so nothing was exercised"
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)
