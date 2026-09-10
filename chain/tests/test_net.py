"""The network layer: frames, the clock, a seat, and seven real processes.

The last test starts actual node processes and waits for them to agree. It is
the slowest thing in the suite and the only one that can catch what the
simulation cannot, which is the trade this whole part exists to make.
"""
import dataclasses
import os
import shutil
import tempfile

from ..block import CeremonyMeta
from ..ceremony import Grid
from ..crypto import h_hex
from ..hardening.params import LOCAL as LOCAL_HARDENING
from ..net import supervisor as sv
from ..net.clock import Clock, parse_time
from ..net.frame import (CLIENT_MAX_FRAME, FrameError, MAX_FRAME, SKIPPED,
                         Reader, pack, unpack)
from ..net.seat import Seat, proposal_header
from ..network import transfer
from ..params import DEMO, LOCAL
from ..tiers import SoloWorkload, bootstrap_world

CHAIN = "fin6:" + "ab" * 32
PARAMS = dataclasses.replace(DEMO, attend_threshold=2, grid_size=7, row_size=5,
                             proof_backends=("mpcith",),
                             proof_policy=(("local", "mpcith"),))


# ── frames ───────────────────────────────────────────────────────────────────

def test_a_frame_round_trips():
    blob = pack("env", CHAIN, {"proposals": [], "attestations": []}, epoch=4)
    got = list(Reader(CHAIN).feed(blob))
    assert len(got) == 1
    assert got[0]["kind"] == "env" and got[0]["epoch"] == 4


def test_frames_survive_being_split_and_batched():
    blob = b"".join(pack(k, CHAIN, {"n": i})
                    for i, k in enumerate(("hello", "tx", "env")))
    reader = Reader(CHAIN)
    seen = []
    for i in range(0, len(blob), 7):
        seen += list(reader.feed(blob[i:i + 7]))
    assert [m["kind"] for m in seen] == ["hello", "tx", "env"]


def test_a_frame_for_another_chain_is_refused():
    """chain_id is the hash of the genesis document, so this catches a node
    pointed at the wrong network on its first frame."""
    blob = pack("hello", CHAIN, {"node_id": "n1"})
    try:
        list(Reader("fin6:" + "cd" * 32).feed(blob))
    except FrameError as exc:
        assert "is for chain" in str(exc)
        return
    raise AssertionError("accepted a frame from another chain")


def test_rubbish_is_refused_rather_than_parsed():
    for bad in (b"XX\x01\x05hello", b"\x00" * 32):
        try:
            list(Reader(CHAIN).feed(bad))
        except FrameError:
            continue
        raise AssertionError(f"parsed {bad!r}")


def test_an_oversized_frame_is_refused_before_it_is_read():
    from ..store import codec
    head = bytearray(b"F6")
    head.append(1)
    codec.put_uint(head, MAX_FRAME + 1)
    try:
        list(Reader(CHAIN).feed(bytes(head)))
    except FrameError as exc:
        assert "announced" in str(exc)
        return
    raise AssertionError("accepted an oversized announcement")


def test_the_gate_sees_a_frame_before_it_is_decoded():
    """Part nine's fourth item. `feed` used to decode the body and the limiter
    was asked afterwards, so the expensive part was already paid — 45 ms per
    megabyte, 357 ms at the 8 MB ceiling. The gate is consulted once the body
    has arrived and before it is parsed."""
    seen = []

    def gate(nbytes):
        seen.append(nbytes)
        return True

    reader = Reader(CHAIN, gate=gate)
    blob = pack("status", CHAIN, {"a": 1})
    frames = list(reader.feed(blob))
    assert len(frames) == 1 and seen and seen[0] < len(blob)


def test_a_frame_the_gate_refuses_is_never_parsed():
    """And it is discarded rather than closing the connection: being over
    budget is not a protocol violation, unlike being over the ceiling."""
    from ..store import codec
    reader = Reader(CHAIN, gate=lambda n: False)
    # Deliberately undecodable: if the gate did not stop it, `unpack` would
    # raise rather than return, and that is the assertion.
    body = b"not a codec frame at all"
    head = bytearray(b"F6")
    head.append(1)
    codec.put_uint(head, len(body))
    assert list(reader.feed(bytes(head) + body)) == []
    assert reader.skipped == 1
    # and the stream is still usable: the skipped bytes were consumed exactly
    assert list(reader.feed(pack("status", CHAIN, None))) == []
    assert reader.skipped == 2


def test_an_unauthenticated_connection_gets_the_smaller_ceiling():
    """8 MB is for a block body, and nothing a wallet sends is a block."""
    assert CLIENT_MAX_FRAME < MAX_FRAME
    from ..store import codec
    reader = Reader(CHAIN, max_frame=CLIENT_MAX_FRAME)
    head = bytearray(b"F6")
    head.append(1)
    codec.put_uint(head, CLIENT_MAX_FRAME + 1)
    try:
        list(reader.feed(bytes(head)))
    except FrameError as exc:
        assert "announced" in str(exc), exc
    else:
        raise AssertionError("an oversized client frame was accepted")


def test_a_three_backend_submission_still_fits_a_client_frame():
    """The ceiling has to clear the largest legitimate client frame: a
    submission carrying all three backends' proofs, measured at 568 KB."""
    assert CLIENT_MAX_FRAME > 600 * 1024


def test_unknown_kinds_are_refused():
    from ..store import codec
    body = codec.encode({"kind": "mystery", "chain_id": CHAIN, "epoch": 1,
                         "payload": None})
    try:
        unpack(body, CHAIN)
    except FrameError:
        return
    raise AssertionError("accepted an unknown kind")


# ── the clock ────────────────────────────────────────────────────────────────

def test_the_epoch_is_computed_not_told():
    clock = Clock(effective_ms=10_000, epoch_millis=5_000)
    assert clock.epoch_at(9_999) == 0
    assert clock.epoch_at(10_000) == 1
    assert clock.epoch_at(14_999) == 1
    assert clock.epoch_at(15_000) == 2
    assert clock.start_of(3) == 20_000
    assert clock.decide_deadline(3) == 23_000
    assert clock.commit_deadline(3) == 24_000


def test_skew_moves_a_node_and_nothing_else():
    a = Clock(effective_ms=0, epoch_millis=1_000)
    b = Clock(effective_ms=0, epoch_millis=1_000, skew_ms=5_000)
    assert b.now_ms() - a.now_ms() >= 4_900
    assert a.start_of(7) == b.start_of(7), "the schedule is shared"


def test_rfc3339_parses():
    assert parse_time("1970-01-01T00:00:01Z") == 1000


# ── a seat ───────────────────────────────────────────────────────────────────

def seated_world(n=7):
    regions = {f"n{i:02d}": "genesis" for i in range(n)}
    world, wallets = bootstrap_world(
        regions, {"alice": [1000, 900], "bob": [100]}, PARAMS,
        note_seed="test-net")
    return world, wallets


def build_seats(world, epoch=1):
    gid = world.topology.grid_ids()[0]
    reg = world.registers[gid]
    members = world.grid_members(gid)
    seed = h_hex("view", "net", epoch, gid, 0)
    grid = Grid.seat(members, PARAMS.row_size, seed,
                     standing={n: reg.standing_of(n) for n in members})
    validators = {n: world.nodes[n].public_hex for n in grid.seats}
    seats = {n: Seat(world.nodes[n], grid,
                     SoloWorkload(world, gid, epoch, "mpcith"),
                     epoch=epoch, quorum=reg.quorum(2, 3), validators=validators,
                     counting=set(reg.attesters()), grid_id=gid)
             for n in grid.seats}
    meta = CeremonyMeta(epoch=epoch, leader_id=grid.leader, rows=grid.n_rows,
                        row_size=grid.row_size, grid_seed=seed)
    return grid, seats, meta


def test_the_leader_has_neighbours():
    """`Grid.neighbours` is one-directional and returns nothing for the leader,
    which is alone in row 0 — so a node driving its own side of the ceremony
    has to read the adjacency instead. The lockstep ceremony never noticed
    because it exchanges over the undirected edge list."""
    world, _ = seated_world()
    grid, seats, _ = build_seats(world)
    assert grid.neighbours(grid.leader) == ()
    assert seats[grid.leader].neighbours(), "the leader must be able to speak"


def test_seats_converge_by_exchanging_messages():
    world, wallets = seated_world()
    tx, _ = transfer(wallets["alice"], wallets["bob"], 100, 5, PARAMS)
    world.submit(tx)
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    bodies = {sp.block_hash: seats[grid.leader].blocks[sp.block_hash]}

    for _ in range(2 * grid.diameter() + 1):
        snapshot = {n: s.wire() for n, s in seats.items()}
        for a, b in grid.edges():
            seats[a].absorb(snapshot[b])
            seats[b].absorb(snapshot[a])
        for seat in seats.values():
            for digest in seat.missing():
                if digest in bodies:
                    seat.offer_block(bodies[digest])
            seat.react()
        if all(s.accepted() for s in seats.values()):
            break
    blocks = [s.accepted()[0] for s in seats.values() if s.accepted()]
    assert len(blocks) == len(seats), {n: s.why_not() for n, s in seats.items()}
    assert len({b.hash() for b in blocks}) == 1
    assert blocks[0].header.tiers == 1


def test_an_envelope_never_carries_a_block():
    """132 messages an epoch times 542 KB is 71 MB; the header is two."""
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    wire = seats[grid.leader].wire()
    assert wire["proposals"] and set(wire["proposals"][0]) == {
        "leader_id", "public_hex", "epoch", "grid_seed", "signature",
        "height", "block_hash"}
    from ..store import codec
    assert len(codec.encode(wire)) < 4096


def test_a_header_without_its_body_does_not_enter_the_envelope():
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    other = next(s for n, s in seats.items() if n != grid.leader)
    assert other.absorb({"proposals": [proposal_header(sp)]}) == 1
    assert other.missing() == [sp.block_hash]
    assert not other.env.proposals, "no body, no proposal"
    body = seats[grid.leader].blocks[sp.block_hash]
    assert other.offer_block(body)
    assert sp.block_hash in other.env.proposals


def test_a_body_that_is_not_the_one_signed_for_is_refused():
    """The signature covers the hash, so a header pins exactly one body."""
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    other = next(s for n, s in seats.items() if n != grid.leader)
    other.absorb({"proposals": [proposal_header(sp)]})

    class NotTheBlock:
        def hash(self):
            return "nb:" + "00" * 32

    assert not other.offer_block(NotTheBlock())
    assert other.missing() == [sp.block_hash], "still waiting for the real one"


def test_a_forged_header_is_ignored():
    world, _ = seated_world()
    grid, seats, meta = build_seats(world)
    sp = seats[grid.leader].propose(meta)
    other = next(s for n, s in seats.items() if n != grid.leader)
    forged = proposal_header(sp)
    forged["block_hash"] = "nb:" + "11" * 32
    assert other.absorb({"proposals": [forged]}) == 0
    assert other.missing() == []


# ── presets ──────────────────────────────────────────────────────────────────

def test_the_local_presets_fit_on_a_laptop():
    assert LOCAL.proof_backends == ("mpcith",), "one proof, not three"
    assert LOCAL_HARDENING.tree_height == 10, "2^17 leaves is 117 s per node"
    assert abs(LOCAL_HARDENING.block_interval - 5.0) < 0.01
    assert LOCAL_HARDENING.blocks_per_era == 125
    assert LOCAL_HARDENING.max_fork_depth(2 / 7) == 35


def test_the_height_is_not_the_epoch():
    """An epoch whose leader is dead makes no block, so the clock advances and
    the chain does not. A seat that used one number for both rejected the
    leader's proposal — including the leader rejecting its own."""
    world, _ = seated_world()
    grid, seats, meta = build_seats(world, epoch=1)
    gid = world.topology.grid_ids()[0]
    reg = world.registers[gid]
    late = Seat(world.nodes[grid.leader], grid,
                SoloWorkload(world, gid, 9, "mpcith"),
                epoch=9, height=world.height + 1, quorum=reg.quorum(2, 3),
                validators={n: world.nodes[n].public_hex for n in grid.seats},
                counting=set(reg.attesters()), grid_id=gid)
    assert late.height == 1 and late.epoch == 9
    sp = late.propose(CeremonyMeta(epoch=9, leader_id=grid.leader,
                                   rows=grid.n_rows, row_size=grid.row_size,
                                   grid_seed=grid.seed))
    assert sp.block_hash in late.env.proposals, \
        "a leader must be able to accept its own proposal after a missed epoch"


# ── seven processes ──────────────────────────────────────────────────────────

def test_a_real_network_reaches_agreement():
    """The whole point. Four processes, real sockets, real clocks."""
    root = tempfile.mkdtemp(prefix="fin6-testnet-")
    # A fresh port range each run: a previous run's sockets linger in TIME_WAIT
    # long enough to make a fixed range flaky.
    base_port = 7800 + (os.getpid() % 60) * 10
    try:
        sv.new_testnet(root, nodes=4, preset="local", epoch_millis=2500,
                       base_port=base_port, force=True)
        net = sv.Testnet(root)
        # Every node must be listening before epoch 1 opens; booting one costs
        # about a second (genesis, store, dialling).
        net.up(until_epoch=8, start_in_ms=4000)
        try:
            status = net.wait_for_height(2, timeout=75)
            ok, height, detail = net.agreement(status)
            assert ok, sv.render_status(status, (ok, height, detail))
            assert height >= 2, detail
            live = [s for s in status.values() if s]
            assert len(live) == 4, "every node answered"
            assert len({s["tip"] for s in live}) == 1
            assert len({s["utxo_root"] for s in live}) == 1
            assert len({s["registers_root"] for s in live}) == 1
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)
