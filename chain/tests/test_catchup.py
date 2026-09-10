"""A way back for a node that fell behind.

Part six called this the largest missing piece, and the reason is arithmetic
rather than cryptography: seven nodes tolerate two faults, a restart or a
pause spends one, and until now it spent it *permanently* — a node that missed
an epoch could not obtain the block it missed, so it never attested again.
Three such events in the life of a network ended it, with nobody attacking.

The unit tests here are about the walk forward and the window; the process
test at the bottom is the one that matters, because it kills a node.
"""
import os
import shutil
import tempfile
import time

from ..net import supervisor as sv
from ..net.catchup import BATCH, BodyCache, Catchup


class _Body:
    """A stand-in block: the buffer and the cache only ever ask for a height,
    a hash, and whether it carries a certificate."""

    def __init__(self, height, tag="", certified=True):
        self.height = height
        self.tag = tag
        self.quorum_cert = object() if certified else None

    def hash(self):
        return f"nb:{self.height}{self.tag}"


# ── knowing that you are behind ──────────────────────────────────────────────

def test_a_node_that_is_level_wants_nothing():
    c = Catchup()
    c.note_height(5)
    assert c.behind(5) == 0
    assert c.wanted(5) is None
    assert c.requests == 0, "and does not go asking"


def test_a_node_that_is_behind_asks_for_the_run_it_is_missing():
    c = Catchup()
    c.note_height(9)
    assert c.behind(3) == 6
    assert c.wanted(3) == (4, 9)


def test_the_request_is_bounded_by_the_batch():
    c = Catchup(batch=3)
    c.note_height(100)
    assert c.wanted(10) == (11, 13)


def test_it_does_not_ask_for_what_it_already_holds():
    c = Catchup()
    c.note_height(9)
    c.absorb([_Body(4), _Body(5)])
    assert c.wanted(3) == (6, 9), "the front of the run is already buffered"


def test_a_target_only_ever_moves_forward():
    c = Catchup()
    c.note_height(9)
    c.note_height(4)
    assert c.target == 9


# ── the walk forward ─────────────────────────────────────────────────────────

def _walker(start=0, refuse_at=None):
    """A fake node: applies blocks in order and reports its height."""
    state = {"height": start, "applied": []}

    def height_of():
        return state["height"]

    def apply_one(block):
        if refuse_at is not None and block.height == refuse_at:
            return False, "refused on purpose"
        state["height"] = block.height
        state["applied"].append(block.height)
        return True, "ok"

    return state, apply_one, height_of


def test_blocks_are_applied_in_order_however_they_arrive():
    c = Catchup()
    c.absorb([_Body(3), _Body(1), _Body(2)])
    state, apply_one, height_of = _walker()
    assert c.advance(apply_one, height_of) == 3
    assert state["applied"] == [1, 2, 3]
    assert c.blocks == {}, "and nothing is left buffered"


def test_a_gap_stops_the_walk_without_being_an_error():
    c = Catchup()
    c.absorb([_Body(1), _Body(3)])            # 2 never arrived
    state, apply_one, height_of = _walker()
    assert c.advance(apply_one, height_of) == 1
    assert state["applied"] == [1]
    assert 3 in c.blocks, "the far side of the gap waits"
    assert c.refused == 0


def test_a_block_that_will_not_apply_is_dropped_not_retried():
    """It will not validate on the next pass either, and keeping it would
    block the height for ever.  Asking again is cheap."""
    c = Catchup()
    c.absorb([_Body(1), _Body(2), _Body(3)])
    state, apply_one, height_of = _walker(refuse_at=2)
    assert c.advance(apply_one, height_of) == 1
    assert c.refused == 1 and "refused on purpose" in c.last_reason
    assert 2 not in c.blocks
    assert 3 in c.blocks


def test_the_walk_stops_when_the_budget_says_so():
    """Catching up is expensive, and a node that spends a whole epoch on it
    has swapped one way of being absent for another."""
    c = Catchup()
    c.absorb([_Body(h) for h in range(1, 6)])
    state, apply_one, height_of = _walker()
    allowed = [True, True, False, False, False]
    assert c.advance(apply_one, height_of,
                     budget=lambda: allowed.pop(0)) == 2
    assert state["applied"] == [1, 2]
    assert len(c.blocks) == 3, "the rest is still there for the next epoch"


def test_applied_blocks_are_forgotten():
    c = Catchup()
    c.absorb([_Body(h) for h in range(1, 4)])
    state, apply_one, height_of = _walker(start=5)   # already past them all
    c.advance(apply_one, height_of)
    assert c.blocks == {}


# ── the window a peer can help across ────────────────────────────────────────

def test_the_body_cache_keeps_the_window_and_no_more():
    cache = BodyCache(window=4)
    for h in range(1, 10):
        cache.put(_Body(h))
    assert len(cache) == 4
    assert cache.at(9) is not None and cache.at(6) is not None
    assert cache.at(5) is None, "and forgets the oldest first"


def test_the_body_cache_answers_by_height_and_by_hash():
    cache = BodyCache(window=8)
    body = _Body(3)
    cache.put(body)
    assert cache.at(3) is body
    assert cache.get("nb:3") is body
    assert "nb:3" in cache
    assert cache.at(4) is None and cache.get("nope") is None


def test_a_range_is_what_is_held_of_it():
    cache = BodyCache(window=8)
    for h in (1, 2, 4, 5):
        cache.put(_Body(h))
    got = [b.height for b in cache.range(1, 5)]
    assert got == [1, 2, 4, 5], "a hole is skipped rather than refused"
    assert len(cache.range(1, 100, limit=2)) == 2


def test_only_certified_bodies_are_offered_for_catch_up():
    """A body is cached twice in an epoch: once as the leader's proposal,
    which has nothing to certify yet, and once finalised.  Serving the first
    to a node catching up wastes a round trip on both sides, because it has no
    way to check it and will refuse it."""
    cache = BodyCache(window=8)
    cache.put(_Body(1, certified=False))
    assert cache.range(1, 1) == [], "a proposal is not history"
    assert cache.at(1) is not None, "but it is still there for a hash fetch"
    assert cache.range(1, 1, certified_only=False), "which is what that is for"


def test_a_certified_body_is_never_replaced_by_a_bare_one():
    """The bug this method exists for.  `Seat.accepted` attaches the
    certificate by setting it in place on the object the cache happened to
    hold, so the cache was correct by aliasing — and wrong the moment a body
    arrived by a path that did not alias.  Peers then served pre-agreement
    proposals to a node catching up, which refused every one of them."""
    cache = BodyCache(window=8)
    cache.put(_Body(4, certified=True))
    cache.put(_Body(4, certified=False))
    assert cache.range(4, 4), "the certified copy was downgraded"


def test_putting_the_same_block_twice_costs_nothing():
    cache = BodyCache(window=4)
    cache.put(_Body(1))
    cache.put(_Body(1))
    assert len(cache) == 1


def test_the_window_is_stated_rather_than_left_to_memory():
    """`self.bodies` was an unbounded dict appended to on every block a node
    saw.  How far back a peer could be helped was therefore however much
    memory had leaked, which is not a design."""
    from ..net.catchup import BODY_WINDOW
    assert BODY_WINDOW >= BATCH, "a window smaller than a batch cannot help"
    assert BodyCache().window == BODY_WINDOW


# ── and with four processes, one of them killed ───────────────────────────────

def test_a_killed_node_comes_back_and_catches_up():
    """The one that matters.

    Before this, `kill -9` on one of four nodes was permanent: the survivor
    restarted, found its height behind, and could not fetch the block it had
    missed because `getblock` only took a hash it did not have. It sat there
    with a live socket and a dead seat, and the network was one straggler from
    a stall for the rest of its life.
    """
    root = tempfile.mkdtemp(prefix="fin6-catchup-")
    base_port = 8100 + (os.getpid() % 40) * 10
    try:
        sv.new_testnet(root, nodes=4, preset="local", epoch_millis=2500,
                       base_port=base_port, force=True)
        net = sv.Testnet(root)
        net.up(start_in_ms=4000)
        try:
            net.wait_for_height(2, timeout=75)
            victim = sorted(net.net["nodes"])[3]
            assert net.kill(victim), "the victim was not running"
            fell_at = max(s["height"] for s in net.status().values() if s)

            # The others must keep going, and get far enough ahead that the
            # gap is real rather than a rounding error on the clock.
            net.wait_for_height(fell_at + 3, timeout=75,
                               quorum=3)
            ahead = max(s["height"] for s in net.status().values() if s)
            assert ahead >= fell_at + 3, (ahead, fell_at)

            net.start(victim)
            deadline = time.time() + 75
            caught = None
            while time.time() < deadline:
                time.sleep(1.5)
                status = net.status()
                mine = status.get(victim)
                if mine and mine["height"] >= ahead:
                    caught = mine
                    break
            assert caught is not None, (
                f"{victim} never caught up: "
                f"{net.status().get(victim, {}).get('height')} against {ahead}")
            assert caught["catchup"]["applied"] > 0, \
                "it reached the height without ever catching up, which means "\
                "this test is not testing anything"

            # And it is the same chain, not merely the same number.
            ok, height, detail = net.agreement()
            assert ok, detail
            live = [s for s in net.status().values() if s]
            assert len(live) == 4
            assert len({s["tip"] for s in live}) == 1
            assert len({s["utxo_root"] for s in live}) == 1
            assert len({s["registers_root"] for s in live}) == 1
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_paused_node_catches_up_when_it_is_let_go():
    """The other half of the fault table.

    A kill exercises the restore path as well; a pause leaves every byte of
    in-memory state intact and only moves the clock, which is the narrower and
    more common fault — a long GC, a suspended laptop, a container throttled
    by its host. It has to end the same way.
    """
    root = tempfile.mkdtemp(prefix="fin6-paused-")
    base_port = 8500 + (os.getpid() % 40) * 10
    try:
        sv.new_testnet(root, nodes=4, preset="local", epoch_millis=2500,
                       base_port=base_port, force=True)
        net = sv.Testnet(root)
        net.up(start_in_ms=4000)
        try:
            net.wait_for_height(2, timeout=75)
            victim = sorted(net.net["nodes"])[3]
            assert net.pause(victim)
            stalled = max(s["height"] for s in net.status().values() if s)
            net.wait_for_height(stalled + 3, timeout=75, quorum=3)
            ahead = max(s["height"] for s in net.status().values() if s)
            assert net.pause(victim, resume=True)

            deadline = time.time() + 75
            while time.time() < deadline:
                time.sleep(1.5)
                mine = net.status().get(victim)
                if mine and mine["height"] >= ahead:
                    break
            ok, height, detail = net.agreement()
            assert ok, detail
            live = [s for s in net.status().values() if s]
            assert len(live) == 4 and len({s["tip"] for s in live}) == 1
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)
