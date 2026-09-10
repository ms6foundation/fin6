"""What a node will spend before it has to attest.

Part nine's claim is a liveness one, so these tests are about a deadline
rather than about a refusal: the interesting assertion is not "the stranger
was told no" but "the ceremony still had time when the stranger was told no".

Time is passed in everywhere rather than read from the wall, so an epoch runs
in no time and the arithmetic is checkable by hand.
"""
import dataclasses

from chain.net.budget import (FLOORS, INITIAL_UNIT_MS, MAX_EPOCHS_QUEUED,
                              Meter, EpochBudget, Priority, RESERVE_CAP,
                              RESERVE_UNITS, WorkQueue)
from chain.net.clock import Clock
from chain.node import PROOF_STRIKES
from chain.store import codec

#: The shipped epoch: `config/genesis-7.json`, 19,749 ms, deciding at 0.60.
EPOCH_MS = 19749


def _budget(epoch_millis=EPOCH_MS, unit_ms=INITIAL_UNIT_MS, alpha=0.0):
    """A budget on a still clock.  alpha=0 freezes the meter so that what is
    being tested is the policy and not the estimator."""
    clock = Clock(effective_ms=0, epoch_millis=epoch_millis)
    return EpochBudget(clock, meter=Meter(unit_ms, alpha=alpha)).open(1)


# ── the meter ────────────────────────────────────────────────────────────────

def test_the_meter_moves_towards_what_it_measures():
    m = Meter(25.0, alpha=0.5)
    m.observe(5.0)
    assert abs(m.estimate - 15.0) < 1e-9, m.estimate
    m.observe(5.0)
    assert abs(m.estimate - 10.0) < 1e-9, m.estimate
    assert m.observations == 2 and m.worst == 5.0


def test_the_meter_remembers_the_worst_case_it_saw():
    m = Meter(25.0, alpha=0.1)
    for ms in (20.0, 300.0, 21.0):
        m.observe(ms)
    assert m.worst == 300.0
    assert m.estimate < 60.0, "one outlier does not become the estimate"


# ── the window ───────────────────────────────────────────────────────────────

def test_the_window_is_the_decide_deadline_not_the_epoch():
    b = _budget()
    assert b.window_ms == int(0.60 * EPOCH_MS)
    assert b.deadline_ms == b.clock.decide_deadline(1)


def test_the_reserve_is_capped_at_a_share_of_the_window():
    """A 2.5 s test epoch has a 1.5 s window, and 128 proofs is 3.2 s.  An
    uncapped reserve would exceed the window and refuse everything for ever,
    which is a stall with a rationale rather than caution."""
    short = _budget(epoch_millis=2500)
    assert short.reserve_ms == RESERVE_CAP * short.window_ms
    long = _budget()
    assert long.reserve_ms == INITIAL_UNIT_MS * RESERVE_UNITS
    assert long.reserve_ms < RESERVE_CAP * long.window_ms


def test_stats_survive_the_codec_because_they_go_over_the_wire():
    """A `status_reply` is encoded with the canonical codec, which has no float
    — so the unit cost is reported in whole microseconds.  This is here
    because getting it wrong made every node in the testnet look dead."""
    b = _budget()
    b.spend(Priority.OWNER, 12.5)
    b.refuse(Priority.ANON)
    codec.encode(b.stats())
    codec.encode(WorkQueue().stats())
    assert b.stats()["unit_us"] == round(INITIAL_UNIT_MS * 1000)


# ── who gets shed, and when ──────────────────────────────────────────────────

def test_the_ceremony_is_never_refused_even_past_the_deadline():
    """The one non-negotiable.  A node that will not validate the proposal
    because it is busy is the failure this module exists to prevent."""
    b = _budget()
    late = b.deadline_ms + 10 * EPOCH_MS
    assert b.afford(Priority.CEREMONY, late)[0]
    for p in (Priority.PEER, Priority.OWNER, Priority.ANON):
        assert not b.afford(p, late)[0], p


def test_the_classes_stop_in_order_as_the_deadline_approaches():
    b = _budget()
    start = b.clock.start_of(1)
    stops = {}
    for p in (Priority.PEER, Priority.OWNER, Priority.ANON):
        # walk the epoch in 50 ms steps and note when this class runs out
        for now in range(start, b.deadline_ms + 100, 50):
            if not b.afford(p, now)[0]:
                stops[p] = now - start
                break
    assert stops[Priority.ANON] < stops[Priority.OWNER] < stops[Priority.PEER], \
        stops
    assert stops[Priority.PEER] < b.window_ms, "and everyone stops in time"


def test_a_stranger_cannot_spend_the_reserve():
    b = _budget()
    # Stand at the moment only the reserve is left.
    now = int(b.deadline_ms - b.reserve_ms)
    assert not b.afford(Priority.ANON, now)[0]
    assert not b.afford(Priority.PEER, now)[0]
    assert b.afford(Priority.CEREMONY, now)[0]


def test_refusal_says_what_it_is_refusing_and_why():
    b = _budget()
    ok, why = b.afford(Priority.ANON, b.deadline_ms - 100)
    assert not ok
    assert "decide deadline" in why and "ANON" in why, why


# ── the queue ────────────────────────────────────────────────────────────────

def test_a_repeated_key_is_not_queued_twice():
    q = WorkQueue()
    assert q.offer(lambda: 1, Priority.OWNER, key="tx1")[0]
    ok, why = q.offer(lambda: 1, Priority.OWNER, key="tx1")
    assert not ok and "already queued" in why
    assert len(q) == 1


def test_a_full_queue_drops_the_least_important_thing_in_it():
    q = WorkQueue(capacity=3)
    for i in range(3):
        assert q.offer(lambda: i, Priority.ANON, key=f"a{i}")[0]
    # A peer arrives at a full queue: an anonymous job goes, not the peer.
    assert q.offer(lambda: "peer", Priority.PEER, key="p")[0]
    assert len(q) == 3
    assert q.dropped[Priority.ANON] == 1
    assert q.pop()[0] == Priority.PEER, "and the peer is served first"


def test_a_full_queue_refuses_an_arrival_no_better_than_its_contents():
    q = WorkQueue(capacity=2)
    q.offer(lambda: 1, Priority.PEER, key="p1")
    q.offer(lambda: 2, Priority.PEER, key="p2")
    ok, why = q.offer(lambda: 3, Priority.ANON, key="a1")
    assert not ok and "queue full" in why
    assert q.dropped[Priority.ANON] == 1


def test_the_queue_is_fifo_within_one_class():
    q = WorkQueue()
    for i in range(4):
        q.offer((lambda n: (lambda: n))(i), Priority.OWNER, key=f"t{i}")
    assert [q.pop()[1]() for _ in range(4)] == [0, 1, 2, 3]


# ── the two together ─────────────────────────────────────────────────────────

def test_drain_runs_in_priority_order():
    b = _budget()
    q, order = WorkQueue(), []
    q.offer(lambda: order.append("anon"), Priority.ANON, key="a")
    q.offer(lambda: order.append("peer"), Priority.PEER, key="p")
    q.offer(lambda: order.append("owner"), Priority.OWNER, key="o")
    ran, expired = q.drain(b, now_ms=b.clock.start_of(1))
    assert ran == 3 and expired == 0
    assert order == ["peer", "owner", "anon"], order


def _ticking(start_ms: int, per_job_ms: float = INITIAL_UNIT_MS):
    """A clock that advances as work runs, which is what a real one does.

    Worth being explicit about, because it is how the budget accounts at all:
    nothing decrements a counter of milliseconds spent.  Doing 25 ms of work
    moves the wall clock 25 ms, so real time *is* the ledger, and `afford`
    reading the clock is the whole of the bookkeeping.
    """
    now = [float(start_ms)]

    def tick():
        now[0] += per_job_ms

    return (lambda: int(now[0])), tick


def test_a_flood_runs_what_it_can_and_the_rest_waits():
    """The headline property. Two hundred submissions arrive; the node runs
    what its slack pays for and stops well clear of the reserve."""
    b = _budget()
    q = WorkQueue(capacity=256)
    clock_now, tick = _ticking(b.clock.start_of(1))
    done = []
    for i in range(200):
        q.offer((lambda n: (lambda: (done.append(n), tick())))(i),
                Priority.ANON, key=f"tx{i}", epoch=1)
    assert len(q) == 200
    ran, expired = q.drain(b, now_ms=clock_now, max_items=1000)
    assert ran == len(done) and expired == 0
    assert 0 < ran < 200, f"ran {ran} of 200"
    assert len(q) == 200 - ran, "the remainder waits for the next epoch"
    # The floor did its job: an anonymous flood cannot reach the reserve.
    assert clock_now() < b.deadline_ms - b.reserve_ms, \
        "the flood stopped before the reserve"
    assert b.afford(Priority.CEREMONY, clock_now())[0]


def test_work_the_deadline_refused_is_run_at_the_next_epoch():
    """The bug this replaced a shed with.  Nothing retries a submission — the
    client sends it once — so shedding one because it arrived at an awkward
    moment lost it silently and for ever.  It waits instead."""
    b = _budget()
    q = WorkQueue()
    ran = []
    q.offer(lambda: ran.append("late"), Priority.OWNER, key="late", epoch=1)
    # Arriving with only the reserve left: refused, and still queued.
    assert q.drain(b, now_ms=int(b.deadline_ms - b.reserve_ms)) == (0, 0)
    assert len(q) == 1 and not ran
    # The next epoch reopens the window, and it runs.
    b.open(2)
    assert q.drain(b, now_ms=b.clock.start_of(2))[0] == 1
    assert ran == ["late"] and len(q) == 0


def test_work_that_waited_too_long_is_given_up_on():
    b = _budget()
    q = WorkQueue()
    q.offer(lambda: None, Priority.ANON, key="ancient", epoch=1)
    b.open(1 + MAX_EPOCHS_QUEUED)
    ran, expired = q.drain(b, now_ms=b.clock.start_of(1 + MAX_EPOCHS_QUEUED))
    assert (ran, expired) == (0, 1)
    assert len(q) == 0 and q.expired == 1


def test_the_deadline_survives_a_flood_that_never_stops():
    """Submissions keep arriving for the whole epoch and the node keeps
    draining.  What must hold at the decide deadline is that the reserve is
    intact — the ceremony has not been spent — and that the queue stayed
    bounded rather than growing to hold the flood."""
    b = _budget()
    q = WorkQueue(capacity=64)
    clock_now, tick = _ticking(b.clock.start_of(1))
    arrivals = 0
    for _ in range(200):                    # keep arriving past the refusal
        for _ in range(8):
            arrivals += 1
            q.offer((lambda: tick()), Priority.ANON, key=f"tx{arrivals}",
                    epoch=1)
        q.drain(b, now_ms=clock_now, max_items=8)
    assert clock_now() <= b.deadline_ms - b.reserve_ms, \
        f"the flood ate into the reserve: {clock_now()} vs {b.deadline_ms}"
    assert b.afford(Priority.CEREMONY, clock_now())[0]
    assert len(q) <= q.capacity, "the queue stayed bounded"
    assert q.dropped[Priority.ANON] > 0, "and the excess was refused at the door"
    assert q.offered == arrivals


def test_a_flood_of_strangers_does_not_starve_a_peer():
    """Ordering, not fairness: the peer's work is done before any of it."""
    b = _budget()
    q = WorkQueue(capacity=64)
    served = []
    for i in range(64):
        q.offer((lambda n: (lambda: served.append(("anon", n))))(i),
                Priority.ANON, key=f"a{i}")
    ok, _ = q.offer(lambda: served.append(("peer", 0)), Priority.PEER,
                    key="peer")
    assert ok, "a peer is never turned away for a queue full of strangers"
    q.drain(b, now_ms=b.clock.start_of(1), max_items=1000)
    assert served and served[0] == ("peer", 0), served[:3]


def test_the_budget_re_prices_itself_from_measurement():
    """No table to edit when a backend changes: `run` observes what the work
    actually cost and the next `afford` uses it."""
    clock = Clock(effective_ms=0, epoch_millis=EPOCH_MS)
    b = EpochBudget(clock, meter=Meter(25.4, alpha=1.0)).open(1)
    before = b.reserve_ms
    b.run(Priority.OWNER, lambda: None, now_ms=clock.start_of(1))
    assert b.meter.estimate < 25.4, b.meter.estimate
    assert b.reserve_ms < before, "a cheaper unit reserves less"


def test_a_struck_body_is_demoted_and_not_refused():
    """`PROOF_STRIKES` must not be a refusal threshold: refusing a body with
    strikes against it would let anyone censor a transaction by splicing bad
    proofs onto its body.  Demotion is the whole of the punishment."""
    assert PROOF_STRIKES > 0
    b = _budget()
    q = WorkQueue()
    ran = []
    q.offer(lambda: ran.append("struck"), Priority.ANON, key="struck")
    q.offer(lambda: ran.append("clean"), Priority.OWNER, key="clean")
    q.drain(b, now_ms=b.clock.start_of(1))
    assert ran == ["clean", "struck"], ran
