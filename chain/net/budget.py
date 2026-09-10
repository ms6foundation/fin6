"""How much work a node will do before it has to attest, and for whom.

Part nine's second half.  Part eight metered *requests* — a token bucket per
source, priced by message kind — and that is necessary and not sufficient,
because a bucket denominated in tokens cannot know what a token costs.  At the
shipped settings one seated peer is authorised 40 submissions a second, which
at 25 ms a proof is 1.02 CPU-seconds per wall second: the whole machine, from
one connection, with every rule obeyed.

The thing that is actually scarce is not requests.  It is the interval between
now and the moment this node has to have validated the leader's proposal and
attested:

    epoch start        0 ms
    decide by     11,849 ms   (0.60 of a 19,749 ms epoch)
    commit by     15,799 ms   (0.80)

A node that spends that window verifying submissions does not attest, the
leader's block misses quorum, and the epoch produces nothing.  Nobody attacked
consensus; they bought the CPU consensus needed.  So this module holds one
budget for the whole node, denominated in milliseconds of that window, and
every expensive thing asks it first.

Three properties are the point:

  * **The deadline is met by construction.**  The budget is derived from the
    deadline rather than hoped for, and it keeps a reserve for the proposal
    that has not arrived yet.
  * **Ceremony work never queues behind a stranger's.**  Validating the
    proposal is priority 0 and is not in the queue at all; it runs inline and
    is never shed.
  * **The cost is measured, not configured.**  `Meter` is an EWMA over what
    verification actually took, so a backend change or a slower machine
    re-prices everything without a table to edit.  Part eight's `COSTS` table
    is still there and still useful — it prices *access*.  This prices *work*.
"""
from __future__ import annotations

import enum
import time


class Priority(enum.IntEnum):
    """Lower is more important.  The order is the whole policy."""

    CEREMONY = 0     # validating the proposal this node must attest to
    PEER = 1         # gossip from a peer that has authenticated
    OWNER = 2        # a submission whose body authenticated (see node.authenticate)
    ANON = 3         # a submission from nobody in particular, or a struck body


#: How much of the *discretionary* slack each priority must leave unspent —
#: that is, of the window after the reserve is taken out, not of the window.
#: Taking it out of the whole window was wrong in a way only a short epoch
#: showed: at a 2.5 s epoch the reserve is already half the window, so a floor
#: of half the window left the lowest class exactly nothing, for ever.
#: A stranger may use the first half of the slack; an authenticated owner three
#: quarters; a peer all of it.  As the deadline approaches the lower classes
#: stop first, which is what shedding means when nothing can be cancelled once
#: it has started.
FLOORS = {Priority.CEREMONY: 0.0, Priority.PEER: 0.0,
          Priority.OWNER: 0.25, Priority.ANON: 0.50}

#: Units of work held back for the proposal.  A block carries as many
#: transactions as the leader chose to include and its size is not known until
#: it arrives, so this is a guess sized to the largest block the testnet
#: produces.  It is deliberately generous: over-reserving wastes slack, and
#: under-reserving misses the deadline, and only one of those is a fault.
RESERVE_UNITS = 128

#: But never more than this share of the window.  Without the cap a short
#: epoch reserves more than it has — 128 proofs is 3.2 s against the 1.5 s
#: decide window of a 2.5 s test epoch — and the node then refuses every
#: submission for ever, which is not caution but a stall with a rationale.
#: If a block genuinely does not fit in the window, no amount of refusing
#: submissions makes it fit; that is a parameter fault and belongs in the
#: params, not here.
RESERVE_CAP = 0.5

#: Starting estimate, replaced by measurement after the first observation.
#: mpcith at LOCAL params, which is what a testnet node runs.
INITIAL_UNIT_MS = 25.4

#: The queue is bounded because it is fed by strangers.  256 submissions is
#: about 6.5 seconds of verification — already more than one decide window has
#: to spare, so a deeper queue would only hold work that is going to be
#: dropped anyway, and would hold it for longer.
QUEUE_CAPACITY = 256

#: How many epochs a job may wait before it is given up on.  Work the budget
#: will not pay for *now* is usually affordable at the top of the next epoch,
#: a second or two later, so the queue holds it rather than dropping it — a
#: submission that arrived at an awkward moment is not a submission that
#: deserves to vanish.  What must not happen is holding it for ever: three
#: epochs is roughly a minute on the shipped clock, by which time a wallet has
#: given up and the transaction may not even be spendable.
MAX_EPOCHS_QUEUED = 3


class Meter:
    """What one unit of work costs, as an exponentially weighted mean.

    Kept deliberately dumb: no percentiles, no histogram.  The budget needs to
    know roughly what the next proof will cost, and the interesting variance in
    this system is between backends, which are chosen per tier rather than per
    transaction.
    """

    __slots__ = ("estimate", "alpha", "observations", "worst")

    def __init__(self, initial_ms: float = INITIAL_UNIT_MS, alpha: float = 0.2):
        self.estimate = float(initial_ms)
        self.alpha = float(alpha)
        self.observations = 0
        self.worst = 0.0

    def observe(self, ms: float):
        ms = max(0.0, float(ms))
        self.observations += 1
        self.worst = max(self.worst, ms)
        self.estimate += self.alpha * (ms - self.estimate)

    def cost(self, units: float = 1.0) -> float:
        return self.estimate * units

    def __repr__(self):
        return (f"Meter({self.estimate:.1f} ms, {self.observations} obs, "
                f"worst {self.worst:.1f} ms)")


class EpochBudget:
    """One node's spending limit for the epoch it is in.

    `open` is called at the top of an epoch; `afford` is asked before anything
    expensive.  Time is passed in rather than read, so the tests can run an
    epoch in no time at all and the arithmetic is checkable.
    """

    def __init__(self, clock, meter: Meter | None = None,
                 reserve_units: int = RESERVE_UNITS):
        self.clock = clock
        self.meter = meter or Meter()
        self.reserve_units = reserve_units
        self.epoch = None
        self.deadline_ms = 0
        self.window_ms = 0.0
        self.spent_ms = 0.0
        self.granted = 0
        self.shed = {p: 0 for p in Priority}

    # ── the epoch ────────────────────────────────────────────────────────────

    def open(self, epoch: int):
        """Start of an epoch: recompute the window from the clock."""
        self.epoch = epoch
        self.deadline_ms = self.clock.decide_deadline(epoch)
        start = self.clock.start_of(epoch)
        self.window_ms = float(max(0, self.deadline_ms - start))
        self.spent_ms = 0.0
        return self

    @property
    def reserve_ms(self) -> float:
        """Time held back for the proposal, never lent to anyone."""
        wanted = self.meter.cost(self.reserve_units)
        if not self.window_ms:
            return wanted
        return min(wanted, RESERVE_CAP * self.window_ms)

    def remaining_ms(self, now_ms: int | None = None) -> float:
        """Time to the decide deadline, minus the reserve.  May be negative."""
        now_ms = self.clock.now_ms() if now_ms is None else now_ms
        return (self.deadline_ms - now_ms) - self.reserve_ms

    # ── spending ─────────────────────────────────────────────────────────────

    def afford(self, priority: Priority, now_ms: int | None = None,
               units: float = 1.0):
        """(ok, reason).  Never raises, never blocks, changes nothing."""
        if priority == Priority.CEREMONY:
            # Not negotiable.  A node that will not validate the proposal
            # because it is busy is the failure this module exists to prevent,
            # and refusing here would be that failure with a reason attached.
            return True, "ok"
        if self.epoch is None:
            return False, "no epoch is open"
        cost = self.meter.cost(units)
        floor = FLOORS[priority] * max(0.0, self.window_ms - self.reserve_ms)
        left = self.remaining_ms(now_ms)
        if left - cost < floor:
            return False, (f"budget: {left:.0f} ms to the decide deadline, "
                           f"{cost:.0f} ms wanted, {floor:.0f} ms reserved "
                           f"above {priority.name}")
        return True, "ok"

    def spend(self, priority: Priority, ms: float):
        """Record what a piece of work actually cost."""
        self.spent_ms += max(0.0, float(ms))
        self.granted += 1
        self.meter.observe(ms)

    def refuse(self, priority: Priority):
        self.shed[priority] = self.shed.get(priority, 0) + 1

    def run(self, priority: Priority, fn, now_ms: int | None = None,
            units: float = 1.0):
        """Ask, run, and pay.  (ran, result_or_reason)."""
        ok, why = self.afford(priority, now_ms, units)
        if not ok:
            self.refuse(priority)
            return False, why
        started = time.perf_counter()
        try:
            result = fn()
        finally:
            self.spend(priority, (time.perf_counter() - started) * 1000.0)
        return True, result

    def stats(self) -> dict:
        """Integers and strings only.

        These go out over the wire in a `status_reply`, and `store/codec.py`
        has no encoding for a float — deliberately, since a canonical codec
        that has to agree byte for byte across nodes has no business carrying
        one.  So the unit cost is reported in whole microseconds.
        """
        return {"epoch": -1 if self.epoch is None else int(self.epoch),
                "window_ms": round(self.window_ms),
                "reserve_ms": round(self.reserve_ms),
                "spent_ms": round(self.spent_ms), "granted": self.granted,
                "unit_us": round(self.meter.estimate * 1000),
                "shed": {p.name: n for p, n in self.shed.items() if n}}

    def __repr__(self):
        return (f"EpochBudget(epoch={self.epoch}, spent {self.spent_ms:.0f} ms, "
                f"unit {self.meter.estimate:.1f} ms)")


class WorkQueue:
    """Deferred expensive work, bounded, priority-ordered, FIFO within a class.

    Bounded is the important word.  An unbounded queue does not refuse
    anything; it converts a CPU problem into a memory problem and answers every
    submission with a promise it will not keep.  When this one is full the
    *least* important item goes — the newest of the lowest priority present,
    which may be the arriving item itself.

    What it does not do is drop work merely because this epoch cannot pay for
    it.  The budget is reopened every epoch, so a job the deadline refuses now
    is very likely affordable in a second or two, and the first version of this
    module shed it instead — which lost exactly one transaction per submission
    on a 2.5 s testnet, silently, because nothing retries a submission.  Work
    waits here for up to `MAX_EPOCHS_QUEUED` epochs and is then given up on.
    """

    def __init__(self, capacity: int = QUEUE_CAPACITY,
                 max_epochs: int = MAX_EPOCHS_QUEUED):
        self.capacity = capacity
        self.max_epochs = max_epochs
        self._items: list = []        # (priority, seq, key, job, epoch)
        self._keys: set = set()
        self._seq = 0
        self.offered = 0
        self.expired = 0
        self.dropped = {p: 0 for p in Priority}

    def __len__(self):
        return len(self._items)

    def offer(self, job, priority: Priority, key=None, epoch: int | None = None):
        """(accepted, reason).  A repeated key is not queued twice."""
        self.offered += 1
        if key is not None and key in self._keys:
            return False, "already queued"
        if len(self._items) >= self.capacity:
            worst = max(self._items, key=lambda it: (it[0], it[1]))
            if worst[0] <= priority:
                # Nothing in here is less important than the arrival.
                self.dropped[priority] = self.dropped.get(priority, 0) + 1
                return False, f"queue full ({self.capacity})"
            self._remove(worst)
            self.dropped[worst[0]] = self.dropped.get(worst[0], 0) + 1
        self._seq += 1
        self._items.append((priority, self._seq, key, job, epoch))
        if key is not None:
            self._keys.add(key)
        return True, "ok"

    def _remove(self, item):
        self._items.remove(item)
        if item[2] is not None:
            self._keys.discard(item[2])

    def pop(self):
        """Most important, oldest first.  None when empty."""
        if not self._items:
            return None
        item = min(self._items, key=lambda it: (it[0], it[1]))
        self._remove(item)
        return item[0], item[3]

    def drain(self, budget: EpochBudget, now_ms=None, max_items: int = 64):
        """Run what the budget allows, keep the rest.  Returns (ran, expired).

        Stopping at the first unaffordable item rather than skipping past it is
        deliberate: the queue is ordered by importance, and a lower priority
        has a *higher* floor, so nothing behind the first refusal could be
        afforded either.
        """
        expired = self._expire(budget.epoch)
        ran = 0
        now = (lambda: now_ms() if callable(now_ms) else now_ms)
        while self._items and ran < max_items:
            item = min(self._items, key=lambda it: (it[0], it[1]))
            ok, _ = budget.afford(item[0], now())
            if not ok:
                budget.refuse(item[0])
                break
            self._remove(item)
            budget.run(item[0], item[3], now())
            ran += 1
        return ran, expired

    def _expire(self, epoch: int | None) -> int:
        """Give up on work that has waited too long to still be wanted."""
        if epoch is None:
            return 0
        stale = [it for it in self._items
                 if it[4] is not None and epoch - it[4] >= self.max_epochs]
        for item in stale:
            self._remove(item)
            self.dropped[item[0]] = self.dropped.get(item[0], 0) + 1
        self.expired += len(stale)
        return len(stale)

    def stats(self) -> dict:
        return {"queued": len(self._items), "offered": self.offered,
                "expired": self.expired,
                "dropped": {p.name: n for p, n in self.dropped.items() if n}}

    def __repr__(self):
        return (f"WorkQueue({len(self._items)}/{self.capacity}, "
                f"{self.offered} offered)")
