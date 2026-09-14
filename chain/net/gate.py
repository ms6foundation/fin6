"""Who gets a socket, and for how long.

Part nine metered messages: a token bucket per source, priced by kind and by
the bytes it costs to decode.  Every one of those charges happens to a frame
that has *arrived*, on a connection that already exists — and nothing ever
metered the connection.  So the cheapest attack on a node was never to send
anything:

  * `_accept_loop` spawned a thread per accepted socket and appended it to a
    list that was never pruned, so ten thousand connections were ten thousand
    threads and a list that outlived all of them;
  * `listen(64)` is a backlog, not a limit, and there was no cap per address
    or in total;
  * `SOCKET_TIMEOUT` is 1 s and the read loop treated a timeout as `continue`,
    for ever — a connection that announced a length and then said nothing held
    a thread and its buffer until the process died;
  * and a `FrameError` disconnect was free to retry, which the handshake made
    *more* relevant rather than less: failing authentication now closes the
    connection, and reconnecting cost nothing.

An idle socket sends no frames, so it is charged nothing by a meter that
charges for frames.  This module is the other half: four bounds that apply
before a byte is read.

Deliberately knows nothing about frames, chains or peers.  It is handed an
address and asked a question, which is what makes it testable without a
network and what keeps the policy in one place.
"""
from __future__ import annotations

import heapq
import threading
import time

#: Total concurrent inbound connections.  Sized well above what the roster
#: needs — six peers dial in, plus wallets and light clients — because the
#: point is to have a ceiling at all, not to be tight.
MAX_CONNECTIONS = 256

#: And per address, which is the one that matters: a full mesh gives each peer
#: one inbound socket, and a wallet host a handful.  Anything opening thirty
#: sockets from one address is not using the protocol.
MAX_PER_ADDRESS = 24

#: How long a connection may hold a worker without completing a frame.  A
#: peer gossips several times a second and a client asks and leaves, so a
#: minute of total silence is generous; a *partial* frame is much more
#: suspicious than silence and gets less.
IDLE_SECONDS = 60.0
PARTIAL_SECONDS = 10.0

#: The penalty box.  A connection closed for a protocol violation — a
#: malformed frame, an unproved seat claim — buys its address a wait before
#: the next one is accepted, doubling up to a cap.  Without it the cost of a
#: refused handshake was one `connect()`.
PENALTY_SECONDS = 2.0
PENALTY_MAX = 60.0

#: Addresses remembered in the box.  Bounded because it is keyed by something
#: an attacker chooses: remembering offenders is itself state they can grow,
#: so the box is a cache with an eviction policy and not a ledger.
#:
#: Bounding the *size* was only half of it.  The first version paid for the
#: eviction policy on the hot path — `penalise` sorted the whole box, and
#: `penalise` is what a malformed frame causes — so the cost of remembering
#: offenders was charged to the node at a rate the offender set: 2.9 us with an
#: empty box, 288 us with a full one, which is 29.5% of a core at a thousand
#: violations a second.  A defence whose cost scales with the attack is not a
#: defence.  The box is now kept in expiry order (`_order`), so both jobs the
#: sweep did — dropping what has expired, and evicting when full — are a pop
#: from the same end.  Review class D, part thirteen.
MAX_PENALISED = 4096


class Gate:
    """Connection admission for one listener.  Thread-safe, never blocks."""

    def __init__(self, max_connections: int = MAX_CONNECTIONS,
                 max_per_address: int = MAX_PER_ADDRESS,
                 penalty_seconds: float = PENALTY_SECONDS,
                 penalty_max: float = PENALTY_MAX,
                 max_penalised: int = MAX_PENALISED):
        self.max_connections = max_connections
        self.max_per_address = max_per_address
        self.penalty_seconds = penalty_seconds
        self.penalty_max = penalty_max
        self.max_penalised = max_penalised
        self._lock = threading.Lock()
        self._open: dict = {}          # address -> how many sockets it holds
        self._penalty: dict = {}       # address -> (until, strikes)
        #: (until, address), a min-heap.  The head is both the next entry to
        #: expire and the cheapest one to evict, which is why one structure
        #: does both jobs.  Entries are superseded rather than deleted when an
        #: address is penalised again — a stale one is recognised by its
        #: `until` disagreeing with the dictionary, and discarded on sight.
        self._order: list = []
        self.total = 0
        self.admitted = 0
        self.refused_total = 0
        self.refused_address = 0
        self.refused_penalty = 0

    # ── admission ────────────────────────────────────────────────────────────

    def admit(self, address: str, now: float | None = None):
        """(ok, reason).  Counts the connection when it says yes."""
        now = time.monotonic() if now is None else now
        with self._lock:
            box = self._penalty.get(address)
            if box is not None and now < box[0]:
                self.refused_penalty += 1
                return False, (f"{address} is in the penalty box for "
                               f"{box[0] - now:.0f}s")
            if self.total >= self.max_connections:
                self.refused_total += 1
                return False, (f"{self.total} connections is the ceiling "
                               f"({self.max_connections})")
            held = self._open.get(address, 0)
            if held >= self.max_per_address:
                self.refused_address += 1
                return False, (f"{address} already holds {held} connections "
                               f"({self.max_per_address})")
            self._open[address] = held + 1
            self.total += 1
            self.admitted += 1
            return True, "ok"

    def release(self, address: str):
        """One connection closed, however it closed."""
        with self._lock:
            held = self._open.get(address)
            if held is None:
                return
            if held <= 1:
                del self._open[address]
            else:
                self._open[address] = held - 1
            self.total = max(0, self.total - 1)

    def penalise(self, address: str, now: float | None = None) -> float:
        """A protocol violation.  Returns how long this address now waits.

        Doubling, because the first offence is usually a version skew or a
        half-finished client and the tenth is not.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            until, strikes = self._penalty.get(address, (0.0, 0))
            strikes += 1
            wait = min(self.penalty_max,
                       self.penalty_seconds * (2 ** (strikes - 1)))
            until = now + wait
            self._penalty[address] = (until, strikes)
            heapq.heappush(self._order, (until, address))
            self._sweep(now)
            return wait

    def _sweep(self, now: float):
        """Drop what has expired, and evict while full.  Both from the head.

        Amortised constant: every push is popped at most once, and the loop
        stops at the first entry that is neither stale nor expired while the
        box is inside its bound.  What it must *not* do is scan or sort, which
        is the whole point — see `MAX_PENALISED`.

        Evicting the head means evicting the entry that would have expired
        soonest, which is the right one to lose: a flood of first offenders at
        two seconds each evicts itself rather than displacing an address that
        has worked its way up to a minute.
        """
        order, box = self._order, self._penalty
        while order:
            until, address = order[0]
            current = box.get(address)
            if current is None or current[0] != until:
                heapq.heappop(order)          # superseded by a later penalty
                continue
            if until <= now:
                heapq.heappop(order)
                del box[address]
                continue
            if len(box) > self.max_penalised:
                heapq.heappop(order)
                del box[address]
                continue
            break
        # Superseded entries are only noticed when they reach the head, so a
        # repeat offender could otherwise leave the heap growing behind a
        # long-lived entry.  Rebuilding is O(n) and happens once per doubling.
        if len(order) > 2 * (len(box) + 16):
            self._order = [(until, a) for a, (until, _) in box.items()]
            heapq.heapify(self._order)

    def penalised(self, address: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        box = self._penalty.get(address)
        return box is not None and now < box[0]

    def stats(self) -> dict:
        with self._lock:
            return {"open": self.total, "addresses": len(self._open),
                    "penalised": len(self._penalty),
                    "admitted": self.admitted,
                    "refused": {"total": self.refused_total,
                                "address": self.refused_address,
                                "penalty": self.refused_penalty}}

    def __repr__(self):
        return (f"Gate({self.total}/{self.max_connections} open, "
                f"{len(self._penalty)} penalised)")


class Deadlines:
    """When a connection has held a worker long enough without finishing.

    Two clocks rather than one.  Total silence is cheap to be patient about —
    a wallet asks a question and waits — but a connection that has announced a
    frame and delivered part of it is holding a buffer against a promise, and
    the promise is the suspicious part.
    """

    __slots__ = ("idle", "partial", "last", "partial_since")

    def __init__(self, idle: float = IDLE_SECONDS,
                 partial: float = PARTIAL_SECONDS, now: float | None = None):
        self.idle = idle
        self.partial = partial
        self.last = time.monotonic() if now is None else now
        self.partial_since = None

    def saw_data(self, now: float | None = None):
        self.last = time.monotonic() if now is None else now

    def saw_frame(self, now: float | None = None):
        """A complete frame: the connection is keeping its promises."""
        self.saw_data(now)
        self.partial_since = None

    def saw_partial(self, now: float | None = None):
        """Bytes buffered that do not yet make a frame."""
        now = time.monotonic() if now is None else now
        self.last = now
        if self.partial_since is None:
            self.partial_since = now

    def expired(self, now: float | None = None):
        """(expired, reason)."""
        now = time.monotonic() if now is None else now
        if self.partial_since is not None and \
                now - self.partial_since > self.partial:
            return True, (f"a partial frame held for "
                          f"{now - self.partial_since:.0f}s")
        if now - self.last > self.idle:
            return True, f"idle for {now - self.last:.0f}s"
        return False, "ok"
