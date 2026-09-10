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
            self._penalty[address] = (now + wait, strikes)
            self._sweep(now)
            return wait

    def _sweep(self, now: float):
        expired = [a for a, (until, _) in self._penalty.items()
                   if until <= now]
        for address in expired:
            del self._penalty[address]
        if len(self._penalty) > self.max_penalised:
            oldest = sorted(self._penalty, key=lambda a: self._penalty[a][0])
            for address in oldest[:len(self._penalty) - self.max_penalised]:
                del self._penalty[address]

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
