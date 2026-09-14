"""What a node will do for a stranger, and how often.

Part eight recorded the problem in one sentence: a submission costs about 26 ms
of proof verification and nothing meters it, and a fee cannot be charged before
the proof is checked, which is the wrong way round.  Two answers, and they are
different answers to different halves of it.

**A cheaper `no`.**  Most rubbish can be refused without touching the proof —
a transaction spending a note that is not in the UTXO set, or republishing a
nullifier, or paying no fee, is refusable by set lookup.  `Node.admissible`
does those first, so the expensive check only ever runs on a transaction that
would otherwise be worth including.  That does not make flooding free to
defend against; it makes it three orders of magnitude cheaper.

**A budget.**  Even a cheap `no` is not free, and a valid transaction is
expensive on purpose.  So every source gets a token bucket: capacity for a
burst, a refill rate for the long run, and a cost per request that reflects
what the request actually makes the node do.  A peer of this chain is metered
too — generously, because a validator that cannot gossip is a validator that
cannot vote, but not exempt, because "it said it was a peer" is not
authentication.

What this is not: a fee market.  Metering by source is what a node can do
alone; charging for the work is what the chain would have to agree on, and
that is a design nobody here has written.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict

from .frame import CLIENT_MAX_FRAME

#: What each request costs a caller, in tokens.  Roughly proportional to what
#: it costs the node: a status is a dictionary, an inclusion proof is 32 hashes,
#: a page of outputs is a table scan, and a submission is a proof.
COSTS = {
    # Authenticating a hello is two dictionary lookups and, if those pass, one
    # signature.  Priced like any other small request because it used to be
    # priced at nothing: the handshake was the one kind that bypassed the
    # meter entirely, so replaying it was free.
    "hello": 5,
    "status": 1,
    "params": 1,
    "tip": 1,
    "txstatus": 1,
    "register": 2,
    "ancestry": 2,
    "inclusion": 2,
    "headers": 5,
    "weight": 5,
    "getoutputs": 10,
    "tags": 20,
    "tx": 50,
    # Not a request, and deliberately zero: a frame is charged for its *bytes*
    # before it is decoded, and for its kind afterwards.  A base cost here
    # would be a flat surcharge on every small frame — it tripled the price of
    # a `status`, which is the one request a light client makes constantly.
    # A stream of tiny frames is priced by the kinds it carries, and a stream
    # of tiny frames carrying no valid kind is a FrameError and a disconnect.
    "frame": 0,
}
DEFAULT_COST = 5

#: One token per 8 KB decoded.  Two charges, not one: the bytes pay for the
#: decode and the kind pays for the work, and a frame refused at the door never
#: reaches the second.
#:
#: The rate is set so that the ceiling and the budget agree, which is the thing
#: that is easy to get wrong — a per-frame ceiling a source can never afford is
#: not a ceiling, it is a decoy, and the real limit is then whatever the bucket
#: happens to allow.  At 8 KB a token:
#:
#:   60 KB   (a LOCAL submission)        8 tokens
#:   600 KB  (a three-backend submission) 75 tokens, +50 for the kind
#:   1 MB    (`CLIENT_MAX_FRAME`)        128 tokens — inside a client's 240 burst
#:   8 MB    (`MAX_FRAME`, a block)    1,024 tokens — inside a peer's 6,000
#:
#: And it prices the attack out: a client's 20 tokens a second buys one 1 MB
#: frame every 6.4 s, so 45 ms of decode every 6.4 s — 0.7% of a core, against
#: the 143% the same address could take when the meter ran after the decode.
BYTES_PER_TOKEN = 8192


def bytes_cost(nbytes: int) -> float:
    """Tokens owed for decoding `nbytes`.

    Proportional, and *not* rounded up.  Rounding up meant a 60-byte request
    cost a whole token on top of its kind, which is a tax on exactly the small
    frequent frames this was never aimed at — a light client's `status` went
    from 1 token to 3.  The buckets hold floats, so there is no reason to
    quantise: a tiny frame costs a tiny fraction and a megabyte costs 128.
    """
    return int(nbytes) / BYTES_PER_TOKEN

#: What one unit of verification cost when the prices above were written:
#: mpcith at `LOCAL` parameters, the same number `budget.INITIAL_UNIT_MS`
#: starts from.  `tx` is 50 tokens *because* of this figure, and at `LAUNCH`
#: parameters the same backend takes 0.31 s — twelve times as long, for a
#: price that never moved.  A stranger could therefore buy 6.4% of a core,
#: sustained, for the price of a 25 ms proof.  Review class D, part thirteen.
PRICED_AT_MS = 25.4

#: The kinds whose price tracks what the work actually costs now, rather than
#: what it cost when somebody wrote the number down.  Only submissions: every
#: other kind is a lookup or a page whose cost has not moved.
METERED_KINDS = ("tx",)

#: And a ceiling on that tracking.  A meter that has just watched one
#: pathological proof must not be able to close the door on every wallet, and
#: a node whose machine is simply slow should throttle rather than refuse.
MAX_PRICE_MULTIPLE = 40.0


def price_multiple(unit_ms) -> float:
    """How much more a unit of work costs now than when the prices were set.

    Never below one: measuring a *cheaper* proof than the written price is not
    a reason to make submissions cheaper than the number somebody argued for.
    """
    if not unit_ms:
        return 1.0
    return min(MAX_PRICE_MULTIPLE, max(1.0, float(unit_ms) / PRICED_AT_MS))


#: A client may spend 240 tokens at once and earns 20 a second: two dozen
#: inclusion proofs back to back, or four transactions a minute sustained.
#: The rate is what bounds sustained abuse; the capacity is a burst allowance,
#: and it has a floor it must never fall below — see `Limiter.floor_capacity`.
CLIENT_CAPACITY, CLIENT_RATE = 240.0, 20.0
#: A seated peer gossips continuously and must not be throttled into silence.
PEER_CAPACITY, PEER_RATE = 6000.0, 2000.0


class Bucket:
    """One source's budget.  Not thread-safe on its own; `Limiter` locks."""

    __slots__ = ("capacity", "rate", "tokens", "last", "refused", "spent")

    def __init__(self, capacity: float, rate: float, now: float | None = None):
        self.capacity, self.rate = float(capacity), float(rate)
        self.tokens = float(capacity)
        self.last = time.monotonic() if now is None else now
        self.refused = 0
        self.spent = 0.0

    def take(self, cost: float, now: float | None = None):
        """(allowed, wait) — wait is how long until this cost would fit."""
        now = time.monotonic() if now is None else now
        self.tokens = min(self.capacity,
                          self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= cost:
            self.tokens -= cost
            self.spent += cost
            return True, 0.0
        self.refused += 1
        return False, (cost - self.tokens) / self.rate if self.rate else None

    def __repr__(self):
        return (f"Bucket({self.tokens:.0f}/{self.capacity:.0f}, "
                f"{self.refused} refused)")


class Limiter:
    """Buckets by source, with the idle ones swept.

    Keyed by address rather than by claimed identity, because a client has no
    identity here and a peer's `hello` is a claim, not a credential.  An
    attacker with many addresses gets many buckets — which is true of every
    scheme of this kind, and is why this is a floor under the cost of flooding
    rather than a fence around it.
    """

    def __init__(self, capacity=CLIENT_CAPACITY, rate=CLIENT_RATE,
                 peer_capacity=PEER_CAPACITY, peer_rate=PEER_RATE,
                 idle_after: float = 300.0, max_sources: int = 4096):
        self.capacity, self.rate = capacity, rate
        self.peer_capacity, self.peer_rate = peer_capacity, peer_rate
        self.idle_after, self.max_sources = idle_after, max_sources
        #: What one unit of work measured at, or 0 for "use the written
        #: prices".  Set once an epoch from the budget's meter.
        self.unit_ms = 0.0
        #: Least-recently-used first, so the sweep is a pop rather than a sort.
        #: The policy is unchanged — idle sources go, oldest first when
        #: crowded — but it used to be paid for by sorting every bucket on the
        #: path that *creates* one, which an attacker walks by sending a frame
        #: from an address it has not used yet: 5.8 us with no sources, 332 us
        #: at the 4,096 cap.  Same shape as the penalty box's, and cheaper for
        #: an attacker to reach, because it costs no disconnect.  Review class
        #: D, part thirteen.
        self._buckets: "OrderedDict" = OrderedDict()
        self._lock = threading.Lock()
        self.allowed = 0
        self.refused = 0

    def cost_of(self, kind: str) -> float:
        """Tokens for one request of this kind, at what the work costs *now*."""
        base = COSTS.get(kind, DEFAULT_COST)
        if kind in METERED_KINDS:
            return base * price_multiple(self.unit_ms)
        return base

    def observe_unit(self, unit_ms: float):
        """The measured cost of one unit of work, from the epoch budget's meter.

        A plain attribute and no lock: it is read to compute a price, a stale
        read costs one request the old price, and the alternative is taking a
        lock on every frame to learn a number that moves once an epoch.
        """
        self.unit_ms = float(unit_ms or 0.0)

    def floor_capacity(self) -> float:
        """The smallest burst a client bucket may have.

        `limits` already carries the warning this enforces — *a per-frame
        ceiling a source can never afford is not a ceiling, it is a decoy* —
        and making the submission price track the work reintroduces exactly
        that failure if nothing watches it: at twelve times the written price a
        `tx` costs 610 tokens against a 240-token bucket, so no client could
        ever submit anything, ever, and the limiter would have become a ban.

        So the burst floor is one largest-possible submission.  The *rate* is
        untouched, which is the half that bounds sustained abuse: a dearer
        submission means fewer per minute, not none.
        """
        return self.cost_of("tx") + bytes_cost(CLIENT_MAX_FRAME)

    def check(self, source, kind: str, *, peer: bool = False,
              now: float | None = None, nbytes: int = 0):
        """(allowed, reason).  Never raises, never blocks."""
        cost = self.cost_of(kind) + (bytes_cost(nbytes) if nbytes else 0)
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._buckets.get(source)
            if bucket is None:
                self._sweep(now)
                bucket = Bucket(
                    self.peer_capacity if peer else max(self.capacity,
                                                        self.floor_capacity()),
                    self.peer_rate if peer else self.rate, now=now)
                self._buckets[source] = bucket
            else:
                # Touching it is what makes the ordering an LRU, and it has to
                # happen on every use rather than only on eviction, or "oldest"
                # would mean "first seen".
                self._buckets.move_to_end(source)
            floor = self.floor_capacity()
            if not peer and bucket.capacity < floor:
                # The price moved under an open connection.  Raising the burst
                # is not a favour to the caller: it is what keeps the ceiling
                # from becoming a ban (see `floor_capacity`).
                bucket.capacity = floor
            if peer and bucket.capacity < self.peer_capacity:
                # A source that turns out to be a seated peer is promoted, not
                # left on a client's budget for the rest of its connection.
                bucket.capacity, bucket.rate = self.peer_capacity, self.peer_rate
            ok, wait = bucket.take(cost, now=now)
            if ok:
                self.allowed += 1
                return True, "ok"
            self.refused += 1
            return False, (f"rate limit: {kind} costs {cost:g} tokens, "
                           f"{bucket.tokens:.0f} left"
                           + (f", try in {wait:.1f}s" if wait else ""))

    def _sweep(self, now: float):
        """Forget sources that have gone quiet, oldest first if crowded.

        The same policy as before and none of the scanning.  Least recently
        used sits at the front, so the idle ones are a prefix: stop at the
        first bucket that is not idle, then pop while over the cap.
        """
        buckets = self._buckets
        while buckets:
            key, bucket = next(iter(buckets.items()))
            if now - bucket.last <= self.idle_after:
                break
            del buckets[key]
        while len(buckets) >= self.max_sources:
            buckets.popitem(last=False)

    def stats(self) -> dict:
        with self._lock:
            return {"sources": len(self._buckets), "allowed": self.allowed,
                    "refused": self.refused}

    def __repr__(self):
        s = self.stats()
        return (f"Limiter({s['sources']} sources, {s['allowed']} allowed, "
                f"{s['refused']} refused)")
