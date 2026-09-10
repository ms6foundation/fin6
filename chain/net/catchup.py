"""A way back for a node that fell behind.

Part six listed this as the largest missing piece and it was right.  Until now
`getblock` fetched a body *by hash*, and only a hash the seat already had a
signed header for in the current epoch — so the only block a node could ask
for was the one it was already being asked to vote on.  A node that missed an
epoch had no way to obtain the block it missed, and no way back:

  * its height stays behind while the clock does not, so the next leader
    proposes at a height whose `prev_hash` it has never seen;
  * `SoloWorkload.validate` refuses that proposal, correctly, because the
    block does not chain onto the state this node holds;
  * so it never attests again, and it is a dead seat with a live socket.

Which makes every fault **irreversible and cumulative**.  Seven nodes tolerate
two, and a restart, a long pause, a brief partition or a `kill -9` each spend
one of those two permanently: the third such event in the life of the network
ends it.  Nothing about that requires an attacker.

**What this fixes and what it does not.**  Block bodies live only in memory —
`netblock` stores the header and the certificate, and `txblock` stores txids,
because a validator is not an archive.  So a peer can only serve what it still
holds, which this module bounds explicitly at `BODY_WINDOW` blocks rather than
leaving it to be however much memory has leaked.  That makes short-range
catch-up — a restart, a pause, a partition that healed — work, and it is the
case that turns a tolerated fault back into a tolerated fault.  A node further
behind than the window needs state sync from a snapshot, which `store/snapshot.py`
can already certify and nothing schedules; that is part four's open item and
still open.

**What it is safe to believe.**  A stranger cannot induce a catch-up: the
trigger is a proposal header carrying a *verified leader signature* for a
height above ours, which `Seat._take_header` has already checked against the
roster.  And a peer cannot feed us a fabricated chain: every block is checked
by the same `SoloWorkload.validate` the ceremony uses, its quorum certificate
is verified against the register's own quorum and the roster's keys, and it
must chain onto the tip we hold.  Catch-up adopts nothing it could not have
agreed to itself.
"""
from __future__ import annotations

#: How many recent block bodies a node keeps so that it can serve them.  Also,
#: therefore, exactly how far behind a node may fall and still be helped by a
#: peer — which is the number this makes explicit.  At the shipped 19.75 s
#: block interval, 64 blocks is about 21 minutes.
BODY_WINDOW = 64

#: How many blocks to ask for at once.  A block of ~100 transactions is around
#: 6 MB against an 8 MB frame ceiling, so the batch is small on purpose and the
#: request repeats.
BATCH = 8

#: What one frame will carry of a state.  A peer refuses to serve more rather
#: than sending a frame nobody will accept; `store/snapshot.py` is chunked
#: precisely so ranges can come from different peers, and a state past this
#: needs that rather than a bigger frame.
MAX_SNAPSHOT = 6 << 20


class Catchup:
    """One node's buffer of blocks it is behind on, and the walk forward.

    Deliberately holds no references to the mesh or the store: it is handed
    blocks and a validator, and it says what it applied.  That is what makes it
    testable without a network.
    """

    def __init__(self, batch: int = BATCH):
        self.batch = batch
        self.blocks: dict = {}          # height -> NetworkBlock
        self.target = 0                 # highest height a leader has signed for
        self.applied = 0
        self.refused = 0
        self.requests = 0
        self.last_reason = ""

    # ── what we know we are missing ──────────────────────────────────────────

    def note_height(self, height: int):
        """Record a height a verified leader header claims.

        Only signed headers reach this, which is what stops a stranger from
        talking a node into a catch-up it does not need.
        """
        self.target = max(self.target, int(height))

    def behind(self, height: int) -> int:
        """How many blocks short of the highest signed height we are."""
        return max(0, self.target - int(height))

    def wanted(self, height: int):
        """The next run of heights worth asking for.  (from, to) or None."""
        if self.behind(height) <= 0:
            return None
        start = int(height) + 1
        end = min(self.target, start + self.batch - 1)
        # Anything already buffered at the front of the run needs no asking.
        while start <= end and start in self.blocks:
            start += 1
        if start > end:
            return None
        self.requests += 1
        return start, end

    def absorb(self, blocks) -> int:
        """Buffer blocks a peer sent.  Returns how many were new."""
        new = 0
        for block in blocks:
            try:
                height = int(block.height)
            except Exception:
                continue
            if height in self.blocks:
                continue
            self.blocks[height] = block
            self.target = max(self.target, height)
            new += 1
        return new

    def forget(self, height: int):
        """Drop buffered blocks at or below `height` — they are applied or dead."""
        for h in [h for h in self.blocks if h <= height]:
            del self.blocks[h]

    # ── the walk forward ─────────────────────────────────────────────────────

    def advance(self, apply_one, height_of, *, budget=None, limit: int = BATCH):
        """Apply buffered blocks in order for as long as they keep working.

        `apply_one(block) -> (ok, reason)` does the validating and applying;
        `height_of() -> int` reports the node's height after each step, because
        this class deliberately does not know where that lives.  `budget`, when
        given, is asked before each block: catching up is expensive, and a node
        that spends an entire epoch on it has replaced one way of being absent
        with another.

        Stops at the first block that does not apply.  A gap is not an error —
        the next request will ask for it — but a block that *should* have
        applied and did not is, and it is left where the log can see it.
        """
        done = 0
        while done < limit:
            nxt = int(height_of()) + 1
            block = self.blocks.get(nxt)
            if block is None:
                break
            if budget is not None and not budget():
                self.last_reason = "out of budget for this epoch"
                break
            ok, why = apply_one(block)
            if not ok:
                self.refused += 1
                self.last_reason = f"height {nxt}: {why}"
                # Dropped rather than retried: a block that does not validate
                # will not validate on the next pass either, and keeping it
                # would block the height for ever.  Asking again is cheap, and
                # a peer that keeps sending an invalid block is stage 4's
                # problem, not this loop's.
                del self.blocks[nxt]
                break
            del self.blocks[nxt]
            self.applied += 1
            done += 1
        self.forget(int(height_of()))
        return done

    def stats(self) -> dict:
        return {"target": self.target, "buffered": len(self.blocks),
                "applied": self.applied, "refused": self.refused,
                "requests": self.requests}

    def __repr__(self):
        return (f"Catchup(target={self.target}, {len(self.blocks)} buffered, "
                f"{self.applied} applied)")


def _certified(block) -> bool:
    return getattr(block, "quorum_cert", None) is not None


class BodyCache:
    """The last `window` block bodies, so a peer can be helped back.

    `self.bodies` was an unbounded dict keyed by hash, appended to on every
    block a node saw and never pruned — a leak, and an accidental answer to
    "how far back can a peer be helped", which is a question that deserves a
    number rather than a memory profile.
    """

    def __init__(self, window: int = BODY_WINDOW):
        self.window = window
        self._by_hash: dict = {}
        self._by_height: dict = {}

    def put(self, block):
        """Keep a body, and never replace a certified one with a bare one.

        A body is cached twice in the life of an epoch: once as the leader's
        *proposal*, which carries no certificate because there is nothing to
        certify yet, and once as the finalised block.  `Seat.accepted` used to
        be what bridged the two, by setting `quorum_cert` in place on the very
        object the cache held — which worked by aliasing and stopped working
        the moment a body arrived on a path that did not alias.  The result was
        a peer serving pre-agreement proposals to a node trying to catch up,
        and that node refusing every one of them for having no certificate.
        So the finalised block is now put here explicitly, and this method is
        careful about which copy wins.
        """
        digest = block.hash()
        if digest in self._by_hash and not _certified(block):
            return
        self._by_hash[digest] = block
        try:
            self._by_height[int(block.height)] = digest
        except Exception:
            pass
        self._evict()

    def _evict(self):
        while len(self._by_hash) > self.window:
            # Oldest by insertion, which for blocks is oldest by height.
            stale = next(iter(self._by_hash))
            self._by_hash.pop(stale, None)
            for h, digest in list(self._by_height.items()):
                if digest == stale:
                    del self._by_height[h]

    def get(self, digest: str):
        return self._by_hash.get(digest)

    def at(self, height: int):
        digest = self._by_height.get(int(height))
        return self._by_hash.get(digest) if digest else None

    def range(self, start: int, end: int, limit: int = BATCH,
              certified_only: bool = True):
        """Bodies for heights `start..end`, as many as are held.

        Certified only, by default: a node catching up has no way to check an
        uncertified body and will refuse it, so serving one wastes a round
        trip on both sides.  Fetch by *hash* is the other case and does not
        filter — a seat asking for the body of a proposal it holds a signed
        header for wants exactly the uncertified thing.
        """
        out = []
        for height in range(int(start), int(end) + 1):
            if len(out) >= limit:
                break
            block = self.at(height)
            if block is None or (certified_only and not _certified(block)):
                continue
            out.append(block)
        return out

    def __contains__(self, digest):
        return digest in self._by_hash

    def __len__(self):
        return len(self._by_hash)

    def __repr__(self):
        heights = sorted(self._by_height)
        span = f"{heights[0]}-{heights[-1]}" if heights else "empty"
        return f"BodyCache({len(self._by_hash)}/{self.window}, {span})"
