"""The clock.  Nodes compute their epoch; nobody is told what it is.

The genesis document declares `effective_time` and `epoch_millis`, so every
node derives the same epoch number from the same wall time — which is the whole
of the schedule.  Everything else here is deadlines carved out of one epoch:

    seat        epoch_start
    decide by   epoch_start + decide_at  * epoch_millis
    commit by   epoch_start + commit_at  * epoch_millis

`skew_ms` is deliberate and belongs to the harness: a testnet that cannot run a
node with a wrong clock cannot find out what a wrong clock does.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone


def parse_time(text: str) -> int:
    """RFC3339 to epoch milliseconds."""
    cleaned = text.replace("Z", "+00:00")
    return int(datetime.fromisoformat(cleaned)
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


@dataclass
class Clock:
    effective_ms: int
    epoch_millis: int
    skew_ms: int = 0
    decide_at: float = 0.60
    commit_at: float = 0.80

    @classmethod
    def from_genesis(cls, doc, skew_ms: int = 0, effective_ms=None) -> "Clock":
        return cls(effective_ms=(parse_time(doc.effective_time)
                                 if effective_ms is None else effective_ms),
                   epoch_millis=doc.epoch_millis, skew_ms=skew_ms)

    # ── now ──────────────────────────────────────────────────────────────────

    def now_ms(self) -> int:
        return int(time.time() * 1000) + self.skew_ms

    def epoch_now(self) -> int:
        return self.epoch_at(self.now_ms())

    def epoch_at(self, when_ms: int) -> int:
        if when_ms < self.effective_ms:
            return 0
        return (when_ms - self.effective_ms) // self.epoch_millis + 1

    # ── boundaries ───────────────────────────────────────────────────────────

    def start_of(self, epoch: int) -> int:
        return self.effective_ms + (epoch - 1) * self.epoch_millis

    def decide_deadline(self, epoch: int) -> int:
        return self.start_of(epoch) + int(self.decide_at * self.epoch_millis)

    def commit_deadline(self, epoch: int) -> int:
        return self.start_of(epoch) + int(self.commit_at * self.epoch_millis)

    # ── views ────────────────────────────────────────────────────────────────
    #
    # A view change needs a timeout, and a timeout every seat agrees about is
    # the one thing this design already has for free: nobody is told what the
    # epoch is either.  So the decide window is cut into equal slices and a
    # seat that has not accepted a block when its slice ends moves on.  No
    # timer negotiation, no back-off, and no view change about the view change.
    # See docs/view_change_design.md §3 for what that costs.

    def views_for(self, cap: int, min_view_ms: int) -> int:
        """How many views this epoch's decide window can actually hold.

        The budget comes from the clock rather than from configuration, because
        a view is a slice of a fixed window: asking for three views of a 2.5 s
        epoch gives three views too short to finish an honest ceremony in,
        which is worse than no view change at all — every view times out and
        the height never advances.  A deployment with a fast epoch simply does
        not get view changes, and says so by arithmetic rather than by a flag
        somebody forgot to set.
        """
        window = int(self.decide_at * self.epoch_millis)
        return max(1, min(cap, window // max(1, min_view_ms)))

    def view_deadline(self, epoch: int, view: int, max_views: int) -> int:
        """When view `view` gives up.  The last one runs to the decide
        deadline, so the slices never overrun the epoch."""
        if max_views < 1:
            raise ValueError("an epoch has at least one view")
        start = self.start_of(epoch)
        window = self.decide_deadline(epoch) - start
        if view >= max_views - 1:
            return self.decide_deadline(epoch)
        return start + (window * (view + 1)) // max_views

    def view_at(self, epoch: int, when_ms: int, max_views: int) -> int:
        """Which view that instant falls in — what a seat joining late uses to
        avoid attesting into a view everyone else has left."""
        for view in range(max_views):
            if when_ms < self.view_deadline(epoch, view, max_views):
                return view
        return max_views - 1

    def sleep_until(self, when_ms: int, stop=None) -> bool:
        """Wait, in short naps so a stop flag is noticed.  False if stopped."""
        while True:
            remaining = (when_ms - self.now_ms()) / 1000
            if remaining <= 0:
                return True
            if stop is not None and stop.is_set():
                return False
            time.sleep(min(remaining, 0.05))

    def wait_for_next_epoch(self, after: int, stop=None):
        """Block until an epoch strictly after `after` has started.

        A node that wakes inside an epoch it has already missed does not try to
        join it half-way; it waits for the next boundary.
        """
        target = max(after + 1, self.epoch_now())
        if not self.sleep_until(self.start_of(target), stop):
            return None
        return target
