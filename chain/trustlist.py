"""Each node's private view of the others.

This is the subjective half of trust, and it is deliberately powerless.  It is
built from watching — who was present, who was reliable, who a node has simply
seen a lot of — and none of it can be proven to a third party, so two honest
nodes will legitimately disagree.

What it may decide: which peers to keep and relay to first, which nearby grid to
prefer when enrolling, how to rank leader candidates in an advisory hint, where
to spend audit effort.

What it may never decide: whose attestation counts.  That comes from the grid
register alone.  If a node's private list could set its quorum, this would stop
being a quorum system and become Federated Byzantine Agreement, where safety
depends on a quorum-intersection condition across every honest node's slices and
drifting lists split the network into disjoint quorums that each believe they are
final.  Nothing in chain/ passes a TrustList to a quorum computation, and
chain/tests/test_tiers.py asserts that finality is unchanged when trust lists
are deliberately made to disagree.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TrustEntry:
    node_id: str
    seen: int = 0            # ceremonies observed together
    agreed: int = 0          # attested the block that was finalised
    absent: int = 0          # seated but silent
    score: float = 0.0


class TrustList:
    """One node's opinion of everyone it has watched."""

    def __init__(self, owner: str, increase: float = 1.0, decay: float = 0.5,
                 cap: float = 50.0):
        self.owner = owner
        self.increase = increase
        self.decay = decay
        self.cap = cap
        self.entries: dict = {}

    def _entry(self, node_id: str) -> TrustEntry:
        return self.entries.setdefault(node_id, TrustEntry(node_id=node_id))

    # ── observation ──────────────────────────────────────────────────────────

    def observe(self, roll, finalised_hash: str | None, agreed_with=()):
        """Fold one ceremony this node witnessed into its private view.

        `agreed_with` is the seats that attested to the block that finalised.
        It used to be a map of whole attestations, from which this asked each
        one what block it had signed — a question a certificate answers once
        for all of its signers, since they all sign the same statement. Part
        nine's compact certificate no longer carries per-seat copies of it, so
        the caller resolves it and passes the names.
        """
        attended = set(roll.attended)
        agreed_with = set(agreed_with)
        for nid in roll.seated:
            if nid == self.owner:
                continue
            e = self._entry(nid)
            e.seen += 1
            if nid in attended:
                if finalised_hash and nid in agreed_with:
                    e.agreed += 1
                e.score = min(self.cap, e.score + self.increase)
            else:
                e.absent += 1
                e.score = max(0.0, e.score * self.decay)

    def penalise(self, node_id: str, to_zero: bool = True):
        e = self._entry(node_id)
        e.score = 0.0 if to_zero else max(0.0, e.score * self.decay)

    # ── use (preferences only) ───────────────────────────────────────────────

    def score(self, node_id: str) -> float:
        e = self.entries.get(node_id)
        return e.score if e else 0.0

    def trusted(self, threshold: float = 1.0) -> list:
        return sorted(n for n, e in self.entries.items() if e.score >= threshold)

    def rank(self, candidates) -> list:
        """Advisory ordering — a hint, never an override."""
        return sorted(candidates, key=lambda n: (-self.score(n), n))

    def __len__(self):
        return len(self.entries)

    def __repr__(self):
        return f"TrustList({self.owner}, {len(self.entries)} watched)"
