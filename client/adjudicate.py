"""The adjudicating client: two tips, and the arithmetic that decides.

A following client trusts the validator register — which works right up to the
moment the register is the thing being lied about.  Two nodes hand back two
tips, each with a certificate from a different seat set, and signatures cannot
settle it because both sets sign honestly by their own lights.

Only work can.  This module is convened when that happens and not before: at
1.3 KB a block a client follows certificates all day, and at 86 KB a block it
downloads stamps for a disputed range once.  Pricing the second as the everyday
cost is what makes people conclude that light clients are impossible on chains
where they are merely unnecessary.
"""
from __future__ import annotations

from dataclasses import dataclass

from chain.crypto import h_bytes
from chain.hardening.history import HardenedBlock, NetworkHistory
from chain.hardening.pool import EraSpec

@dataclass
class Branch:
    """One node's claim about history, after the client has checked it."""
    source: str
    tip: str = ""
    height: int = 0
    cumulative: int = 0
    blocks: int = 0
    stamps: int = 0
    ok: bool = False
    reason: str = "not examined"

    def __repr__(self):
        return (f"Branch({self.source}, h={self.height}, "
                f"weight={self.cumulative:,}, "
                f"{'ok' if self.ok else self.reason})")


class Adjudicator:
    """Rebuild each branch, check the work, and say what the work says.

    The arithmetic is unusually clean.  A branch that
    reuses a turn already spent on its own history is invalid outright and
    turns are consumed per branch, so an attacker cannot re-cast what the
    honest chain burned; it can only spend its own, which puts a ceiling on how
    deep it can ever reach:

        max fork depth = attacker's unspent turns / width

    That is a bound, not a probability, and it is computable — which is what
    lets `settled_depth` answer "how many blocks until this payment cannot be
    unsaid" with a number rather than a convention.

    This client verifies rather than tallies.  It rebuilds each branch in its
    own `NetworkHistory` and re-runs every check: that the committee is the one
    the draw produces, that each stamp solves its puzzle and opens to the era
    root, that no turn is spent twice on a branch, and that the weight claimed
    is the weight of the stamps present.  A node's `cumulative` field is never
    read as evidence; it is only compared against what the client computed, and
    a disagreement is reported rather than resolved.
    """

    def __init__(self, doc, *, era_spec: EraSpec | None = None):
        self.doc = doc
        self.params = doc.hardening_params()
        self.spec = era_spec or self.derive_spec(doc)

    @staticmethod
    def derive_spec(doc) -> EraSpec:
        """Rebuild era 0 from the genesis document.

        Deriving it means holding the master seed, which in this dev model
        every node does — the README's "distribution is the security parameter"
        caveat, in the one place a reader will trip over it.  A deployment
        publishes the era root in the genesis document and derives nothing; the
        client code below does not care which, because all it uses is the spec.
        """
        from chain.hardening.pool import Era
        hp = doc.hardening_params()
        return Era(0, h_bytes("era-seed", doc.digest()),
                   hp.tree_height, hp.turns).spec

    # ── one branch ───────────────────────────────────────────────────────────

    def examine(self, client, name: str | None = None) -> Branch:
        """Fetch a node's hardened chain and check every block of it."""
        source = name or f"{client.host}:{client.port}"
        branch = Branch(source=source)
        try:
            answer = client.weight(since=1)
        except Exception as exc:
            branch.reason = f"could not be asked: {exc}"
            return branch
        era = answer.get("era") or {}
        if era.get("root") != self.spec.root.hex():
            branch.reason = "that node is hardening under another era"
            return branch

        history = NetworkHistory(self.spec, self.params)
        for row in answer.get("blocks", []):
            hb = HardenedBlock(
                block_hash=row["block_hash"], height=int(row["height"]),
                prev_hash=row["prev"], era_id=int(row["era_id"]),
                drawn=tuple(int(t) for t in row["drawn"]),
                stamps=tuple(row["stamps"]),
                weight=int(row["weight"]), cumulative=int(row["cumulative"]),
                spent_root=int(row["spent_root"]))
            ok, why = history.accept(hb)
            if not ok:
                branch.reason = f"height {hb.height}: {why}"
                branch.blocks = len(history.blocks)
                return branch
            branch.stamps += len(hb.stamps)
        if not history.blocks:
            branch.reason = "that node has hardened nothing"
            return branch
        branch.ok = True
        branch.reason = "ok"
        branch.tip = history.tip_hash
        branch.height = history.height
        branch.cumulative = history.cumulative_weight
        branch.blocks = len(history.blocks)
        return branch

    # ── two of them ──────────────────────────────────────────────────────────

    def weigh(self, sources: dict) -> dict:
        """{name: client} -> what the work says.

        Returns every branch it examined, whether they agree, and which one
        wins if they do not.  It does not adopt anything: choosing is the
        caller's, and a client that silently switched chains on the strength of
        a fork-choice rule would be doing the one thing this whole module
        exists to avoid.
        """
        branches = [self.examine(c, name=n) for n, c in sorted(sources.items())]
        good = [b for b in branches if b.ok]
        if not good:
            return {"decision": "no branch could be verified",
                    "branches": branches, "agree": False, "winner": None}
        tips = {b.tip for b in good}
        if len(tips) == 1:
            return {"decision": "the sources agree", "branches": branches,
                    "agree": True, "winner": good[0].tip,
                    "cumulative": max(b.cumulative for b in good)}
        best = max(good, key=lambda b: (b.cumulative, b.height, b.tip))
        rivals = [b for b in good if b.tip != best.tip]
        margin = best.cumulative - max(b.cumulative for b in rivals)
        return {
            "decision": f"{best.source} carries the most work",
            "branches": branches, "agree": False, "winner": best.tip,
            "winner_source": best.source, "cumulative": best.cumulative,
            "margin": margin,
            "margin_blocks": margin // max(1, self.params.stamp_weight
                                           * self.params.threshold),
        }

    # ── how deep is settled ──────────────────────────────────────────────────

    def settled_depth(self, attacker_share: float = 1 / 3) -> int:
        """How deep a rewrite could reach, for an attacker holding this share.

        The number a wallet should show instead of a spinner.  It is a bound,
        not a probability: below this depth a payment can still be unsaid, and
        above it there are not enough unspent turns in the pool to reach it.
        """
        return self.params.max_fork_depth(attacker_share)

    def is_settled(self, confirmations: int,
                   attacker_share: float = 1 / 3) -> bool:
        return confirmations > self.settled_depth(attacker_share)

    def __repr__(self):
        return (f"Adjudicator(era {self.spec.era_id}, "
                f"{self.params.turns:,} turns, width {self.params.width})")
