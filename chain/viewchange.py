"""Moving to the next view, and what the new leader is bound by.

Part eleven, review C1. `docs/view_change_design.md` has the argument; this is
the statement and the rule.

The one thing to keep in mind while reading: a view change is not a retry. A
retry assumes nothing happened. A view change has to survive the case where
something *did* happen — a block finalised at one seat while the others were
giving up on it — and that is what the lock, and the obligation it puts on the
next leader, are for.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import h_bytes, h_hex, verify_sig


class ViewError(Exception):
    pass


@dataclass(frozen=True)
class ViewChange:
    """One seat saying: I am moving to view v, and here is what I am holding.

    The lock is the payload. A seat that attested in an earlier view carries
    that vote forward rather than forgetting it, because forgetting it is
    precisely how two blocks finalise at one height.
    """
    node_id: str
    public_hex: str
    chain_id: str
    height: int
    epoch: int
    view: int                      # the view being moved *to*
    locked_view: int = -1          # -1 when this seat holds no lock
    locked_hash: str = ""
    signature: str = ""

    @property
    def locked(self) -> bool:
        return self.locked_view >= 0 and bool(self.locked_hash)

    @staticmethod
    def message(chain_id, node_id, height, epoch, view, locked_view,
                locked_hash) -> bytes:
        return h_bytes("view-change", chain_id, node_id, height, epoch, view,
                       locked_view, locked_hash)

    def verify(self) -> bool:
        return verify_sig(self.public_hex, self.message(
            self.chain_id, self.node_id, self.height, self.epoch, self.view,
            self.locked_view, self.locked_hash), self.signature)


def sign_view_change(node, height: int, epoch: int, view: int,
                     lock=None) -> ViewChange:
    """`lock` is (view, block_hash) or None."""
    locked_view, locked_hash = lock if lock else (-1, "")
    msg = ViewChange.message(node.chain_id, node.id, height, epoch, view,
                             locked_view, locked_hash)
    return ViewChange(node_id=node.id, public_hex=node.public_hex,
                      chain_id=node.chain_id, height=height, epoch=epoch,
                      view=view, locked_view=locked_view,
                      locked_hash=locked_hash,
                      signature=node.signer.sign(msg))


@dataclass(frozen=True)
class ViewChangeCert:
    """The quorum of view-change messages a new leader proposes under.

    It travels with the proposal, which is the point: the leader and every seat
    have to reach the same conclusion about what may be proposed, and they can
    only do that by reading the same evidence. A seat that evaluated its own
    collection instead would refuse honest proposals whenever its set differed
    from the leader's — safe, and unable to make progress.
    """
    view: int
    changes: tuple = field(default=())

    def digest(self) -> str:
        """Bound into the proposal's signature, so the certificate cannot be
        swapped for another quorum that permits a different block."""
        return h_hex("view-cert", self.view,
                     sorted(f"{c.node_id}:{c.locked_view}:{c.locked_hash}"
                            for c in self.changes))

    def signers(self) -> tuple:
        return tuple(sorted({c.node_id for c in self.changes}))

    def check(self, *, chain_id: str, height: int, epoch: int, view: int,
              quorum: int, validators: dict) -> tuple:
        """(ok, reason).  Never raises."""
        try:
            if view != self.view:
                return False, (f"certificate is for view {self.view}, this is "
                               f"view {view}")
            seen = set()
            for c in self.changes:
                if not isinstance(c, ViewChange):
                    return False, "certificate carries something that is not a "\
                                  "view change"
                if (c.chain_id, c.height, c.epoch, c.view) != \
                        (chain_id, height, epoch, view):
                    return False, f"{c.node_id}'s view change is for another " \
                                  f"height, epoch or view"
                key = validators.get(c.node_id)
                if key is None or key != c.public_hex:
                    return False, f"{c.node_id} is not a seat in this grid"
                if c.node_id in seen:
                    return False, f"{c.node_id} appears twice"
                if not c.verify():
                    return False, f"{c.node_id}'s view change is not signed"
                seen.add(c.node_id)
            if len(seen) < quorum:
                return False, (f"{len(seen)} view changes, quorum is {quorum}")
            return True, "ok"
        except Exception as exc:
            return False, f"malformed certificate: {exc.__class__.__name__}"

    def required_block(self) -> str | None:
        """The block this certificate obliges the leader to re-propose, if any.

        The highest locked view wins; a tie is broken by the block hash so two
        readers of the same certificate never disagree. None means the locks
        are all empty and the leader may build something new.
        """
        best = None
        for c in self.changes:
            if not c.locked:
                continue
            key = (c.locked_view, c.locked_hash)
            if best is None or key > best:
                best = key
        return None if best is None else best[1]


def may_propose(cert: ViewChangeCert | None, block_hash: str,
                view: int) -> tuple:
    """(ok, reason) for a proposal in `view` carrying `cert`.

    View 0 needs no certificate — there is nothing to carry forward into the
    first attempt at a height.
    """
    if view == 0:
        return (True, "ok") if cert is None or not cert.changes else \
            (False, "view 0 carries no view-change certificate")
    if cert is None:
        return False, "a proposal after view 0 must carry its view change"
    required = cert.required_block()
    if required is not None and required != block_hash:
        return False, (f"the view change locks {required[:14]}…, this "
                       f"proposal is {block_hash[:14]}…")
    return True, "ok"
