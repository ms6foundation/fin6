"""Undo records: how the ledger goes backwards, and how far back it can go.

`ChainState` only moves forward.  A reorg needs it to move back, and the record
that lets it is the exact inverse of what a network block applied:

    unspend    the notes the block consumed — flip the dead bit back
    truncate   the notes it created — drop them off the tail
    nullifiers the markers it published — drop them off the tail
    fees       what it burned

Truncation is the interesting part.  It is legitimate *only* because the
accumulator is append-only and undo is strictly last-in-first-out: the notes a
block created are exactly the tail of the set, so long as no later block has
touched them.  So the store refuses to undo anything but the tip, which is a
stronger and far cheaper invariant than general-purpose rollback — and the
accumulator refuses too, independently, if a value being dropped turns out to
have been spent since.

**How far back to keep records is not a judgement call.**  The hardening layer
bounds a rewrite absolutely: an attacker can only re-cast turns it still holds,
so

    max fork depth = attacker's unspent turns / width

and keeping undo for that depth is keeping it for every reorg that can happen.
Past it, a block is irreversible by storage policy as well as by weight, which
is an honest statement of a limit rather than an accident.
"""
from __future__ import annotations

from dataclasses import dataclass


class UndoError(Exception):
    pass


@dataclass(frozen=True)
class UndoRecord:
    """Everything needed to put one network block back in the box."""
    height: int
    block_hash: str
    prev_tip: str
    unspend: tuple = ()
    created: tuple = ()
    nullifiers: tuple = ()
    fees: int = 0
    prev_utxo_root: int = 0
    prev_nf_root: int = 0
    prev_height: int = -1
    # Pre-images of the registers this block advanced.  Standing is a
    # deterministic function of the rolls, but not an invertible one — a
    # counter that reset cannot say what it was — so the only way back is to
    # have kept what it was.
    registers: tuple = ()

    def summary(self) -> str:
        return (f"undo(h={self.height}: +{len(self.unspend)} unspent, "
                f"-{len(self.created)} notes, -{len(self.nullifiers)} nf)")


def capture(state, delta, *, height: int, block_hash: str,
            registers=()) -> UndoRecord:
    """Take the record **before** the delta is applied.

    The roots and the tip go in as they are now, so applying the record later
    can check that it landed where it said it would rather than trusting that it
    did.
    """
    return UndoRecord(
        height=height,
        block_hash=block_hash,
        prev_tip=state.tip,
        prev_height=state.height,
        unspend=tuple(delta.spent),
        created=tuple(delta.created),
        nullifiers=tuple(delta.nullifiers),
        fees=delta.fees,
        prev_utxo_root=state.utxo.root,
        prev_nf_root=state.nullifiers.root,
        registers=tuple(r.dump() for r in registers),
    )


def apply_undo(state, record: UndoRecord):
    """Roll one block off the tip, and prove it by the roots.

    Order matters and is the mirror of `apply_delta`: created notes and
    nullifiers come off the tail first, then the spent notes come back.  Doing
    it the other way would put a note back into a set that still contained the
    note that replaced it.
    """
    if state.height != record.height:
        raise UndoError(f"undo is for height {record.height}, state is at "
                        f"{state.height} — undo only ever applies to the tip")
    state.utxo.truncate(len(record.created))
    state.nullifiers.truncate(len(record.nullifiers))
    for cm in record.unspend:
        state.utxo.unspend(cm)
    state.burned_fees -= record.fees
    state.history.truncate_to(record.prev_height)
    state.height = record.prev_height
    state.tip = record.prev_tip
    if state.utxo.root != record.prev_utxo_root:
        raise UndoError("utxo root does not match the state before the block")
    if state.nullifiers.root != record.prev_nf_root:
        raise UndoError("nullifier root does not match the state before the "
                        "block")
    return state


def retention_depth(hardening_params, attacker_share: float = 1 / 3) -> int:
    """How many undo records to keep, from the share of the pool you are
    willing to be reorged by.  Bitcoin cannot compute this; the finite pool is
    what makes it computable."""
    return max(1, hardening_params.max_fork_depth(attacker_share))
