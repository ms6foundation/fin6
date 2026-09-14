"""The canonical seat order, and what a certificate can say once it exists.

A quorum certificate names who signed it.  Today that is a sorted tuple of node
ids, which is the honest shape and the expensive one: at 667 seats the ids
alone are most of the certificate, repeated every epoch, for ever.

The compact shape is a bitmap — one bit a seat, set if that seat signed — and a
bitmap is meaningless without an order to index into.  So the order has to be
something every reader derives identically and nobody can choose after the
fact, which means it has to be *committed*, in the header, at the height the
certificate is for.  That commitment is the whole of this module's reason to
exist, and it is why the work lands before genesis rather than after: the
header is hashed into the chain, so adding a field later is a new chain.

The order itself is deliberately the dullest thing available — the grid's
seated membership, sorted by node id.  Sorted rather than seated-position or
join-order because a sort is a function of the set and nothing else: two nodes
that agree on who is in a grid cannot disagree about the order, there is no
tie-break to get wrong, and a founding that moves members between grids cannot
silently renumber the ones that stayed.

None of this aggregates signatures.  It is the half of that change that costs
nothing to decide now: see docs/quorum_signature_decision.md.
"""
from __future__ import annotations

from .crypto import h_hex
from .seal import seal_root


class SeatError(Exception):
    """A seat that is not in the order, or a bitmap that does not fit it."""


def canonical_order(members) -> tuple:
    """The order a bitmap indexes into: the seated set, sorted by node id.

    A set, not a sequence — a member listed twice is one seat, and the genesis
    document already refuses a roster with a duplicate id.
    """
    return tuple(sorted(set(members)))


def seats_digest(grid_id: str, order) -> str:
    """One grid's order, as one value.

    Includes the grid id, so an order cannot be lifted from the grid it was
    committed for and presented as another's.
    """
    return h_hex("seats", grid_id, list(order))


def seats_root(orders: dict) -> str:
    """Every grid's order in the block, as one value for the header.

    `orders` maps grid_id -> order.  Sorted by grid id, so the root is a
    function of the mapping rather than of the order the builder happened to
    walk it in.
    """
    return "sr:" + h_hex("seats-root", seal_root(
        "seats", [f"{gid}:{seats_digest(gid, order)}"
                  for gid, order in sorted(orders.items())]))


# ── the bitmap ───────────────────────────────────────────────────────────────
#
# Little-endian within each byte: seat i is bit (i % 8) of byte (i // 8).  The
# length is ceil(n/8) bytes for n seats regardless of how many signed, which is
# the point — a certificate's size stops depending on who turned up.

def to_bits(signers, order) -> str:
    """Hex bitmap over `order`.  Every signer must be a seat in it."""
    index = {nid: i for i, nid in enumerate(order)}
    raw = bytearray((len(order) + 7) // 8)
    for nid in signers:
        i = index.get(nid)
        if i is None:
            raise SeatError(f"{nid} is not a seat in this order")
        raw[i // 8] |= 1 << (i % 8)
    return raw.hex()


def from_bits(bits: str, order) -> tuple:
    """The seats a bitmap names, in the order's own order.

    Refuses a bitmap of the wrong length or with a bit set past the last seat,
    because both are a reader and a writer disagreeing about the seat count —
    which is the one way a bitmap can silently mean something else.
    """
    width = (len(order) + 7) // 8
    try:
        raw = bytes.fromhex(bits)
    except ValueError as exc:
        raise SeatError(f"bitmap is not hex: {exc}") from exc
    if len(raw) != width:
        raise SeatError(f"bitmap is {len(raw)} bytes, {len(order)} seats "
                        f"need {width}")
    spare = width * 8 - len(order)
    if spare and raw[-1] >> (8 - spare):
        raise SeatError("bitmap sets a bit past the last seat")
    return tuple(nid for i, nid in enumerate(order)
                 if raw[i // 8] >> (i % 8) & 1)


def bitmap_bytes(n_seats: int) -> int:
    return (n_seats + 7) // 8
