"""Notes — the unit of state on the fin6 private chain.

A note is this chain's UTXO.  It is a vector of field coordinates

    x_note = [ value, asset, owner, rho, blinder_0 … blinder_{k-1} ]

committed with a fixed public MQ map:

    v_note = NOTE_SYS.F(x_note)          NOTE_SYS = MQSystem(n_note)
    cm     = note_id(v_note)             compact hex id used by the ledger

Binding comes from MQ hardness (finding a second preimage of F is an MQ
inversion); hiding comes from the blinder coordinates, which carry full field
entropy so a low-entropy note — small value, known owner — cannot be
brute-forced from its published commitment.

The reason the commitment is an MQ map rather than a hash is that the
transaction proof has to *reason about it*: chain/txsystem.py embeds one copy of
NOTE_SYS's rows per note into the per-transaction system, so a single MQ proof
can relate a note's hidden value to the very commitment the ledger stores.  A
hash-based commitment would not be expressible in that language.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from mq.ms6 import MQSystem, P

from .crypto import h_bytes, h_field, h_hex, rand_field, owner_field
from .params import (ChainParams, NOTE_ASSET, NOTE_FIXED_COORDS, NOTE_OWNER,
                     NOTE_RHO, NOTE_VALUE)


# ═══════════════════════════════════════════════════════════════════════════════
# The public note commitment map
# ═══════════════════════════════════════════════════════════════════════════════

@lru_cache(maxsize=None)
def note_system(n_note: int, note_folds: int) -> MQSystem:
    """The fixed, public MQ map every note on the chain is committed under.

    Cached: it is a pure function of the parameters, every participant derives
    the identical system from the same seed, and building it costs O(n^3).
    """
    return MQSystem(n_note, fold_degree=2, m_rand=n_note - 1,
                    n_folds=note_folds, seed="fin6-note-sys")


def system_for(params: ChainParams) -> MQSystem:
    return note_system(params.n_note, params.note_folds)


def asset_field(name: str) -> int:
    """Map an asset name ('USD', 'shares:ACME') to its field element."""
    return h_field("asset", name)


# ═══════════════════════════════════════════════════════════════════════════════
# Note
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# Detection tags
# ═══════════════════════════════════════════════════════════════════════════════
#
# A tag is computed by the sender and re-computed by whoever is sorting the
# chain, so the arithmetic sits here where both can reach it.  What a tag is
# *for*, and what handing one to a node costs, is in wallet/sealing.py — the
# ledger neither makes them nor reads them.

#: How wide a detection tag is on the wire.  Three bytes is enough precision
#: that a node given the whole detection secret finds your outputs and almost
#: nothing else, and enough width that a client can ask it to match on far
#: fewer bits than that.
TAG_BYTES = 3


def tag_from_shared(shared: bytes) -> bytes:
    """The tag both sides compute, from the detection exchange."""
    return h_bytes("note-tag", shared)[:TAG_BYTES]


def tag_matches(tag: bytes, other: bytes, bits: int) -> bool:
    """Do these two tags agree on their first `bits` bits?"""
    bits = max(0, min(int(bits), 8 * TAG_BYTES))
    if bits == 0:
        return True
    whole, spare = divmod(bits, 8)
    if tag[:whole] != other[:whole]:
        return False
    if not spare:
        return True
    mask = (0xFF << (8 - spare)) & 0xFF
    return (tag[whole] & mask) == (other[whole] & mask)


@dataclass(frozen=True)
class Note:
    """The secret opening of one note.  Whoever holds this can spend it."""

    value: int
    asset: int
    owner: int              # field image of the owner's public key
    rho: int                # nullifier seed
    blinders: tuple

    @classmethod
    def create(cls, value: int, owner_pub_hex: str, params: ChainParams,
               asset: str | int = "USD", rho: int | None = None,
               blinders: tuple | None = None) -> "Note":
        if not 0 <= value < params.max_value:
            raise ValueError(
                f"value {value} outside [0, 2^{params.range_bits}) — "
                "raise range_bits or split the note")
        asset_fe = asset if isinstance(asset, int) else asset_field(asset)
        if blinders is None:
            blinders = tuple(rand_field() for _ in range(params.note_blinders))
        if len(blinders) != params.note_blinders:
            raise ValueError(
                f"expected {params.note_blinders} blinders, got {len(blinders)}")
        return cls(value=value, asset=asset_fe,
                   owner=owner_field(owner_pub_hex),
                   rho=rand_field() if rho is None else rho,
                   blinders=tuple(blinders))

    def coords(self) -> list:
        """x_note, in the coordinate order the note system expects."""
        x = [0] * (NOTE_FIXED_COORDS + len(self.blinders))
        x[NOTE_VALUE] = self.value % P
        x[NOTE_ASSET] = self.asset % P
        x[NOTE_OWNER] = self.owner % P
        x[NOTE_RHO] = self.rho % P
        for i, b in enumerate(self.blinders):
            x[NOTE_FIXED_COORDS + i] = b % P
        return x

    def commit(self, params: ChainParams):
        """(cm, v_note) — the ledger id and the full public commitment vector."""
        v = note_vector(self, params)
        return note_id(v), v

    def nullifier(self, params: ChainParams) -> str:
        return nullifier_id(note_id(note_vector(self, params)),
                            nullifier_value(self.coords()))

    def __repr__(self):
        return f"Note(value={self.value}, asset={hex(self.asset)[:8]}…)"


def note_vector(note: Note, params: ChainParams) -> list:
    """v_note = F(x_note) under the chain's public note system."""
    sys = system_for(params)
    x = note.coords()
    if len(x) != sys.n:
        raise ValueError(f"note has {len(x)} coordinates, system wants {sys.n}")
    return sys.F(sys.lift(x))


def note_id(v_note) -> str:
    """Compact ledger id for a note commitment vector."""
    return "cm:" + h_hex("note-id", [int(a) for a in v_note])


# ═══════════════════════════════════════════════════════════════════════════════
# Nullifiers
# ═══════════════════════════════════════════════════════════════════════════════
#
# The nullifier is a public quadratic form over the note's own coordinates.  It
# is quadratic rather than a hash for the same reason the commitment is: the
# transaction proof carries it as one more row, so the published nullifier is
# provably derived from the coordinates of the note actually being spent,
# without those coordinates ever appearing.
#
# **And the published id binds the commitment as well as that form**, which
# part nine added and which the form alone cannot do.  A quadratic form maps
# every note — eight coordinates at DEMO, forty-eight at STRONG — onto a
# single field element, so its fibres are enormous and, worse, easy to walk:
# the form is homogeneous of degree 2, so Q(-x) = Q(x), and solving Q(x) = t
# for one unconstrained blinder is a single square root mod P.
#
# That was exploitable, and not in the direction the design worried about.  A
# payer chooses every coordinate of the note it hands you, blinders included.
# So it could craft your note to have the same nullifier as a note it already
# held, spend its own note, and leave yours permanently unspendable: live and
# unspent in the UTXO set, and refused by every node as a double spend.  One
# payment to freeze a stranger's funds for good.
#
# Hashing the commitment in with the form makes the published id as
# discriminating as `cm` itself, so a collision now needs a collision in the
# note commitment vector.  It costs one extra hash input and it is why
# `nullifier_id` takes `cm`.

@lru_cache(maxsize=None)
def nullifier_coeffs(n_note: int) -> tuple:
    """Public symmetric quadratic form (i, j, c) with i <= j."""
    out = []
    for i in range(n_note):
        for j in range(i, n_note):
            c = h_field("nf-coeff", n_note, i, j)
            if c:
                out.append((i, j, c))
    return tuple(out)


def nullifier_value(coords) -> int:
    """Evaluate the nullifier form at a note's coordinates."""
    coords = [int(a) % P for a in coords]
    acc = 0
    for i, j, c in nullifier_coeffs(len(coords)):
        acc += c * coords[i] * coords[j]
    return acc % P


def nullifier_id(cm: str, fe: int) -> str:
    """The published spend marker for the note committed as `cm`.

    Both inputs, and `cm` is the one that makes it injective.  See the note
    above: the quadratic form on its own has walkable fibres, and a payer
    controls the coordinates of the note it pays you.
    """
    return "nf:" + h_hex("nf-id", cm, int(fe))
