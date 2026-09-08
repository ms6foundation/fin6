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
# Sending a note to its owner
# ═══════════════════════════════════════════════════════════════════════════════

FIELD_BYTES = 32
NONCE = b"\x00" * 12


class NoteCipherError(Exception):
    pass


def _pack_opening(note, params) -> bytes:
    """value, asset, rho, blinders — everything but the owner, which the
    recipient already knows because it is the recipient."""
    parts = [note.value, note.asset, note.rho, *note.blinders]
    if len(parts) != 3 + params.note_blinders:
        raise NoteCipherError("note does not match the parameters")
    return b"".join(int(x).to_bytes(FIELD_BYTES, "big") for x in parts)


def _unpack_opening(raw: bytes, owner: int, params):
    want = FIELD_BYTES * (3 + params.note_blinders)
    if len(raw) != want:
        raise NoteCipherError(f"opening is {len(raw)} bytes, expected {want}")
    values = [int.from_bytes(raw[i:i + FIELD_BYTES], "big")
              for i in range(0, len(raw), FIELD_BYTES)]
    return Note(value=values[0], asset=values[1], owner=owner,
                rho=values[2], blinders=tuple(values[3:]))


def encrypt_opening(note, address, cm: str, params) -> bytes:
    """Seal this note's opening to its recipient.

    `epk || ciphertext`, where the key is a fresh X25519 exchange and the
    commitment is the associated data — so a ciphertext cannot be lifted onto
    a different output, and a nonce of zero is safe because every output has
    its own ephemeral key and therefore its own shared secret.

    272 bytes at the demo parameters, against a 63 KB proof.  This is what
    makes a note recoverable from a seed rather than only from a backup of the
    wallet's own files.
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from .keys import ephemeral
    private, epk = ephemeral()
    shared = private.exchange(address.view_key())
    key = h_bytes("note-key", shared, epk, cm)
    blob = ChaCha20Poly1305(key).encrypt(NONCE, _pack_opening(note, params),
                                         cm.encode())
    return epk + blob


def decrypt_opening(blob: bytes, keys, cm: str, params):
    """The note, if this output was addressed to these keys — else None.

    Returns None rather than raising: a wallet trial-decrypts every output on
    the chain, and almost all of them are somebody else's.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    if not isinstance(blob, (bytes, bytearray)) or len(blob) <= 32:
        return None
    epk, body = bytes(blob[:32]), bytes(blob[32:])
    try:
        shared = keys.exchange(epk)
    except Exception:
        return None
    key = h_bytes("note-key", shared, epk, cm)
    try:
        raw = ChaCha20Poly1305(key).decrypt(NONCE, body, cm.encode())
    except (InvalidTag, ValueError):
        return None
    try:
        note = _unpack_opening(raw, owner_field(keys.spend_hex), params)
    except NoteCipherError:
        return None
    # The commitment is the last word: a sender who encrypts an opening that
    # does not match the output it is attached to has sent nothing.
    if note_id(note_vector(note, params)) != cm:
        return None
    return note


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
        return nullifier_id(nullifier_value(self.coords()))

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


def nullifier_id(fe: int) -> str:
    return "nf:" + h_hex("nf-id", int(fe))
