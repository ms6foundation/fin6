"""Sealing a note to its recipient, and tagging it so they can find it.

The chain stores a commitment; a commitment is a hash of an opening, so a
recipient cannot recognise its own output by looking at the chain.  This module
is the answer to that: every output carries its opening encrypted to the
address it was sent to, and a short tag that lets somebody else sort the chain
on the recipient's behalf without being able to read it.

It lives in `wallet/` rather than `chain/` because none of it is the ledger's
business.  A validator checks a proof, applies a delta and moves on; it never
opens a ciphertext and could not if it wanted to.  What the ledger does keep is
the two tag primitives in `chain/notes.py` — a node computes tags when it is
asked to sort, and the arithmetic has to be the same on both sides.

    seal_output      (sealed opening, detection tag) for one output
    decrypt_opening  the recipient's side; returns None, never raises
    detection_tag    the sender's side of the tag, and what it costs
"""
from __future__ import annotations

from chain.crypto import ephemeral, h_bytes, owner_field
from chain.notes import (Note, TAG_BYTES, note_id, note_vector,
                         tag_from_shared)

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


def detection_tag(private, address) -> bytes:
    """The sender's side: tag this output to its recipient's detection key.

    What this buys, and what it costs, stated plainly.

    *Buys:* a wallet no longer has to read every ciphertext on the chain to
    find its own.  It hands a node the detection secret and a precision — how
    many bits of the tag to match on — and gets back the outputs that match,
    which is its own plus a 2^-bits share of everybody else's.  At eight bits
    that is a 256-fold cut in what has to be downloaded and trial-decrypted;
    part eight measured the alternative at 538 MB a day.

    *Costs:* the node learns that a set of outputs, one of which is probably
    yours, is worth watching.  The precision is the knob, and the honest
    caveat is that it is a knob the **node** turns: it is handed the whole
    detection secret and asked to compare only some of the bits.  A node that
    ignores the request computes the whole tag and identifies your outputs
    exactly.  So this construction bounds the *bandwidth* cryptographically
    and the *disclosure* only behaviourally.

    Binding it properly needs one detection key per tag bit, so that a client
    can hand over the first p keys and the node is unable to compute bit p+1 —
    the fuzzy-message-detection construction §09 named.  That costs 32 bytes of
    address per bit, which at eight bits is a 570-character address, and it
    remains the open item.  What is here is the useful half of it, said out
    loud rather than implied.
    """
    return tag_from_shared(private.exchange(address.detect_key()))


def encrypt_opening(note, address, cm: str, params) -> bytes:
    """Seal this note's opening to its recipient.

    `epk || ciphertext`, where the key is a fresh X25519 exchange and the
    commitment is the associated data — so a ciphertext cannot be lifted onto
    a different output, and a nonce of zero is safe because every output has
    its own ephemeral key and therefore its own shared secret.

    272 bytes at the demo parameters, against a 63 KB proof.  This is what
    makes a note recoverable from a seed rather than only from a backup of the
    wallet's own files.

    The ciphertext alone, for callers that do not want a tag.  `seal_output`
    is what a transaction uses.
    """
    return seal_output(note, address, cm, params)[0]


def seal_output(note, address, cm: str, params):
    """(sealed opening, detection tag) for one output.

    One ephemeral key serves both: the ciphertext's exchange is against the
    viewing key and the tag's against the detection key, so holding the tag
    tells you nothing about the opening and holding the opening tells you
    nothing you did not already have.
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    private, epk = ephemeral()
    shared = private.exchange(address.view_key())
    key = h_bytes("note-key", shared, epk, cm)
    blob = ChaCha20Poly1305(key).encrypt(
        NONCE, _pack_opening(note, params), cm.encode())
    tag = (detection_tag(private, address) if address.detect_hex
           else b"\x00" * TAG_BYTES)
    return epk + blob, tag


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
