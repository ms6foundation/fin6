"""Hashing, field, and signature helpers.

Deliberately thin.  All the real cryptography — MQ commitments, the 5-pass SSH
zero-knowledge proof, seal trees — comes from mq/ms6 and mq/vs6 unchanged; this
module only supplies domain-separated hashing and a validator signature scheme.

NOTE on the signature scheme: Ed25519 is a placeholder.  The rest of this stack
is post-quantum by construction (MQ hardness, "no factoring/DL anywhere" per
mq/mq.md), so shipping Ed25519 for attestations is an inconsistency, tracked as
the design's open item "quorum signature scheme".  The Signer/verify interface
below is the seam where a PQ scheme drops in.
"""
from __future__ import annotations

import hashlib
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mq.ms6 import P

DOMAIN = "fin6-chain-v1"


# ═══════════════════════════════════════════════════════════════════════════════
# Domain-separated hashing
# ═══════════════════════════════════════════════════════════════════════════════

def _encode(part) -> bytes:
    if isinstance(part, (bytes, bytearray)):
        return b"b" + bytes(part)
    if isinstance(part, bool):
        return b"o" + (b"1" if part else b"0")
    if isinstance(part, int):
        return b"i" + str(part).encode()
    if isinstance(part, str):
        return b"s" + part.encode()
    if isinstance(part, (list, tuple)):
        inner = b"".join(_len_prefixed(_encode(p)) for p in part)
        return b"l" + inner
    if part is None:
        return b"n"
    raise TypeError(f"cannot hash value of type {type(part).__name__}")


def _len_prefixed(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def h_bytes(tag: str, *parts, length: int = 32) -> bytes:
    """SHAKE-256 digest over (domain, tag, parts), unambiguously encoded."""
    h = hashlib.shake_256()
    h.update(_len_prefixed(f"{DOMAIN}:{tag}".encode()))
    for part in parts:
        h.update(_len_prefixed(_encode(part)))
    return h.digest(length)


def h_hex(tag: str, *parts) -> str:
    return h_bytes(tag, *parts).hex()


def h_field(tag: str, *parts) -> int:
    """Domain-separated hash into F_P (48 bytes folded, negligible bias)."""
    return int.from_bytes(h_bytes(tag, *parts, length=48), "big") % P


def rand_field() -> int:
    return secrets.randbelow(P)


# ═══════════════════════════════════════════════════════════════════════════════
# Signatures
# ═══════════════════════════════════════════════════════════════════════════════

class Signer:
    """A validator / account key pair."""

    __slots__ = ("_sk", "public_hex")

    def __init__(self, sk: Ed25519PrivateKey | None = None):
        self._sk = sk or Ed25519PrivateKey.generate()
        self.public_hex = self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()

    @classmethod
    def generate(cls) -> "Signer":
        return cls()

    @classmethod
    def from_seed(cls, seed: str) -> "Signer":
        """Deterministic key from a label — reproducible demos and tests."""
        raw = hashlib.shake_256(f"{DOMAIN}:seed:{seed}".encode()).digest(32)
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def sign(self, message: bytes) -> str:
        return self._sk.sign(message).hex()

    def __repr__(self):
        return f"Signer({self.public_hex[:8]}…)"


def verify_sig(public_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify a hex signature under a hex raw Ed25519 public key."""
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pk.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def owner_field(public_hex: str) -> int:
    """Map a public key to the field element stored in a note's owner slot."""
    return h_field("owner", public_hex)


# ═══════════════════════════════════════════════════════════════════════════════
# Seed derivations
# ═══════════════════════════════════════════════════════════════════════════════
#
# One secret, three keys, and the formula for getting from one to the other
# lives here rather than in `wallet/` — because the ledger has to derive a
# genesis holder's spend key too, and a chain that reached up into the wallet
# package to do it would be a dependency pointing the wrong way.  What `wallet/`
# adds on top is the *object*: an address, an encoding, a note store.  What is
# here is only the arithmetic, so both sides derive the same key and neither
# owns the other.

def seed_from_phrase(phrase: str) -> bytes:
    """A reproducible seed from a human string.

    For testnets, genesis holders and tests.  A deployment wants real entropy
    and a real mnemonic, and this is the seam where one drops in.
    """
    return h_bytes("wallet-seed", phrase)


def spend_signer(seed: bytes) -> "Signer":
    """The Ed25519 key that authorises a spend.

    Domain-separated from the other two, so the derivations cannot be confused
    for one another even if one is ever reused elsewhere.
    """
    return Signer.from_seed("wallet-spend:" + bytes(seed).hex())


def view_key(seed: bytes) -> X25519PrivateKey:
    """The X25519 key that opens the notes sent to this seed."""
    return X25519PrivateKey.from_private_bytes(h_bytes("wallet-view", seed))


def detect_key(seed: bytes) -> X25519PrivateKey:
    """The X25519 key that only sorts.  Safe to hand to whoever scans for you."""
    return X25519PrivateKey.from_private_bytes(h_bytes("wallet-detect", seed))


def ephemeral():
    """A fresh X25519 keypair for one output."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey  # noqa
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return private, public
