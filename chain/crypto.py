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
