"""One seed, two keys, and an address that can be read out loud.

A fin6 user holds a single secret.  Everything else is derived from it:

    seed ──┬── spend key   Ed25519    authorises a spend; its field image is
           │                          the `owner` coordinate inside a note
           └── view key    X25519     decrypts the openings sent to this
                                      address, and nothing else

Two keys rather than one because they do different jobs and one of them is
safe to give away.  A signing key must never be reused for key agreement, and
separating them means the *viewing* key can be handed to an auditor for
read-only access to incoming notes — which a permissioned financial chain
probably wants designed in rather than discovered later.

The address carries both public keys and a checksum, because an address that
can be mistyped into a valid-looking different address is a way to lose money
quietly.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

from chain.crypto import (Signer, detect_key, ephemeral, h_bytes, seed_from_phrase,
                          spend_signer, view_key)

PREFIX = "fin6"
ADDRESS_VERSION = 2
CHECKSUM_BYTES = 4


class AddressError(Exception):
    pass


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=").lower()


def _unb32(text: str) -> bytes:
    pad = "=" * (-len(text) % 8)
    try:
        return base64.b32decode(text.upper() + pad)
    except Exception:
        raise AddressError("not valid base32") from None


@dataclass(frozen=True)
class Address:
    """Where money is sent.  Public, and safe to publish.

    Three keys, not two.  The third — the *detection* key — exists so that the
    work of finding your money can be handed to somebody else without handing
    them the ability to read it.  A sender tags each output with it; a node
    given the detection secret can sort the chain's outputs into "possibly
    yours" and "certainly not", and can do neither more nor less than that.
    See `notes.detection_tag`, and §09 of the part-eight design for what it
    costs in privacy.
    """
    spend_hex: str
    view_hex: str
    detect_hex: str = ""

    def payload(self) -> bytes:
        return (bytes([ADDRESS_VERSION]) + bytes.fromhex(self.spend_hex)
                + bytes.fromhex(self.view_hex)
                + bytes.fromhex(self.detect_hex))

    def encode(self) -> str:
        body = self.payload()
        check = h_bytes("address", body)[:CHECKSUM_BYTES]
        return PREFIX + _b32(body + check)

    @classmethod
    def decode(cls, text: str) -> "Address":
        text = text.strip()
        if not text.startswith(PREFIX):
            raise AddressError(f"an address starts with {PREFIX!r}")
        raw = _unb32(text[len(PREFIX):])
        if len(raw) != 1 + 96 + CHECKSUM_BYTES:
            raise AddressError(f"an address is {1 + 96 + CHECKSUM_BYTES} bytes, "
                               f"this decoded to {len(raw)}")
        body, check = raw[:-CHECKSUM_BYTES], raw[-CHECKSUM_BYTES:]
        if h_bytes("address", body)[:CHECKSUM_BYTES] != check:
            raise AddressError("checksum does not match — a typo, most likely")
        if body[0] != ADDRESS_VERSION:
            raise AddressError(f"address version {body[0]}")
        return cls(spend_hex=body[1:33].hex(), view_hex=body[33:65].hex(),
                   detect_hex=body[65:97].hex())

    def view_key(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(bytes.fromhex(self.view_hex))

    def detect_key(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(bytes.fromhex(self.detect_hex))

    def short(self) -> str:
        text = self.encode()
        return f"{text[:14]}…{text[-6:]}"

    def __repr__(self):
        return f"Address({self.short()})"


class WalletKeys:
    """The secret.  Everything a wallet can do comes from here."""

    __slots__ = ("seed", "signer", "_view", "_detect")

    def __init__(self, seed: bytes):
        if len(seed) < 16:
            raise ValueError("a seed needs at least 16 bytes")
        self.seed = bytes(seed)
        # The three derivations live in `chain.crypto`, not here: the ledger
        # has to derive a genesis holder's spend key too, and a chain reaching
        # up into the wallet package to do it would point the dependency the
        # wrong way.  What this class adds is the object — an address, an
        # encoding, and the two exchanges below.
        self.signer = spend_signer(self.seed)
        self._view = view_key(self.seed)
        # Separate again, because the detection secret is the one a user may
        # hand to an untrusted server.  Sharing it must not imply sharing the
        # viewing key, or the tunable leak collapses into total disclosure.
        self._detect = detect_key(self.seed)

    # ── construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_phrase(cls, phrase: str) -> "WalletKeys":
        """A reproducible wallet from a human string.  For testnets and tests;
        a deployment wants real entropy and a real mnemonic."""
        return cls(seed_from_phrase(phrase))

    @classmethod
    def generate(cls) -> "WalletKeys":
        import secrets
        return cls(secrets.token_bytes(32))

    # ── public halves ────────────────────────────────────────────────────────

    @property
    def spend_hex(self) -> str:
        return self.signer.public_hex

    @property
    def view_hex(self) -> str:
        return self._view.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()

    @property
    def detect_hex(self) -> str:
        return self._detect.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()

    @property
    def address(self) -> Address:
        return Address(spend_hex=self.spend_hex, view_hex=self.view_hex,
                       detect_hex=self.detect_hex)

    # ── key agreement ────────────────────────────────────────────────────────

    def exchange(self, epk: bytes) -> bytes:
        """The shared secret with an output's ephemeral key."""
        return self._view.exchange(X25519PublicKey.from_public_bytes(epk))

    def detect_exchange(self, epk: bytes) -> bytes:
        return self._detect.exchange(X25519PublicKey.from_public_bytes(epk))

    def detection_secret(self) -> str:
        """The key a user hands to whoever does the scanning for them.

        It grants the ability to *sort*, not to read: an output's opening is
        still sealed to the viewing key.  What it costs is described honestly
        in `notes.detection_tag`.
        """
        return self._detect.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()).hex()

    def viewing_secret(self) -> str:
        """The read-only half, for an auditor.  Grants sight of every note sent
        to this address, forever and unscoped — see the design's open item."""
        return self._view.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()).hex()

    def __repr__(self):
        return f"WalletKeys({self.address.short()})"


#: A fresh X25519 keypair for one output.  Defined in `chain.crypto` beside the
#: other derivations and re-exported here, where a reader will look for it.
__all__ = ["Address", "AddressError", "WalletKeys", "ephemeral"]
