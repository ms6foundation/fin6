"""The one write that has to happen before the thing it protects.

Every other record in this package describes something that already happened.
Turn spending cannot work that way: signing a second anchor with one WOTS key
publishes the private key, so if the record of *having signed* is written after
the signature, a crash in between destroys the turn's security rather than the
turn.

    1. fsync( high_water = anchor height )   <- refuse to sign at or below it
    2. sign
    3. broadcast

A crash between 1 and 2 wastes a turn, which costs the holder one stamp.  A
crash between 2 and 3 has already been recorded.  The reverse order loses the
key.  Eight bytes and one fsync per stamp buys that.

A monotone mark rather than a set of spent turns, for a reason worth stating:
**the chain is the durable spent-turn record** — every spent turn appears in a
hardened block — so this file is a cache of something the network already
publishes.  That is what makes the failure mode survivable.  A holder restored
from last night's backup does not need its file to be right; it needs to sync
to the tip and `adopt` the highest height it finds itself in there before it
signs anything.  Any scheme where the local file is the only record turns an
ordinary restore into a key disclosure.
"""
from __future__ import annotations

import hashlib
import os

MAGIC = b"FIN6HW"
VERSION = 1


class HighWaterError(Exception):
    pass


class HighWater:
    """A monotone, durable, fail-safe counter."""

    def __init__(self, path):
        self.path = str(path)
        self._value = -1
        if os.path.exists(self.path) and os.path.getsize(self.path):
            self._value = self._read()
        else:
            self._write(-1)

    # ── the file ─────────────────────────────────────────────────────────────

    def _read(self) -> int:
        with open(self.path, "rb") as fh:
            blob = fh.read()
        if len(blob) != len(MAGIC) + 1 + 8 + 32 or not blob.startswith(MAGIC):
            raise HighWaterError(
                f"{self.path} is not a usable high-water mark; refusing to "
                f"sign against a file we cannot read")
        body = blob[:len(MAGIC) + 1 + 8]
        if hashlib.sha256(body).digest() != blob[-32:]:
            raise HighWaterError(
                f"{self.path} fails its digest — treat this holder's turns as "
                f"unsafe until it has resynced from the chain")
        return int.from_bytes(body[-8:], "big", signed=True)

    def _write(self, value: int):
        body = MAGIC + bytes([VERSION]) + value.to_bytes(8, "big", signed=True)
        blob = body + hashlib.sha256(body).digest()
        # Written in place rather than through a rename: the record must be
        # durable before the caller signs, and a rename buys atomicity we do
        # not need for 47 bytes that are checked by digest anyway.
        with open(self.path, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        self._value = value

    # ── use ──────────────────────────────────────────────────────────────────

    @property
    def value(self) -> int:
        return self._value

    def claim(self, height: int) -> int:
        """Reserve the right to sign at `height`.  Durable before it returns.

        Refuses anything at or below the mark, which is the whole guarantee: a
        turn cannot be spent twice because the second attempt never gets past
        this line.
        """
        if height <= self._value:
            raise HighWaterError(
                f"already signed at or above height {height} (mark is "
                f"{self._value}) — signing again would publish the key")
        self._write(height)
        return height

    def adopt(self, height: int) -> int:
        """Move the mark forward to something learned from the chain.

        For a holder that was restored from a backup, or that is catching up:
        the chain shows where its turns were spent, and the mark must never
        move backwards to match a stale file.
        """
        if height > self._value:
            self._write(height)
        return self._value

    def __repr__(self):
        return f"HighWater({self.path}, mark={self._value})"
