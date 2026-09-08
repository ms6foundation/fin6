"""Framing: the only place bytes from a stranger become objects.

One length-prefixed frame carries one message, encoded with `store/codec.py` —
the same canonical encoder the archive uses, so there is one serialisation in
the system rather than two that can disagree.

This module is a trust boundary and is written like one.  A frame declares its
length before its content, so a peer that claims 4 GB is refused before a byte
of it is read; a frame that does not decode, or decodes to the wrong shape, or
names a different chain, is a disconnect rather than an exception somewhere
deeper in.  Nothing here trusts anything.
"""
from __future__ import annotations

from ..store import codec

MAGIC = b"F6"
VERSION = 1
MAX_FRAME = 8 << 20          # 8 MB: a block of ~100 transactions with one proof

KINDS = ("hello", "tx", "env", "getblock", "block",
         # what a client — a wallet — may ask a node
         "status", "status_reply", "getoutputs", "outputs_reply",
         "txstatus", "txstatus_reply", "submit_reply")

#: Requests a node answers on the asking connection, without the asker ever
#: having been a peer.  A wallet is not a validator and never becomes one.
CLIENT_KINDS = frozenset({"status", "getoutputs", "txstatus"})


class FrameError(Exception):
    """Malformed, oversized, or for another chain.  Always fatal to the
    connection: a peer that sent one bad frame has no claim on the next."""


def pack(kind: str, chain_id: str, payload=None, *, epoch: int = -1) -> bytes:
    if kind not in KINDS:
        raise FrameError(f"unknown kind {kind!r}")
    body = codec.encode({"kind": kind, "chain_id": chain_id, "epoch": epoch,
                         "payload": payload})
    if len(body) > MAX_FRAME:
        raise FrameError(f"frame of {len(body)} bytes exceeds {MAX_FRAME}")
    head = bytearray(MAGIC)
    head.append(VERSION)
    codec.put_uint(head, len(body))
    return bytes(head) + body


def unpack(body: bytes, expect_chain: str | None = None) -> dict:
    """Decode one frame body, and refuse anything that is not what it claims."""
    try:
        msg = codec.decode(body)
    except codec.CodecError as exc:
        raise FrameError(f"undecodable frame: {exc}") from None
    if not isinstance(msg, dict):
        raise FrameError("a frame must decode to a mapping")
    missing = {"kind", "chain_id", "epoch", "payload"} - set(msg)
    if missing:
        raise FrameError(f"frame is missing {sorted(missing)}")
    if msg["kind"] not in KINDS:
        raise FrameError(f"unknown kind {msg['kind']!r}")
    if expect_chain is not None and msg["chain_id"] != expect_chain:
        # The chain id is the hash of the genesis document, so this catches a
        # node pointed at the wrong network on its first frame rather than at
        # its first divergent root.
        raise FrameError(f"frame is for chain {msg['chain_id']}, not "
                         f"{expect_chain}")
    return msg


class Reader:
    """Incremental parser over a byte stream.  Feed it whatever arrived."""

    def __init__(self, expect_chain: str | None = None, max_frame=MAX_FRAME):
        self.expect_chain = expect_chain
        self.max_frame = max_frame
        self._buf = bytearray()

    def feed(self, data: bytes):
        """Append bytes; yield every complete frame they finish."""
        self._buf += data
        while True:
            frame = self._take()
            if frame is None:
                return
            yield frame

    def _take(self):
        buf = self._buf
        if len(buf) < len(MAGIC) + 1:
            return None
        if bytes(buf[:len(MAGIC)]) != MAGIC:
            raise FrameError("stream does not start with a fin6 frame")
        if buf[len(MAGIC)] != VERSION:
            raise FrameError(f"frame version {buf[len(MAGIC)]}")
        try:
            size, pos = codec.get_uint(memoryview(buf), len(MAGIC) + 1)
        except codec.CodecError:
            return None                      # length prefix not complete yet
        if size > self.max_frame:
            raise FrameError(f"peer announced a {size}-byte frame")
        if len(buf) < pos + size:
            return None
        body = bytes(buf[pos:pos + size])
        del self._buf[:pos + size]
        return unpack(body, self.expect_chain)
