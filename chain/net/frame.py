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

#: What an *unauthenticated* connection may send in one frame.  8 MB exists
#: for a block body, and nothing a wallet sends is a block: the largest
#: legitimate client frame is a submission carrying all three backends' proofs,
#: measured at 568 KB (mpcith 60 KB, ssh5 203 KB, ssh3 304 KB) plus the body.
#: 1 MB leaves room and still takes the 357 ms decode off every path that has
#: no use for it.  A connection is promoted to `MAX_FRAME` when it
#: authenticates as a peer, which is known before a byte of the body is parsed.
CLIENT_MAX_FRAME = 1 << 20

#: Returned by `Reader._take` for a frame the caller's gate would not pay for.
#: The bytes are discarded without being decoded, which is the whole point.
SKIPPED = object()

KINDS = ("hello", "tx", "env", "getblock", "block",
         # catch-up: bodies addressed by height rather than by hash, because a
         # node that fell behind knows which heights it is missing and cannot
         # know their hashes — that circularity was the whole reason there was
         # no way back
         "getblocks", "blocks",
         # what a client — a wallet — may ask a node
         "status", "status_reply", "getoutputs", "outputs_reply",
         "txstatus", "txstatus_reply", "submit_reply",
         # what a light client may ask: the spine, and proofs against it
         "params", "params_reply", "tip", "tip_reply",
         "headers", "headers_reply", "ancestry", "ancestry_reply",
         "inclusion", "inclusion_reply", "register", "register_reply",
         "tags", "tags_reply", "weight", "weight_reply",
         # what a node says instead of working
         "refused",
         # hardening: one node's stamps on a block every node applied
         "stamps")

#: Requests a node answers on the asking connection, without the asker ever
#: having been a peer.  A wallet is not a validator and never becomes one.
CLIENT_KINDS = frozenset({"status", "getoutputs", "txstatus",
                          "params", "tip", "headers", "ancestry",
                          "inclusion", "register", "tags", "weight"})


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
    """Incremental parser over a byte stream.  Feed it whatever arrived.

    `gate` is called with the announced body length once the whole body has
    arrived and *before* it is decoded, and a falsy answer discards those bytes
    unparsed.  It exists because the meter used to run on the other side of the
    decode: `feed` parsed the frame and `Mesh._read_loop` then asked the
    limiter whether it was allowed — by which time the expensive part was
    already paid.  Decode measures 45 ms/MB, so an 8 MB frame is 357 ms, and at
    `DEFAULT_COST` a client's four frames a second came to 1.43 CPU-seconds per
    wall second from one address that never exceeded its rate limit.
    """

    def __init__(self, expect_chain: str | None = None, max_frame=MAX_FRAME,
                 gate=None):
        self.expect_chain = expect_chain
        self.max_frame = max_frame
        self.gate = gate
        self.skipped = 0
        self._buf = bytearray()

    @property
    def buffered(self) -> int:
        """Bytes held that do not yet make a frame."""
        return len(self._buf)

    def feed(self, data: bytes):
        """Append bytes; yield every complete frame they finish."""
        self._buf += data
        while True:
            frame = self._take()
            if frame is None:
                return
            if frame is SKIPPED:
                continue
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
        if self.gate is not None and not self.gate(size):
            self.skipped += 1
            return SKIPPED
        return unpack(body, self.expect_chain)
