"""Canonical binary encoding for everything the chain stores or sends.

The archive's problem is not that its data compresses badly.  It is that the
data comes in two populations that need opposite treatment:

  * **Opaque** — proofs, signatures, hashes.  Measured at 7.997-7.999 bits per
    byte, which is what uniform field elements and hash output look like.  zlib,
    bzip2 and lzma all make them *bigger*.  Nothing to do but store them.
  * **Structured** — headers, rolls, certificates, identifiers.  Written as
    Python objects full of hex strings, and every attestation in a certificate
    repeats the chain id, the block hash, the epoch and the grid seed.  A
    general-purpose compressor finds that redundancy the expensive way; a
    canonical encoding never emits it in the first place.

So this module is the compression.  Three mechanisms, in order of what they are
worth on real blocks:

  1. **Interning.** Every string in a record is written once into a table and
     referred to afterwards by index.  A quorum certificate names one block hash
     28 times; it is stored once.
  2. **Hex packing.** Nearly every identifier here is a hex string, often with a
     short tag in front (``tx:``, ``nb:``).  The hex half is stored as the bytes
     it stands for, which halves it.
  3. **Vector packing.** A list of field elements is written as one length and
     n fixed-width elements with no per-item tags, and a list of equal-length
     byte strings likewise.  This is what keeps the encoding of a proof within a
     fraction of a percent of its hand-rolled serialiser while still being
     self-describing enough to decode without knowing which protocol wrote it.

Everything round-trips exactly, and the same object always produces the same
bytes — the archive digests what this module emits, so canonicality is not a
nicety here.
"""
from __future__ import annotations

import dataclasses

from mq.ms6.core import FIELD_BYTES

from ..block import (Attestation, Block, BlockHeader, CeremonyMeta,
                     FaultReport, QuorumCert, SignedProposal)
from ..hardening.history import HardenedBlock
from ..hardening.stamp import Stamp
from ..register import AttendanceRoll
from ..state import UtxoDelta
from ..tiered import (CeremonyBlock, CeremonyBlockHeader, NetworkBlock,
                      NetworkBlockHeader, SuperBlock, SuperBlockHeader)
from ..transaction import Transaction, TxInput

FORMAT_VERSION = 1

# Append only.  The index is what a stored record names, so reordering this
# tuple silently reinterprets every archive ever written.
TYPES = (
    TxInput, Transaction, CeremonyMeta, BlockHeader, Block, Attestation,
    QuorumCert, FaultReport, SignedProposal, AttendanceRoll, UtxoDelta,
    CeremonyBlockHeader, CeremonyBlock, SuperBlockHeader, SuperBlock,
    NetworkBlockHeader, NetworkBlock, Stamp, HardenedBlock,
)
_TYPE_INDEX = {cls: i for i, cls in enumerate(TYPES)}
_FIELDS = {cls: tuple(f.name for f in dataclasses.fields(cls)) for cls in TYPES}

# Tags
T_NONE, T_FALSE, T_TRUE = 0, 1, 2
T_UINT, T_NINT, T_FE, T_BIG = 3, 4, 5, 6
T_BYTES, T_STR = 7, 8
T_LIST, T_TUPLE, T_DICT = 9, 10, 11
T_FE_LIST, T_FE_TUPLE = 12, 13          # packed field-element vectors
T_BV_LIST, T_BV_TUPLE = 14, 15          # packed equal-length byte vectors
T_OBJ = 16

FE_MAX = 1 << (8 * FIELD_BYTES)
_HEX = frozenset("0123456789abcdef")


class CodecError(Exception):
    """Malformed input.  Archives are read back from disk, so decode is a trust
    boundary: it must refuse rather than hang or return something plausible."""


# ═══════════════════════════════════════════════════════════════════════════════
# Primitives
# ═══════════════════════════════════════════════════════════════════════════════

def put_uint(out: bytearray, n: int):
    """LEB128.  Canonical because the minimal encoding is the only one emitted."""
    if n < 0:
        raise CodecError("put_uint is unsigned")
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return


def get_uint(buf: memoryview, pos: int):
    n, shift = 0, 0
    while True:
        if pos >= len(buf):
            raise CodecError("truncated varint")
        b = buf[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, pos
        shift += 7
        if shift > 4096:
            raise CodecError("varint too long")


def _take(buf: memoryview, pos: int, n: int):
    if n < 0 or pos + n > len(buf):
        raise CodecError("truncated payload")
    return bytes(buf[pos:pos + n]), pos + n


# ═══════════════════════════════════════════════════════════════════════════════
# String table — interning and hex packing
# ═══════════════════════════════════════════════════════════════════════════════

def _hex_split(s: str):
    """Split a string into (prefix, packed-hex) if that is worth doing.

    Identifiers here are a short ASCII tag and a long lowercase hex body —
    ``tx:9f3c…``, ``nb:0a11…``, or bare hex for keys and signatures.  Returns
    None when packing would not pay, so short strings and node names stay plain.
    """
    i = len(s)
    while i and s[i - 1] in _HEX:
        i -= 1
    if (len(s) - i) % 2:
        i += 1                              # keep the hex body even-length
    body = s[i:]
    if len(body) < 32:                      # below this the flag byte eats it
        return None
    return s[:i], bytes.fromhex(body)


class _Strings:
    """Sorted intern table.

    Sorted rather than first-seen, because the table is built in a pass of its
    own before anything is emitted.  First-seen order would make an index depend
    on the order a dict happened to be built in, and then two nodes holding the
    same mapping would produce different bytes for it — which the archive would
    read as two different records.
    """

    def __init__(self, strings=()):
        self.order = sorted(set(strings))
        self.index = {s: i for i, s in enumerate(self.order)}

    def id_of(self, s: str) -> int:
        try:
            return self.index[s]
        except KeyError:
            raise CodecError(f"string {s!r} was not collected") from None

    def dump(self) -> bytes:
        out = bytearray()
        put_uint(out, len(self.order))
        for s in self.order:
            split = _hex_split(s)
            if split is None:
                raw = s.encode("utf-8")
                out.append(0)
                put_uint(out, len(raw))
                out += raw
            else:
                prefix, packed = split
                praw = prefix.encode("utf-8")
                out.append(1)
                put_uint(out, len(praw))
                out += praw
                put_uint(out, len(packed))
                out += packed
        return bytes(out)

    @staticmethod
    def load(buf: memoryview, pos: int):
        count, pos = get_uint(buf, pos)
        table = []
        for _ in range(count):
            if pos >= len(buf):
                raise CodecError("truncated string table")
            flag = buf[pos]
            pos += 1
            if flag == 0:
                n, pos = get_uint(buf, pos)
                raw, pos = _take(buf, pos, n)
                table.append(raw.decode("utf-8"))
            elif flag == 1:
                n, pos = get_uint(buf, pos)
                prefix, pos = _take(buf, pos, n)
                n, pos = get_uint(buf, pos)
                packed, pos = _take(buf, pos, n)
                table.append(prefix.decode("utf-8") + packed.hex())
            else:
                raise CodecError(f"unknown string flag {flag}")
        return table, pos


# ═══════════════════════════════════════════════════════════════════════════════
# Values
# ═══════════════════════════════════════════════════════════════════════════════

def _put_int(out: bytearray, n: int):
    if n < 0:
        out.append(T_NINT)
        _put_magnitude(out, -n)
        return
    if n < 1 << 64:
        out.append(T_UINT)
        put_uint(out, n)
    elif n < FE_MAX:
        out.append(T_FE)
        out += n.to_bytes(FIELD_BYTES, "big")
    else:
        out.append(T_BIG)
        _put_magnitude(out, n)


def _put_magnitude(out: bytearray, n: int):
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    put_uint(out, len(raw))
    out += raw


def _is_fe_vec(seq):
    return len(seq) >= 2 and all(
        type(x) is int and 0 <= x < FE_MAX for x in seq)


def _is_byte_vec(seq):
    if len(seq) < 2 or not all(isinstance(x, (bytes, bytearray)) for x in seq):
        return False
    n = len(seq[0])
    return n > 0 and all(len(x) == n for x in seq)


def _put_seq(out: bytearray, seq, st: _Strings, is_tuple: bool):
    """Pack when packing wins, otherwise fall back to tagged items.

    A packed field-element vector costs 32 bytes an item, which is a loss for a
    list of small integers (the hidden-party indices in an MPCitH proof) and a
    large win for the ones that carry the proof (alpha, the deltas).  Rather
    than guess, encode both and keep the shorter — the tag records which, so the
    decoder never has to.
    """
    if _is_byte_vec(seq):
        out.append(T_BV_TUPLE if is_tuple else T_BV_LIST)
        put_uint(out, len(seq))
        put_uint(out, len(seq[0]))
        for x in seq:
            out += bytes(x)
        return
    plain = bytearray()
    plain.append(T_TUPLE if is_tuple else T_LIST)
    put_uint(plain, len(seq))
    for item in seq:
        _put(plain, item, st)
    if _is_fe_vec(seq):
        packed = bytearray()
        packed.append(T_FE_TUPLE if is_tuple else T_FE_LIST)
        put_uint(packed, len(seq))
        for x in seq:
            packed += x.to_bytes(FIELD_BYTES, "big")
        if len(packed) < len(plain):
            out += packed
            return
    out += plain


def _put(out: bytearray, val, st: _Strings):
    if val is None:
        out.append(T_NONE)
    elif val is True:
        out.append(T_TRUE)
    elif val is False:
        out.append(T_FALSE)
    elif isinstance(val, int):
        _put_int(out, val)
    elif isinstance(val, str):
        out.append(T_STR)
        put_uint(out, st.id_of(val))
    elif isinstance(val, (bytes, bytearray)):
        out.append(T_BYTES)
        put_uint(out, len(val))
        out += bytes(val)
    elif isinstance(val, tuple):
        _put_seq(out, val, st, True)
    elif isinstance(val, list):
        _put_seq(out, val, st, False)
    elif isinstance(val, dict):
        out.append(T_DICT)
        put_uint(out, len(val))
        # Sorted by encoded key so two nodes holding the same mapping agree.
        items = []
        for k, v in val.items():
            kb = bytearray()
            _put(kb, k, st)
            items.append((bytes(kb), v))
        for kb, v in sorted(items, key=lambda kv: kv[0]):
            out += kb
            _put(out, v, st)
    elif type(val) in _TYPE_INDEX:
        cls = type(val)
        out.append(T_OBJ)
        put_uint(out, _TYPE_INDEX[cls])
        for name in _FIELDS[cls]:
            _put(out, getattr(val, name), st)
    else:
        raise CodecError(f"no encoding for {type(val).__name__}")


def _get(buf: memoryview, pos: int, table: list):
    if pos >= len(buf):
        raise CodecError("truncated value")
    tag = buf[pos]
    pos += 1
    if tag == T_NONE:
        return None, pos
    if tag == T_TRUE:
        return True, pos
    if tag == T_FALSE:
        return False, pos
    if tag == T_UINT:
        return get_uint(buf, pos)
    if tag == T_NINT:
        n, pos = get_uint(buf, pos)
        raw, pos = _take(buf, pos, n)
        return -int.from_bytes(raw, "big"), pos
    if tag == T_FE:
        raw, pos = _take(buf, pos, FIELD_BYTES)
        return int.from_bytes(raw, "big"), pos
    if tag == T_BIG:
        n, pos = get_uint(buf, pos)
        raw, pos = _take(buf, pos, n)
        return int.from_bytes(raw, "big"), pos
    if tag == T_BYTES:
        n, pos = get_uint(buf, pos)
        return _take(buf, pos, n)
    if tag == T_STR:
        i, pos = get_uint(buf, pos)
        if i >= len(table):
            raise CodecError("string index out of range")
        return table[i], pos
    if tag in (T_LIST, T_TUPLE):
        n, pos = get_uint(buf, pos)
        items = []
        for _ in range(n):
            item, pos = _get(buf, pos, table)
            items.append(item)
        return (tuple(items) if tag == T_TUPLE else items), pos
    if tag in (T_FE_LIST, T_FE_TUPLE):
        n, pos = get_uint(buf, pos)
        raw, pos = _take(buf, pos, n * FIELD_BYTES)
        items = [int.from_bytes(raw[i * FIELD_BYTES:(i + 1) * FIELD_BYTES], "big")
                 for i in range(n)]
        return (tuple(items) if tag == T_FE_TUPLE else items), pos
    if tag in (T_BV_LIST, T_BV_TUPLE):
        n, pos = get_uint(buf, pos)
        width, pos = get_uint(buf, pos)
        raw, pos = _take(buf, pos, n * width)
        items = [raw[i * width:(i + 1) * width] for i in range(n)]
        return (tuple(items) if tag == T_BV_TUPLE else items), pos
    if tag == T_DICT:
        n, pos = get_uint(buf, pos)
        out = {}
        for _ in range(n):
            k, pos = _get(buf, pos, table)
            v, pos = _get(buf, pos, table)
            out[k] = v
        return out, pos
    if tag == T_OBJ:
        i, pos = get_uint(buf, pos)
        if i >= len(TYPES):
            raise CodecError(f"unknown type index {i}")
        cls = TYPES[i]
        kw = {}
        for name in _FIELDS[cls]:
            kw[name], pos = _get(buf, pos, table)
        return cls(**kw), pos
    raise CodecError(f"unknown tag {tag}")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry points
# ═══════════════════════════════════════════════════════════════════════════════

def _collect(val, out: set):
    """Gather every string, so the table can be sorted before anything is
    emitted.  One extra walk buys order-independence."""
    if isinstance(val, str):
        out.add(val)
    elif isinstance(val, (list, tuple)):
        for item in val:
            _collect(item, out)
    elif isinstance(val, dict):
        for k, v in val.items():
            _collect(k, out)
            _collect(v, out)
    elif type(val) in _TYPE_INDEX:
        for name in _FIELDS[type(val)]:
            _collect(getattr(val, name), out)


def encode(value) -> bytes:
    """Canonical bytes for one value: version, string table, then the tree."""
    found = set()
    _collect(value, found)
    st = _Strings(found)
    body = bytearray()
    _put(body, value, st)
    out = bytearray()
    put_uint(out, FORMAT_VERSION)
    out += st.dump()
    out += body
    return bytes(out)


def decode(blob: bytes):
    buf = memoryview(blob)
    version, pos = get_uint(buf, 0)
    if version != FORMAT_VERSION:
        raise CodecError(f"format version {version}, expected {FORMAT_VERSION}")
    table, pos = _Strings.load(buf, pos)
    value, pos = _get(buf, pos, table)
    if pos != len(buf):
        raise CodecError(f"{len(buf) - pos} trailing bytes")
    return value
