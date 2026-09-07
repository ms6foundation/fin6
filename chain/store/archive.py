"""The archive segment: an append-only container for hardened history.

An archive node is the one role that keeps everything, and at 10 tx/s that is
505 GB a day.  So this file is about giving back as much of that as can be given
back without weakening what an archive is *for* — letting someone re-derive the
whole history from genesis without trusting anybody.

Three levers, and it is worth being clear about which is which, because only one
of them is compression in the usual sense.

**1. Retention — by far the largest.**  Every transaction carries three proofs
of the same statement, one per tier, because the tiers deliberately do not share
an implementation.  That diversity protects the live consensus; it does nothing
for a reader in five years, who only needs the statement to be true.  Keeping
one proof instead of three is a 9x cut and still allows full re-verification.
The proofs are not committed to by any root anyway — `txid` binds the body, not
the proof bytes — so this is a storage policy, not a change to history.

**2. Encoding — worth 3.8x on everything that is not a proof.**  See codec.py:
interning, hex packing, vector packing.

**3. Deflate — worth ~11% of what is left, and nothing at all on proofs.**
Measured at 7.997-7.999 bits per byte, proof bytes come out *larger* from zlib,
bzip2 and lzma alike.  So a record is split into a structured section, which is
deflated when that helps, and an opaque section, which never is.  Each section
records which happened, so the reader neither knows nor cares.

Layout, all integers LEB128:

    header   MAGIC | version | era_id | retention name
    record   0x1E | key | n_sections | descriptors | payloads | sha256
    descriptor  section id | codec | stored length | raw length

Descriptors precede payloads so a reader can build its index by seeking rather
than by reading, and the digest covers descriptors and payloads together, which
is what turns silent bit-rot into a loud failure.
"""
from __future__ import annotations

import collections
import dataclasses
import hashlib
import os
import zlib

from ..hardening.history import HardenedBlock
from . import codec

MAGIC = b"FIN6ARC"
VERSION = 1
REC = 0x1E

CODEC_RAW, CODEC_DEFLATE = 0, 1
SEC_STRUCTURE, SEC_PROOFS = 0, 1
_CODEC_NAME = {CODEC_RAW: "raw", CODEC_DEFLATE: "deflate"}


class ArchiveError(Exception):
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Retention
# ═══════════════════════════════════════════════════════════════════════════════

@dataclasses.dataclass(frozen=True)
class Retention:
    """Which proofs a segment keeps.

    `keep=None` means every proof the block carried; a tuple names the backends
    to keep, and the empty tuple keeps none.  Naming the backend rather than
    saying "the smallest" keeps the choice deterministic: two archives written
    under the same profile hold the same bytes.
    """
    name: str
    keep: tuple | None = None

    def filter(self, proofs: dict) -> dict:
        if self.keep is None:
            return dict(proofs)
        return {k: v for k, v in proofs.items() if k in self.keep}

    def __repr__(self):
        what = "all proofs" if self.keep is None else \
            (", ".join(self.keep) if self.keep else "no proofs")
        return f"Retention({self.name}: {what})"


FULL = Retention("full", None)
COMPACT = Retention("compact", ("mpcith",))     # the smallest of the three
HEADERS = Retention("headers", ())

PROFILES = {r.name: r for r in (FULL, COMPACT, HEADERS)}


# ═══════════════════════════════════════════════════════════════════════════════
# Splitting a block into its opaque and structured halves
# ═══════════════════════════════════════════════════════════════════════════════

def split_proofs(block, retention: Retention = FULL):
    """(block with empty proof dicts, one proof dict per transaction).

    The order is the block's own walk order — supers, then children, then
    transactions — which is the order `join_proofs` puts them back in, so the
    two never need to agree on a key.
    """
    table = []

    def do_tx(tx):
        table.append(retention.filter(tx.proofs))
        return dataclasses.replace(tx, proofs={})

    def do_ceremony(cb):
        return dataclasses.replace(
            cb, transactions=tuple(do_tx(t) for t in cb.transactions))

    def do_super(sb):
        return dataclasses.replace(
            sb, children=tuple(do_ceremony(c) for c in sb.children))

    def do_network(nb):
        return dataclasses.replace(
            nb, supers=tuple(do_super(s) for s in nb.supers))

    if isinstance(block, HardenedBlock):
        inner = None if block.block is None else do_network(block.block)
        return dataclasses.replace(block, block=inner), table
    return do_network(block), table


def join_proofs(block, table):
    """Inverse of split_proofs.  Refuses a table that does not line up."""
    it = iter(table)

    def do_tx(tx):
        try:
            proofs = next(it)
        except StopIteration:
            raise ArchiveError("proof table is shorter than the block") from None
        return dataclasses.replace(tx, proofs=proofs)

    def do_ceremony(cb):
        return dataclasses.replace(
            cb, transactions=tuple(do_tx(t) for t in cb.transactions))

    def do_super(sb):
        return dataclasses.replace(
            sb, children=tuple(do_ceremony(c) for c in sb.children))

    def do_network(nb):
        return dataclasses.replace(
            nb, supers=tuple(do_super(s) for s in nb.supers))

    if isinstance(block, HardenedBlock):
        inner = None if block.block is None else do_network(block.block)
        out = dataclasses.replace(block, block=inner)
    else:
        out = do_network(block)
    if next(it, None) is not None:
        raise ArchiveError("proof table is longer than the block")
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# Sections
# ═══════════════════════════════════════════════════════════════════════════════

def pack_section(sec_id: int, raw: bytes):
    """(codec, stored bytes).  Deflate is tried only where it can win.

    The proofs section is never tried: at ~8 bits per byte every compressor adds
    a header and gives nothing back, so the trial is pure CPU.  The structured
    section is tried and kept only if it actually came out smaller, which means
    this can never make a record larger than not compressing at all.
    """
    if sec_id == SEC_PROOFS:
        return CODEC_RAW, raw
    squeezed = zlib.compress(raw, 9)
    if len(squeezed) < len(raw):
        return CODEC_DEFLATE, squeezed
    return CODEC_RAW, raw


def unpack_section(codec_id: int, stored: bytes, raw_len: int) -> bytes:
    if codec_id == CODEC_RAW:
        out = stored
    elif codec_id == CODEC_DEFLATE:
        out = zlib.decompress(stored)
    else:
        raise ArchiveError(f"unknown section codec {codec_id}")
    if len(out) != raw_len:
        raise ArchiveError(f"section is {len(out)} bytes, header says {raw_len}")
    return out


def _put_uint(out: bytearray, n: int):
    codec.put_uint(out, n)


# ═══════════════════════════════════════════════════════════════════════════════
# Writer
# ═══════════════════════════════════════════════════════════════════════════════

class ArchiveWriter:
    """Append blocks to one segment file.  One segment per era, so pruning an
    era is deleting a file rather than rewriting an index."""

    def __init__(self, path, era_id: int = 0, retention: Retention = FULL):
        self.path = str(path)
        self.era_id = era_id
        self.retention = retention
        exists = os.path.exists(self.path) and os.path.getsize(self.path) > 0
        self._fh = open(self.path, "ab")
        if exists:
            head = _read_header(self.path)
            if head["era_id"] != era_id or head["retention"] != retention.name:
                raise ArchiveError(
                    f"segment holds era {head['era_id']} under "
                    f"{head['retention']!r}; refusing to mix")
        else:
            out = bytearray(MAGIC)
            out.append(VERSION)
            _put_uint(out, era_id)
            name = retention.name.encode()
            _put_uint(out, len(name))
            out += name
            self._fh.write(bytes(out))
        self.written = 0
        self.stored_bytes = 0
        self.proofs_seen = collections.Counter()
        self.proofs_kept = collections.Counter()

    # ── one record ───────────────────────────────────────────────────────────

    def append(self, block) -> int:
        """Store one block.  Returns the offset it was written at."""
        key = getattr(block, "height", None)
        if key is None:
            raise ArchiveError("a block must expose a height")
        for tx in _transactions_of(block):
            self.proofs_seen.update(tx.proofs.keys())
        stripped, table = split_proofs(block, self.retention)
        for kept in table:
            self.proofs_kept.update(kept.keys())
        sections = [(SEC_STRUCTURE, codec.encode(stripped)),
                    (SEC_PROOFS, codec.encode(table))]

        desc, payloads = bytearray(), bytearray()
        desc.append(REC)
        _put_uint(desc, key)
        _put_uint(desc, len(sections))
        for sec_id, raw in sections:
            codec_id, stored = pack_section(sec_id, raw)
            _put_uint(desc, sec_id)
            desc.append(codec_id)
            _put_uint(desc, len(stored))
            _put_uint(desc, len(raw))
            payloads += stored
        digest = hashlib.sha256(bytes(desc) + bytes(payloads)).digest()

        offset = self._fh.tell()
        self._fh.write(bytes(desc))
        self._fh.write(bytes(payloads))
        self._fh.write(digest)
        self.written += 1
        self.stored_bytes += len(desc) + len(payloads) + 32
        return offset

    def stats(self):
        """What retention actually threw away, which is the number that matters
        to whoever is paying for the disk."""
        seen = sum(self.proofs_seen.values())
        kept = sum(self.proofs_kept.values())
        return {"records": self.written, "retention": self.retention.name,
                "stored_bytes": self.stored_bytes,
                "proofs_seen": dict(self.proofs_seen),
                "proofs_kept": dict(self.proofs_kept),
                "proofs_dropped": seen - kept}

    def flush(self):
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self):
        if self._fh is not None:
            self.flush()
            self._fh.close()
            self._fh = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Reader
# ═══════════════════════════════════════════════════════════════════════════════

def _read_header(path):
    with open(path, "rb") as fh:
        blob = fh.read(64)
    if not blob.startswith(MAGIC):
        raise ArchiveError("not a fin6 archive segment")
    pos = len(MAGIC)
    version = blob[pos]
    pos += 1
    if version != VERSION:
        raise ArchiveError(f"segment version {version}, expected {VERSION}")
    buf = memoryview(blob)
    era_id, pos = codec.get_uint(buf, pos)
    n, pos = codec.get_uint(buf, pos)
    name = bytes(buf[pos:pos + n]).decode()
    return {"version": version, "era_id": era_id, "retention": name,
            "body_offset": pos + n}


class ArchiveReader:
    """Random access into a segment.

    The index is built by walking descriptors and seeking past payloads, so
    opening a full era costs one small read per block rather than reading the
    era.  It is also rebuilt every open, which means a lost or damaged index can
    never be the thing that loses an archive.
    """

    def __init__(self, path):
        self.path = str(path)
        head = _read_header(self.path)
        self.era_id = head["era_id"]
        self.retention = head["retention"]
        self.index = {}            # key -> (offset, [(sec, codec, stored, raw)])
        self._scan(head["body_offset"])

    def _scan(self, pos):
        size = os.path.getsize(self.path)
        with open(self.path, "rb") as fh:
            while pos < size:
                fh.seek(pos)
                head = fh.read(64)
                if not head:
                    break
                if head[0] != REC:
                    raise ArchiveError(f"no record marker at offset {pos}")
                buf = memoryview(head)
                p = 1
                key, p = codec.get_uint(buf, p)
                n, p = codec.get_uint(buf, p)
                secs, total = [], 0
                for _ in range(n):
                    sec_id, p = codec.get_uint(buf, p)
                    codec_id = buf[p]
                    p += 1
                    stored, p = codec.get_uint(buf, p)
                    raw, p = codec.get_uint(buf, p)
                    secs.append((sec_id, codec_id, stored, raw))
                    total += stored
                if key in self.index:
                    raise ArchiveError(f"height {key} appears twice")
                self.index[key] = (pos, p, secs)
                pos += p + total + 32

    # ── access ───────────────────────────────────────────────────────────────

    def heights(self):
        return sorted(self.index)

    def __len__(self):
        return len(self.index)

    def __contains__(self, height):
        return height in self.index

    def _sections(self, height, check=True):
        if height not in self.index:
            raise KeyError(f"height {height} is not in this segment")
        offset, desc_len, secs = self.index[height]
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            desc = fh.read(desc_len)
            payload = fh.read(sum(s[2] for s in secs))
            digest = fh.read(32)
        if check and hashlib.sha256(desc + payload).digest() != digest:
            raise ArchiveError(
                f"record at height {height} fails its digest — the segment is "
                f"damaged; refetch it rather than trusting it")
        out, at = {}, 0
        for sec_id, codec_id, stored, raw in secs:
            out[sec_id] = unpack_section(codec_id, payload[at:at + stored], raw)
            at += stored
        return out

    def get(self, height):
        """The block as it was stored — with whatever proofs retention kept."""
        secs = self._sections(height)
        stripped = codec.decode(secs[SEC_STRUCTURE])
        table = codec.decode(secs[SEC_PROOFS])
        return join_proofs(stripped, table)

    def __iter__(self):
        for h in self.heights():
            yield self.get(h)

    def verify(self):
        """(ok, [complaints]).  Reads every record and checks every digest."""
        problems = []
        for h in self.heights():
            try:
                self._sections(h)
            except Exception as exc:
                problems.append(f"height {h}: {exc}")
        return not problems, problems

    # ── what it cost ─────────────────────────────────────────────────────────

    def stats(self):
        """Bytes in, bytes on disk, and which codec each section chose."""
        per = {SEC_STRUCTURE: [0, 0], SEC_PROOFS: [0, 0]}
        codecs = {}
        for _, _, secs in self.index.values():
            for sec_id, codec_id, stored, raw in secs:
                per.setdefault(sec_id, [0, 0])
                per[sec_id][0] += raw
                per[sec_id][1] += stored
                codecs[(sec_id, _CODEC_NAME[codec_id])] = \
                    codecs.get((sec_id, _CODEC_NAME[codec_id]), 0) + 1
        enc = sum(v[0] for v in per.values())
        stored = sum(v[1] for v in per.values())
        s_raw, s_stored = per[SEC_STRUCTURE]
        return {
            "records": len(self.index),
            "retention": self.retention,
            "encoded_bytes": enc,        # after codec.py, before deflate
            "stored_bytes": stored,
            "on_disk": os.path.getsize(self.path),
            # Deflate only ever runs on the structured section, so quoting one
            # ratio over the whole segment would just report how big the proofs
            # were.  The saving that matters is retention, and that happened
            # before any of these bytes existed.
            "deflate_ratio": (s_raw / s_stored) if s_stored else 1.0,
            "structure": (s_raw, s_stored),
            "proofs": tuple(per[SEC_PROOFS]),
            "codecs": codecs,
        }


def _transactions_of(block):
    inner = block.block if isinstance(block, HardenedBlock) else block
    if inner is None:
        return
    for sup in inner.supers:
        for child in sup.children:
            yield from child.transactions


def prune(path):
    """Delete a whole segment.  Pruning an era is exactly this and nothing else,
    which is the reason for one file per era."""
    head = _read_header(path)            # refuse to delete something else
    os.remove(path)
    return head["era_id"]
