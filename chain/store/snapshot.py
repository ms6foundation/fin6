"""Snapshots: state that proves itself against a header.

A joining node has two honest options.  It can verify from genesis, which means
re-checking every proof the chain ever carried and needs an archive to serve
them.  Or it can take a snapshot of the state and check that snapshot against a
block header — which is cheap, because the header already commits `utxo_root`,
`nf_root` and `registers_root`, and folding those roots costs 4.1 us a leaf.

The second is what makes proof pruning safe: a node that never saw a proof can
still prove to itself that it holds exactly the state the network agreed.  What
it cannot do is re-derive the agreement.  **Snapshot sync trusts consensus;
genesis sync trusts nobody.**  Both are legitimate and the difference should
never be blurred, so `load` demands the header's roots and refuses without them.

The file is chunked because the values are an ordered list: ranges can be
fetched from different peers, each range carries its own digest, and the fold
happens once at the end.
"""
from __future__ import annotations

import hashlib
import os

from ..params import ChainParams
from ..register import GridRegister
from ..seal import SealAccumulator
from ..state import ChainState
from ..tiered import registers_root as compute_registers_root
from . import codec

MAGIC = b"FIN6SNAP"
VERSION = 2
DEFAULT_CHUNK = 50_000

#: What a chunk holds when the snapshot is going over a wire rather than onto a
#: disk.  50,000 commitments is about 3.4 MB, which fits a frame and nothing
#: else; 10,000 is about 680 KB, which leaves room for a peer to be serving
#: several requesters and a ceremony at the same time.  Review C7.
SERVE_CHUNK = 10_000

KIND_UTXO, KIND_NF, KIND_REGISTERS = 0, 1, 2


class SnapshotError(Exception):
    pass


def _frame(kind: int, index: int, payload: bytes) -> bytes:
    """One chunk on disk: header, payload, and the digest over both."""
    head = bytearray()
    codec.put_uint(head, kind)
    codec.put_uint(head, index)
    codec.put_uint(head, len(payload))
    return bytes(head) + payload + hashlib.sha256(
        bytes(head) + payload).digest()


def chunk_digest(kind: int, index: int, payload: bytes) -> str:
    """What the manifest commits for one chunk, and what a receiver checks.

    The same digest the file carries, hex, so a chunk that arrives over a wire
    is checkable the moment it lands rather than at the end of the fold — which
    is what lets ranges come from different peers and the wrong one be blamed
    (review C7).
    """
    head = bytearray()
    codec.put_uint(head, kind)
    codec.put_uint(head, index)
    codec.put_uint(head, len(payload))
    return hashlib.sha256(bytes(head) + payload).hexdigest()


def _put(fh, kind: int, index: int, payload: bytes):
    fh.write(_frame(kind, index, payload))


def parts_of(state: ChainState, registers: dict, chunk: int = DEFAULT_CHUNK):
    """The chunks a snapshot of this state is made of, in order.

    Split out from `export` because a snapshot now has two destinations: a
    file, and a peer that wants it one range at a time.
    """
    utxo_values, utxo_dead = state.utxo.dump()
    nf_values, _ = state.nullifiers.dump()
    dead = set(utxo_dead)
    out = []
    for i in range(0, max(1, len(utxo_values)), chunk):
        part = utxo_values[i:i + chunk]
        flags = [j - i for j in range(i, i + len(part)) if j in dead]
        out.append((KIND_UTXO, i // chunk, codec.encode([part, flags])))
    for i in range(0, max(1, len(nf_values)), chunk):
        out.append((KIND_NF, i // chunk,
                    codec.encode(nf_values[i:i + chunk])))
    out.append((KIND_REGISTERS, 0,
                codec.encode([r.dump() for _, r in sorted(registers.items())])))
    return out, len(utxo_values), len(nf_values)


def export(state: ChainState, registers: dict, path, *,
           chunk: int = DEFAULT_CHUNK):
    """Write the whole state, in ranges, with a manifest of what it claims.

    The manifest lists every chunk and its digest, which is what makes a
    snapshot fetchable in pieces: a receiver knows exactly what to ask for, can
    check each piece as it lands, and can ask different peers for different
    ranges (review C7).
    """
    parts, n_utxo, n_nf = parts_of(state, registers, chunk)
    manifest = {
        "chain_id": state.chain_id,
        "height": state.height,
        "tip": state.tip,
        "burned_fees": state.burned_fees,
        "utxo_root": state.utxo.root,
        "nf_root": state.nullifiers.root,
        "registers_root": compute_registers_root(
            {g: r.root() for g, r in registers.items()}),
        "utxo_count": n_utxo,
        "nullifier_count": n_nf,
        "chunk": chunk,
        "parts": [[kind, index, len(payload),
                   chunk_digest(kind, index, payload)]
                  for kind, index, payload in parts],
    }
    with open(path, "wb") as fh:
        fh.write(MAGIC)
        fh.write(bytes([VERSION]))
        blob = codec.encode(manifest)
        head = bytearray()
        codec.put_uint(head, len(blob))
        fh.write(bytes(head))
        fh.write(blob)
        for kind, index, payload in parts:
            _put(fh, kind, index, payload)
        fh.flush()
        os.fsync(fh.fileno())
    return manifest


def write_parts(manifest: dict, parts, path):
    """Assemble a snapshot file from chunks that arrived one at a time.

    Every chunk is checked against the digest the manifest commits before it is
    written, so a file this produces is one `load` can be handed — and a peer
    that served a wrong range is caught here, by name, rather than at the fold
    where all anybody knows is that the roots do not match.
    """
    wanted = {(int(k), int(i)): (int(size), str(digest))
              for k, i, size, digest in manifest.get("parts", ())}
    have = {(int(k), int(i)): bytes(p) for k, i, p in parts}
    missing = sorted(set(wanted) - set(have))
    if missing:
        raise SnapshotError(f"{len(missing)} chunks missing, first is "
                            f"{missing[0]}")
    for key, (size, digest) in sorted(wanted.items()):
        payload = have[key]
        if len(payload) != size:
            raise SnapshotError(f"chunk {key} is {len(payload)} bytes, the "
                                f"manifest says {size}")
        if chunk_digest(key[0], key[1], payload) != digest:
            raise SnapshotError(f"chunk {key} fails the digest the manifest "
                                f"commits")
    with open(path, "wb") as fh:
        fh.write(MAGIC)
        fh.write(bytes([VERSION]))
        blob = codec.encode(manifest)
        head = bytearray()
        codec.put_uint(head, len(blob))
        fh.write(bytes(head))
        fh.write(blob)
        for key in sorted(wanted):
            _put(fh, key[0], key[1], have[key])
        fh.flush()
        os.fsync(fh.fileno())
    return path


def manifest_of(path) -> dict:
    """Just the manifest, without reading the chunks."""
    return _read_manifest(path)[0]


def read_chunk(path, kind: int, index: int) -> bytes:
    """One chunk's payload, checked against its own digest on the way out."""
    _, chunks = _read(path)
    for k, i, payload in chunks:
        if (k, i) == (int(kind), int(index)):
            return payload
    raise SnapshotError(f"no chunk {kind}/{index} in this snapshot")


def _read_manifest(path):
    """(manifest, blob, position after it)."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if not blob.startswith(MAGIC):
        raise SnapshotError("not a fin6 snapshot")
    pos = len(MAGIC)
    if blob[pos] != VERSION:
        raise SnapshotError(f"snapshot version {blob[pos]}")
    pos += 1
    buf = memoryview(blob)
    n, pos = codec.get_uint(buf, pos)
    return codec.decode(bytes(buf[pos:pos + n])), blob, pos + n


def _read(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    if not blob.startswith(MAGIC):
        raise SnapshotError("not a fin6 snapshot")
    pos = len(MAGIC)
    if blob[pos] != VERSION:
        raise SnapshotError(f"snapshot version {blob[pos]}")
    pos += 1
    buf = memoryview(blob)
    n, pos = codec.get_uint(buf, pos)
    manifest = codec.decode(bytes(buf[pos:pos + n]))
    pos += n
    chunks = []
    while pos < len(blob):
        start = pos
        kind, pos = codec.get_uint(buf, pos)
        index, pos = codec.get_uint(buf, pos)
        size, pos = codec.get_uint(buf, pos)
        head = bytes(buf[start:pos])
        payload = bytes(buf[pos:pos + size])
        pos += size
        digest = bytes(buf[pos:pos + 32])
        pos += 32
        if hashlib.sha256(head + payload).digest() != digest:
            raise SnapshotError(f"chunk {kind}/{index} fails its digest")
        chunks.append((kind, index, payload))
    return manifest, chunks


def load(path, params: ChainParams, *, expect_roots: dict):
    """Read a snapshot and refuse it unless it folds to the roots you name.

    `expect_roots` comes from a block header — `utxo_root`, `nf_root` and
    `registers_root`.  Without it there is nothing to check against, so this
    does not offer a way to skip it.
    """
    for key in ("utxo_root", "nf_root", "registers_root"):
        if key not in expect_roots:
            raise SnapshotError(f"expect_roots must name {key}")
    manifest, chunks = _read(path)

    utxo, dead, nfs, registers = [], [], [], {}
    for kind, index, payload in sorted(chunks, key=lambda c: (c[0], c[1])):
        value = codec.decode(payload)
        if kind == KIND_UTXO:
            part, flags = value
            dead.extend(len(utxo) + f for f in flags)
            utxo.extend(part)
        elif kind == KIND_NF:
            nfs.extend(value)
        elif kind == KIND_REGISTERS:
            for dump in value:
                registers[dump["grid_id"]] = GridRegister.load(dump)
        else:
            raise SnapshotError(f"unknown chunk kind {kind}")

    if len(utxo) != manifest["utxo_count"]:
        raise SnapshotError(f"{len(utxo)} notes, manifest says "
                            f"{manifest['utxo_count']} — chunks are missing")
    if len(nfs) != manifest["nullifier_count"]:
        raise SnapshotError("nullifier chunks are missing")

    state = ChainState.load(params, {
        "chain_id": manifest["chain_id"], "height": manifest["height"],
        "tip": manifest["tip"], "burned_fees": manifest["burned_fees"],
        "utxo": utxo, "utxo_dead": dead, "nullifiers": nfs})

    got = {"utxo_root": state.utxo.root,
           "nf_root": state.nullifiers.root,
           "registers_root": compute_registers_root(
               {g: r.root() for g, r in registers.items()})}
    for key, want in expect_roots.items():
        if got[key] != want:
            raise SnapshotError(
                f"{key} folds to {str(got[key])[:18]}…, the header says "
                f"{str(want)[:18]}… — this snapshot is not that chain's state")
    return state, registers


def verify(path, expect_roots: dict, params: ChainParams) -> tuple:
    """(ok, reason).  Same work as `load`, thrown away."""
    try:
        load(path, params, expect_roots=expect_roots)
    except (SnapshotError, ValueError) as exc:
        return False, str(exc)
    return True, "ok"


def roots_of(header) -> dict:
    """The three roots a network block header commits, in the shape `load`
    wants.  The point of the snapshot design is that this is all it takes."""
    return {"utxo_root": header.utxo_root, "nf_root": header.nf_root,
            "registers_root": header.registers_root}
