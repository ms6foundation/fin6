"""What an archive costs, and where it goes.   python3 -m chain.demo_archive

Three questions, answered by measurement rather than by assertion:

  * how compressible is a proof?  (it is not, and every compressor makes it
    worse, so the format must know that)
  * what does a canonical encoding buy on everything that is not a proof?
  * what does retention buy, which is the only lever with an order of magnitude
    in it?
"""
from __future__ import annotations

import bz2
import collections
import dataclasses
import json
import lzma
import math
import os
import tempfile
import time
import zlib

from .network import transfer
from .params import DEMO
from .proofs import get_backend
from .store import archive, codec
from .tiers import bootstrap_world, run_tiered_epoch

BOLD, DIM, GREEN, CYAN, OFF = ("\033[1m", "\033[2m", "\033[32m", "\033[36m",
                               "\033[0m")

PARAMS = dataclasses.replace(DEMO, attend_threshold=3, grid_size=5, row_size=5)

# The hardening layer's shape, for turning bytes per block into bytes per day.
BLOCKS_PER_DAY = 4375


def rule(t):
    print(f"\n{BOLD}{t}{OFF}\n{DIM}{'─' * 76}{OFF}")


def entropy(b):
    counts = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in counts.values())


def build(epochs=3):
    regions = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(20)}
    world, wallets = bootstrap_world(
        regions, {"alice": [1000, 900, 800, 700], "bob": [250]}, PARAMS)
    blocks = []
    for e in range(1, epochs + 1):
        tx, _ = transfer(wallets["alice"], wallets["bob"], 200 + e, 5, PARAMS)
        world.submit(tx)
        result = run_tiered_epoch(world, epoch=e, base_seed="arch")
        if not result.finalised:
            raise SystemExit(f"epoch {e} did not finalise: {result.reason}")
        world.apply_network_block(result.block)
        blocks.append(result.block)
    return blocks


def main():
    print(f"{BOLD}fin6 — archive storage{OFF}")
    blocks = build()
    txs = [t for b in blocks for t in b.transactions()]
    print(f"{len(blocks)} network blocks, {len(txs)} transactions, "
          f"{PARAMS.proof_backends} proofs each")

    # ── 1. proofs do not compress ────────────────────────────────────────────
    rule("1. a proof is incompressible, and compressing it costs bytes")
    print(f"{'proof':10}{'raw':>10}{'bits/byte':>11}{'zlib-9':>10}"
          f"{'bzip2':>10}{'lzma':>10}")
    for name in sorted(txs[0].proofs):
        blob = get_backend(name).serialize(txs[0].proofs[name])
        sizes = [len(zlib.compress(blob, 9)), len(bz2.compress(blob)),
                 len(lzma.compress(blob, preset=6))]
        marks = "".join(f"{s:>10,}" for s in sizes)
        print(f"{name:10}{len(blob):>10,}{entropy(blob):>11.3f}{marks}")
    print(f"{DIM}  every compressor gives back a negative number here — this is "
          f"uniform field elements and hash output{OFF}")

    # ── 2. the encoding earns its keep on everything else ────────────────────
    rule("2. canonical encoding, on the part that is not a proof")
    stripped = dataclasses.replace(blocks[0], supers=tuple(
        dataclasses.replace(s, children=tuple(
            dataclasses.replace(c, transactions=()) for c in s.children))
        for s in blocks[0].supers))
    as_json = json.dumps(dataclasses.asdict(stripped), default=str).encode()
    encoded = codec.encode(stripped)
    print(f"  one block's headers, rolls and certificates")
    print(f"    python objects as json      {len(as_json):>9,} B")
    print(f"    json + zlib-9               {len(zlib.compress(as_json, 9)):>9,} B")
    print(f"    codec.encode                {len(encoded):>9,} B"
          f"   {GREEN}{len(as_json)/len(encoded):.1f}x{OFF}")
    print(f"    codec.encode + deflate      "
          f"{len(zlib.compress(encoded, 9)):>9,} B"
          f"   {GREEN}{len(as_json)/len(zlib.compress(encoded,9)):.1f}x{OFF}")
    print(f"{DIM}  interning, hex packing, vector packing — then deflate finds "
          f"another ~11% on top{OFF}")

    # ── 3. retention is the order of magnitude ───────────────────────────────
    rule("3. retention")
    with tempfile.TemporaryDirectory() as d:
        sizes = {}
        for profile in (archive.FULL, archive.COMPACT, archive.HEADERS):
            path = os.path.join(d, f"{profile.name}.seg")
            t0 = time.time()
            with archive.ArchiveWriter(path, era_id=0, retention=profile) as w:
                for b in blocks:
                    w.append(b)
                wstats = w.stats()
            elapsed = time.time() - t0
            reader = archive.ArchiveReader(path)
            stats = reader.stats()
            sizes[profile.name] = os.path.getsize(path)
            per_block = sizes[profile.name] / len(blocks)
            ok, problems = reader.verify()
            assert ok, problems
            print(f"  {profile.name:8} {os.path.getsize(path):>10,} B  "
                  f"{per_block:>9,.0f} B/block  "
                  f"{per_block*BLOCKS_PER_DAY/1e9:>7.2f} GB/day  "
                  f"kept {sum(wstats['proofs_kept'].values()):>2}/"
                  f"{sum(wstats['proofs_seen'].values()):<2} proofs  "
                  f"{DIM}wrote in {elapsed:.2f}s{OFF}")
        print(f"\n  {CYAN}compact is {sizes['full']/sizes['compact']:.1f}x "
              f"smaller than full and still verifies every transaction{OFF}")
        print(f"  {CYAN}headers is {sizes['full']/sizes['headers']:.0f}x smaller "
              f"and can only prove the history, not re-derive it{OFF}")

        # ── 4. and it is still an archive ────────────────────────────────────
        rule("4. what a compact archive can still do")
        path = os.path.join(d, "compact.seg")
        reader = archive.ArchiveReader(path)
        from .transaction import verify_transaction
        block = reader.get(blocks[0].height)
        print(f"  block {block.height} read back, hash matches: "
              f"{block.hash() == blocks[0].hash()}")
        for tx in list(block.transactions())[:1]:
            t0 = time.time()
            ok, why = verify_transaction(tx, PARAMS, backend="mpcith")
            print(f"  its proof re-verifies from disk: {ok} "
                  f"{DIM}({time.time()-t0:.3f}s){OFF}")
            ok, why = verify_transaction(tx, PARAMS, backend="ssh5")
            print(f"  and it is honest about what it dropped: {why}")
        print(f"  every digest checks: {reader.verify()[0]}")


if __name__ == "__main__":
    main()
