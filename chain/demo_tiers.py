"""The tiered chain, end to end.   python3 -m chain.demo_tiers"""
from __future__ import annotations

import dataclasses
import sys
import time

from .network import transfer
from .locality import tx_partition
from .params import DEMO, DESIGNED
from .proofs import available_backends, get_backend
from .register import Standing
from .tiers import bootstrap_world, run_tiered_epoch

BOLD, DIM, GREEN, CYAN, WARN, OFF = (
    "\033[1m", "\033[2m", "\033[32m", "\033[36m", "\033[33m", "\033[0m")


def rule(title):
    print(f"\n{BOLD}{title}{OFF}\n{DIM}{'─' * 74}{OFF}")


def main(argv=None):
    params = dataclasses.replace(DEMO, attend_threshold=3, grid_size=5,
                                 row_size=5)
    n = 40
    regions = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(n)}

    rule(f"1. Topology — {n} validators, grid size {params.grid_size}")
    t = time.time()
    world, wallets = bootstrap_world(
        regions, {"alice": [1000, 800], "bob": [250], "carol": []}, params,
        newcomers={"new0": "eu"})
    print(f"   built in {time.time() - t:.2f}s")
    for g in world.topology.grid_ids():
        r = world.registers[g]
        print(f"   {g:<8} partition {world.topology.partition_of(g):>2}  "
              f"{len(world.topology.members(g))} seats  "
              f"{len(r.attesters())} attesters, "
              f"{len(r.apprentices())} apprentices")
    print(f"   {DIM}locality proposes, the seed disposes — no node picks its "
          f"own grid{OFF}")

    rule("2. Standing")
    home_grid = world.topology.grid_of("new0")
    print(f"   new0 joined {home_grid} as an "
          f"{world.registers[home_grid].standing_of('new0')}")
    print(f"   it holds a seat and does the work, but its attestation does not "
          f"count until it has")
    print(f"   attended {params.attend_threshold} consecutive ceremonies "
          f"{DIM}(40 in the real setting){OFF}")

    rule("3. Proof systems, one per tier")
    print(f"   available backends: {available_backends()}")
    for tier in ("local", "super", "supreme"):
        name = params.backend_for(tier)
        b = get_backend(name)
        print(f"   {tier:<8} → {name:<7} {b.passes}-pass, "
              f"{b.rounds_for(params.security_bits):>3} rounds for 2^-80")
    print(f"   {DIM}designed policy is {DESIGNED.backend_for('local')} at the "
          f"local tier; not implemented, so this run falls back to ssh5{OFF}")

    rule("4. A transfer — alice pays bob 300, fee 5")
    t = time.time()
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, params)
    print(f"   built in {time.time() - t:.2f}s, carrying "
          f"{len(tx.proofs)} proofs ({', '.join(sorted(tx.proofs))}) "
          f"= {tx.proof_bytes() / 1024:.0f} KB")
    part = tx_partition(tx, world.topology.n_partitions)
    ok, why, owner = world.submit(tx)
    print(f"   nullifier lands in partition {part} → grid {owner} "
          f"{DIM}({why}){OFF}")
    print(f"   {DIM}no other grid may include it, so a cross-grid double spend "
          f"cannot arise{OFF}")

    rule("5. The epoch")
    t = time.time()
    result = run_tiered_epoch(world, epoch=1, base_seed="demo")
    elapsed = time.time() - t
    st = result.stats()
    print(f"   {'phase L':<9} {st['grids_finalised']}/{st['grids']} grids "
          f"finalised a CeremonyBlock")
    for g, block in sorted(result.local.blocks.items())[:3]:
        print(f"     {g:<8} {len(block.transactions)} txs  "
              f"delta {block.delta}  register_root "
              f"{str(block.header.register_root)[:10]}…")
    print(f"     {DIM}… {st['grids'] - 3} more{OFF}")
    print(f"   {'phase S':<9} {len(result.supers.finalised)} super grids "
          f"bundled them")
    for s_id, block in sorted(result.supers.blocks.items()):
        print(f"     {s_id:<8} {len(block.children)} grids, "
              f"{len(block.dropped)} dropped")
    print(f"   {'phase X':<9} supreme grid computed the global roots")
    b = result.block
    print(f"     utxo_root {str(b.header.utxo_root)[:14]}…  "
          f"nf_root {str(b.header.nf_root)[:14]}…")
    print(f"\n   {GREEN}{result.status}{OFF} — {result.tiers} tiers, "
          f"{st['ceremonies']} ceremonies, {st['directed_messages']} directed "
          f"messages, {elapsed:.1f}s")
    print(f"   {b}")

    world.apply_network_block(b)
    agree = len({nd.state.utxo.root for nd in world.nodes.values()}) == 1
    print(f"   applied — all {len(world.nodes)} validators agree on both roots: "
          f"{GREEN if agree else WARN}{agree}{OFF}")
    print(f"   balances: " + "  ".join(f"{k}={v.balance()}"
                                       for k, v in wallets.items()))

    rule("6. Standing accrues")
    reg = world.registers[home_grid]
    print(f"   after epoch 1: new0 consecutive="
          f"{reg.members['new0'].consecutive}, {reg.standing_of('new0')}")
    for epoch in range(2, params.attend_threshold + 2):
        tx, _ = transfer(wallets["alice"], wallets["carol"], 50, 5, params)
        world.submit(tx)
        r = run_tiered_epoch(world, epoch=epoch, base_seed="demo")
        if not r.finalised:
            print(f"   epoch {epoch}: {WARN}{r.reason}{OFF}")
            break
        world.apply_network_block(r.block)
        rec = reg.members["new0"]
        mark = f" {GREEN}← promoted{OFF}" if rec.standing == Standing.ATTESTER else ""
        print(f"   after epoch {epoch}: consecutive={rec.consecutive}, "
              f"{rec.standing}{mark}")
    print(f"   {DIM}the counter lives in the grid's register, so relocating "
          f"restarts it — capturing a grid costs {params.attend_threshold} "
          f"ceremonies per node, in the open{OFF}")

    rule("7. Final state")
    node = world.nodes[next(iter(world.nodes))]
    print(f"   height {world.height}   {len(node.state.utxo)} unspent notes   "
          f"{len(node.state.nullifiers)} nullifiers   "
          f"{node.state.burned_fees} fees burned")
    print(f"   registers: " + ", ".join(
        f"{g}={len(world.registers[g].attesters())}a/"
        f"{len(world.registers[g].apprentices())}p"
        for g in world.topology.grid_ids()[:4]) + " …")
    print(f"   balances: " + "  ".join(f"{k}={v.balance()}"
                                       for k, v in wallets.items()))
    print(f"\n   {DIM}blocks reach the supreme mempool here.  Moving them into "
          f"network history is part three.{OFF}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
