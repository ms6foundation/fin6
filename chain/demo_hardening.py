"""Consensus through to network history.   python3 -m chain.demo_hardening"""
from __future__ import annotations

import dataclasses
import random
import sys
import time

from .hardening import Era, HardeningParams, NetworkHistory, PRODUCTION
from .hardening.history import GENESIS
from .network import transfer
from .params import DEMO as CHAIN_DEMO
from .tiers import bootstrap_world, run_epoch_to_history

BOLD, DIM, GREEN, CYAN, WARN, RED, OFF = (
    "\033[1m", "\033[2m", "\033[32m", "\033[36m", "\033[33m", "\033[31m", "\033[0m")

HARD = HardeningParams(name="demo", turns=320, era_seconds=43_200, width=8,
                       difficulty_bits=14, tree_height=9)


def rule(t):
    print(f"\n{BOLD}{t}{OFF}\n{DIM}{'─' * 74}{OFF}")


def main(argv=None):
    params = dataclasses.replace(CHAIN_DEMO, attend_threshold=3, grid_size=5,
                                 row_size=5)

    rule("1. The era — two a day")
    print(f"   production: {PRODUCTION.summary()}")
    print(f"   {DIM}the pool is finite, so interval and era length are one knob:")
    print(f"   interval = era_seconds × width / turns = "
          f"43200 × 32 / 70000 = {PRODUCTION.block_interval:.2f}s{OFF}")
    print(f"   a 2^17 tree of 70,000 turns takes ~131 s of hashing to build — "
          f"precomputed,")
    print(f"   {DIM}which a 12-hour era gives ample room for{OFF}")
    print(f"\n   this demo runs {HARD.summary()}")

    t = time.time()
    era = Era(0, b"era-seed-0", tree_height=HARD.tree_height, turns=HARD.turns)
    history = NetworkHistory(era.spec, HARD)
    print(f"   pool built in {time.time() - t:.2f}s: {era}")

    rule("2. Network")
    regions = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(20)}
    world, wallets = bootstrap_world(
        regions, {"alice": [1000, 800], "bob": [250]}, params)
    print(f"   {world.topology}")
    print(f"   history starts empty: {history}")

    rule("3. Four epochs, consensus then hardening")
    print(f"   {'epoch':>6} {'grids':>6} {'stamps':>8} {'weight':>10} "
          f"{'cumulative':>12} {'turns left':>11}")
    for epoch in range(1, 5):
        tx, _ = transfer(wallets["alice"], wallets["bob"], 100, 5, params)
        world.submit(tx)
        t = time.time()
        res = run_epoch_to_history(world, history, era, epoch, "demo")
        dt = time.time() - t
        hb = res.hardened
        status = f"{GREEN}✓{OFF}" if res.finalised else f"{RED}✗{OFF}"
        print(f"   {epoch:>6} {len(res.epoch.local.finalised):>6} "
              f"{len(hb.stamps):>4}/{len(hb.drawn):<3} {hb.weight:>10,} "
              f"{hb.cumulative:>12,} {history.remaining_turns():>11,}  "
              f"{status} {dt:.1f}s")

    print(f"\n   {history}")
    print(f"   tip {history.tip.block_hash[:20]}…  "
          f"{history.confirmations(history.canonical()[0].block_hash)} "
          f"confirmations on the first block")
    print(f"   stamps cost {history.tip.bytes_of_stamps() / 1024:.0f} KB per block "
          f"{DIM}(84 KB at production width){OFF}")
    print(f"   all {len(world.nodes)} validators agree on the ledger roots: "
          f"{GREEN}{len({n.state.utxo.root for n in world.nodes.values()}) == 1}{OFF}")

    rule("4. What an attacker faces")
    print(f"   the committee is redrawn every block from the previous block's "
          f"hash, so a fork")
    print(f"   must clear the {HARD.threshold}-of-{HARD.width} threshold on a "
          f"fresh unbiased draw {BOLD}every time{OFF}")
    rng = random.Random(5)
    for share in (0.10, 0.25, 0.50, 1.00):
        owned = set(rng.sample(range(HARD.turns), int(HARD.turns * share)))

        class Evil:
            def hash(self): return f"nb:evil-{share}"

        hb = history.harden(Evil(), era, prev_hash=GENESIS, owned=owned)
        ok, why = history.check(hb)
        mark = f"{RED}forged{OFF}" if ok else f"{GREEN}refused{OFF}"
        print(f"   holds {share*100:>4.0f}% of the pool → stamped "
              f"{len(hb.stamps):>2}/{HARD.width}  {mark}  {DIM}{why}{OFF}")

    print(f"\n   {CYAN}and every attempt burns the turns it drew, forever{OFF}")
    print(f"   at production width, an attacker holding 50% clears the threshold "
          f"on 2.5% of blocks;")
    print(f"   six consecutive — the shallowest useful rewrite — is 2.5e-10")

    rule("5. Era arithmetic")
    print(f"   {'share':>7} {'turns':>8} {'ceiling (blocks)':>18} {'wall clock':>12}")
    for share in (0.05, 0.10, 0.25, 0.33):
        turns = int(70_000 * share)
        depth = PRODUCTION.max_fork_depth(share)
        print(f"   {share*100:>6.0f}% {turns:>8,} {depth:>18,} "
              f"{depth * PRODUCTION.block_interval / 3600:>10.1f} h")
    print(f"   {DIM}a hard ceiling from the finite pool — the second line of "
          f"defence, behind the threshold{OFF}")
    print(f"\n   this era has {history.blocks_left_in_era()} blocks left before "
          f"rollover")
    return 0


if __name__ == "__main__":
    sys.exit(main())
