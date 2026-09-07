"""Stop the chain, start it again.   python3 -m chain.demo_persistence

Runs a tiered world against a real store, closes it, opens it in what may as
well be a new process, and shows that the roots, the tip and the registers came
back exactly — then rolls a block off, takes a snapshot that proves itself
against a header, and demonstrates the one write that has to precede the thing
it protects.
"""
from __future__ import annotations

import dataclasses
import os
import tempfile
import time

from .hardening.params import PRODUCTION
from .network import transfer
from .params import DEMO
from .store import snapshot as snap
from .store.db import ChainStore
from .store.high_water import HighWater, HighWaterError
from .store.undo import retention_depth
from .tiers import bootstrap_world, run_tiered_epoch

BOLD, DIM, GREEN, CYAN, RED, OFF = ("\033[1m", "\033[2m", "\033[32m",
                                    "\033[36m", "\033[31m", "\033[0m")

PARAMS = dataclasses.replace(DEMO, attend_threshold=3, grid_size=5, row_size=5)
REGIONS = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(20)}
ENDOW = {"alice": [1000, 900, 800, 700], "bob": [250]}


def rule(t):
    print(f"\n{BOLD}{t}{OFF}\n{DIM}{'─' * 76}{OFF}")


def short(x):
    text = str(x)
    return text if len(text) <= 18 else text[:17] + "…"


def main():
    print(f"{BOLD}fin6 — a chain that survives a restart{OFF}")
    workdir = tempfile.mkdtemp()
    db_path = os.path.join(workdir, "n00.db")

    # ── run ──────────────────────────────────────────────────────────────────
    rule("1. three epochs, committed as they finalise")
    world, wallets = bootstrap_world(REGIONS, ENDOW, PARAMS)
    store = ChainStore(db_path, undo_depth=retention_depth(PRODUCTION))
    world.persist(store, ["n00"])
    print(f"  node n00 has a store; the other {len(world.nodes)-1} are memory only")
    for e in (1, 2, 3):
        tx, _ = transfer(wallets["alice"], wallets["bob"], 200 + e, 5, PARAMS)
        world.submit(tx)
        t0 = time.time()
        result = run_tiered_epoch(world, epoch=e, base_seed="demo")
        if not result.finalised:
            raise SystemExit(result.reason)
        world.apply_network_block(result.block)
        print(f"  epoch {e}: height {result.block.height}, "
              f"{sum(1 for _ in result.block.transactions())} tx, "
              f"tip {short(result.block.hash())}  {DIM}{time.time()-t0:.2f}s{OFF}")
    live = world.nodes["n00"].state
    stats = store.stats()
    print(f"\n  on disk: {stats['bytes']:,} B — {stats['utxo_rows']} notes "
          f"({stats['utxo_live']} live), {stats['nullifiers']} nullifiers, "
          f"{stats['netblocks']} headers, {stats['undo_records']} undo records")
    print(f"{DIM}  the epoch below tier 2 was a journal; nothing under it was "
          f"written at all{OFF}")
    store.close()

    # ── restart ──────────────────────────────────────────────────────────────
    rule("2. the process ends.  a new one opens the same file")
    fresh, _ = bootstrap_world(REGIONS, ENDOW, PARAMS)
    store = ChainStore(db_path)
    t0 = time.time()
    fresh.restore_from(store)
    back = fresh.nodes["n00"].state
    print(f"  loaded in {time.time()-t0:.2f}s — the accumulators were rebuilt "
          f"from their values, not replayed from blocks")
    for label, a, b in (("height", back.height, live.height),
                        ("tip", back.tip, live.tip),
                        ("utxo root", back.utxo.root, live.utxo.root),
                        ("nf root", back.nullifiers.root, live.nullifiers.root),
                        ("burned fees", back.burned_fees, live.burned_fees)):
        mark = f"{GREEN}same{OFF}" if a == b else f"{RED}DIFFERENT{OFF}"
        print(f"    {label:12} {short(a):20} {mark}")
    same = all(fresh.registers[g].root() == world.registers[g].root()
               for g in world.registers)
    print(f"    {'registers':12} {f'{len(fresh.registers)} grids':20} "
          f"{GREEN if same else RED}{'same' if same else 'DIFFERENT'}{OFF}")
    print(f"  {DIM}mempools came back empty on purpose — gossip refills them, and "
          f"a restored one re-admits what the chain has since invalidated{OFF}")

    tx, _ = transfer(wallets["alice"], wallets["bob"], 260, 5, PARAMS)
    fresh.submit(tx)
    result = run_tiered_epoch(fresh, epoch=4, base_seed="demo")
    print(f"  and it keeps going: epoch 4 finalised = {result.finalised}")
    if result.finalised:
        fresh.apply_network_block(result.block)

    # ── rollback ─────────────────────────────────────────────────────────────
    rule("3. rolling the tip off, in memory and on disk together")
    state = store.load_state(PARAMS)
    registers = store.load_registers()
    print(f"  before: height {state.height}, utxo root {short(state.utxo.root)}")
    record = store.rollback(state, registers)
    print(f"  {record.summary()}")
    print(f"  after:  height {state.height}, utxo root {short(state.utxo.root)}"
          f"  {GREEN}matches the pre-block root{OFF}")
    depth = retention_depth(PRODUCTION)
    print(f"{DIM}  undo is kept {depth} blocks deep — the ceiling a third of the "
          f"turn pool could ever reach, which is {depth*PRODUCTION.block_interval/3600:.1f} h{OFF}")

    # ── snapshot ─────────────────────────────────────────────────────────────
    rule("4. a snapshot that proves itself against a header")
    target = os.path.join(workdir, "state.snap")
    manifest = snap.export(state, registers, target, chunk=2)
    print(f"  wrote {os.path.getsize(target):,} B in chunks of 2, each digested")
    roots = {k: manifest[k] for k in ("utxo_root", "nf_root", "registers_root")}
    t0 = time.time()
    joined, regs = snap.load(target, PARAMS, expect_roots=roots)
    print(f"  a joiner folds it and checks the three roots the header commits: "
          f"{GREEN}accepted{OFF} in {time.time()-t0:.2f}s "
          f"(height {joined.height}, {len(regs)} registers)")
    bad = dict(roots, utxo_root=roots["utxo_root"] ^ 1)
    ok, why = snap.verify(target, bad, PARAMS)
    print(f"  against the wrong header: {RED}refused{OFF} — {why[:66]}…")
    print(f"{DIM}  snapshot sync trusts consensus; genesis sync trusts nobody and "
          f"needs an archive{OFF}")

    # ── the guard ────────────────────────────────────────────────────────────
    rule("5. the write that comes before the signature")
    hw = HighWater(os.path.join(workdir, "turns.hw"))
    print(f"  {hw}")
    hw.claim(41)
    print(f"  claim(41) -> fsynced, then and only then would the turn sign")
    try:
        hw.claim(41)
    except HighWaterError as exc:
        print(f"  claim(41) again -> {RED}refused{OFF}: {str(exc)[:60]}…")
    reopened = HighWater(hw.path)
    print(f"  reopened after a crash: mark is still {reopened.value}")
    print(f"{DIM}  a holder restored from backup does not trust this file — it "
          f"adopts the highest height the chain shows before signing{OFF}")

    store.close()
    print(f"\n{CYAN}store, snapshot and mark are under {workdir}{OFF}")


if __name__ == "__main__":
    main()
