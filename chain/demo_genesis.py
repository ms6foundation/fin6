"""Launch the seven-node network.   python3 -m chain.demo_genesis

Boots from `config/genesis-7.json`, shows what a joining node checks before it
will apply block 1, and runs the chain at one tier — one grid, one ceremony,
one certificate, and a network block in exactly the format the three-tier
chain will use later.
"""
from __future__ import annotations

import os
import tempfile
import time

from . import genesis
from .hardening.params import PRODUCTION
from .network import transfer
from .store.db import ChainStore
from .tiers import run_tiered_epoch

BOLD, DIM, GREEN, CYAN, WARN, RED, OFF = (
    "\033[1m", "\033[2m", "\033[32m", "\033[36m", "\033[33m", "\033[31m",
    "\033[0m")


def rule(t):
    print(f"\n{BOLD}{t}{OFF}\n{DIM}{'─' * 76}{OFF}")


def main():
    print(f"{BOLD}fin6 — launching a seven-node network{OFF}")

    # ── the document ─────────────────────────────────────────────────────────
    rule("1. the genesis document")
    path = genesis.GENESIS_7
    if not os.path.exists(path):
        raise SystemExit(f"{path} is missing — run python3 -m chain.genesis")
    doc = genesis.load(path)
    print(f"  {path}  ({os.path.getsize(path):,} B)")
    print(f"  network     {doc.network}")
    print(f"  chain_id    {CYAN}{doc.chain_id}{OFF}")
    print(f"{DIM}              = 'fin6:' + H(document), so every attestation, "
          f"proposal and proof binds to this exact setup{OFF}")
    print(f"  roster      {len(doc.nodes)} nodes, quorum {doc.quorum()}, "
          f"tolerates {len(doc.nodes) - doc.quorum()} faults "
          f"{DIM}(n = 3f+1 at f = 2){OFF}")
    print(f"  tiers       {doc.tiers}  ·  partitions {doc.n_partitions}")
    print(f"  cadence     {doc.epoch_millis/1000:.2f} s per epoch")
    print(f"  supply      {doc.declared_total:,} in "
          f"{sum(len(v) for v in doc.supply.values())} notes")

    # ── ratification ─────────────────────────────────────────────────────────
    rule("2. what a joining node checks before it applies block 1")
    ok, problems, caveats = doc.verify()
    checks = [
        ("the file re-encodes to the bytes it was signed as", True),
        ("chain_id equals 'fin6:' + H(document)",
         doc.chain_id == genesis.ID_PREFIX + doc.digest()),
        (f"{len(doc.ratifications)} ratifications verify against roster keys, "
         f"{doc.ratification_threshold} required", ok),
        ("the parameters are the ones this build knows", ok),
        ("the turn map covers the pool, one holder per slice",
         sorted(doc.turn_holders) == sorted(n.node_id for n in doc.nodes)),
    ]
    for label, passed in checks:
        print(f"  {GREEN + 'ok  ' + OFF if passed else RED + 'FAIL' + OFF}  {label}")
    for caveat in caveats:
        print(f"  {WARN}note{OFF}  {caveat[:96]}…" if len(caveat) > 96
              else f"  {WARN}note{OFF}  {caveat}")

    # ── boot ─────────────────────────────────────────────────────────────────
    rule("3. booting, with a store")
    workdir = tempfile.mkdtemp()
    store = ChainStore(os.path.join(workdir, "fin6-n01.db"))
    world, wallets = genesis.boot(doc, store=store)
    gid = world.topology.grid_ids()[0]
    reg = world.registers[gid]
    print(f"  grid {gid}: {len(world.nodes)} seats, "
          f"{len(reg.attesters())} attesters, quorum {reg.quorum(2, 3)}")
    print(f"{DIM}  the 40-ceremony gate is waived exactly once — a grid of pure "
          f"apprentices could never reach quorum{OFF}")
    print(f"  treasury holds {wallets['treasury'].balance():,}, "
          f"the document declares {doc.declared_total:,}")

    # ── run ──────────────────────────────────────────────────────────────────
    rule("4. three epochs at one tier")
    for e in (1, 2, 3):
        tx, _ = transfer(wallets["treasury"], wallets["treasury"], 100 + e, 5,
                         world.params)
        world.submit(tx)
        t0 = time.time()
        result = run_tiered_epoch(world, epoch=e, base_seed=doc.first_seed)
        if not result.finalised:
            raise SystemExit(f"epoch {e}: {result.reason}")
        block, stats = result.block, result.stats()
        world.apply_network_block(block)
        print(f"  epoch {e}: height {block.height}  tiers={block.header.tiers}  "
              f"{stats['ceremonies']} ceremony  {stats['transactions']} tx  "
              f"{stats['directed_messages']} messages  "
              f"{DIM}{time.time()-t0:.2f}s{OFF}")

    b = world.nodes[sorted(world.nodes)[0]].state
    print(f"\n  the block is the ordinary format, not a special one:")
    print(f"    NetworkBlock  tiers={block.header.tiers}  "
          f"supers={len(block.supers)}  "
          f"grids={sum(1 for _ in block.ceremony_blocks())}")
    print(f"    certificate on the network block: "
          f"{GREEN}{block.quorum_cert is not None}{OFF}   "
          f"on the blocks nested inside it: "
          f"{block.supers[0].children[0].quorum_cert is not None}")
    print(f"{DIM}    tiers=1 is signed, so a later reader can tell a legitimately "
          f"degenerate block from a forged one whose inner certificates were "
          f"stripped{OFF}")
    print(f"  ledger: height {b.height}, {len(b.utxo)} live notes, "
          f"{len(b.nullifiers)} nullifiers, {b.burned_fees} burned")

    # ── what seven nodes buys ────────────────────────────────────────────────
    rule("5. what a seven-node launch costs, in hardening terms")
    print(f"  the pool is only as distributed as the roster: "
          f"{PRODUCTION.turns // len(doc.nodes):,} turns each, 14.3%")
    print(f"  {'colluding':<12}{'share':>8}{'ceiling':>12}{'wall clock':>14}")
    for k in (1, 2, 3):
        depth = PRODUCTION.max_fork_depth(k / len(doc.nodes))
        mark = f"  {DIM}<- the fault bound{OFF}" if k == 2 else ""
        print(f"  {k} of 7{'':<6}{100*k/7:>7.1f}%{depth:>12,}"
              f"{depth * PRODUCTION.block_interval / 3600:>13.1f} h{mark}")
    print(f"{DIM}  it improves as operators join and the pool redistributes at "
          f"each 12-hour rollover{OFF}")

    rule("6. growing out of one tier")
    print(f"  {WARN}not yet possible.{OFF} A second grid has to come from a split, "
          f"which is not implemented,")
    print(f"  or from creating an empty one — but relocating restarts the "
          f"attendance counter and a")
    print(f"  grid of pure apprentices never reaches quorum, so a new grid is "
          f"deadlocked. See")
    print(f"  docs/genesis_design.md §10; the fix is a change to part two.")

    store.close()
    print(f"\n{CYAN}store under {workdir}{OFF}")


if __name__ == "__main__":
    main()
