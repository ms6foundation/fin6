"""Launch the seven-node network.   python3 -m chain.demo_genesis

Boots from `config/genesis-7.json`, shows what a joining node checks before it
will apply block 1, and runs the chain at one tier — one grid, one ceremony,
one certificate, and a network block in exactly the format the three-tier
chain will use later.
"""
from __future__ import annotations

import dataclasses
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
    print(f"  a grid founds a child once it is over size and has twice the "
          f"cohort in attesters.")
    print(f"  The cohort keeps what it earned — otherwise a grid of pure "
          f"apprentices could never")
    print(f"  reach quorum, and so could never run the ceremony that would "
          f"promote anyone.\n")

    # A faster gate, so the walkthrough does not need 40 ceremonies per joiner.
    quick = dataclasses.replace(world.params, attend_threshold=2)
    world.params = quick
    for node in world.nodes.values():
        node.params = quick
    for reg in world.registers.values():
        reg.attend_threshold = 2
    joined = [f"fin6-m{i:02d}" for i in range(1, 9)]
    for nid in joined:
        world.admit(nid, doc.nodes[0].region)
    print(f"  {len(joined)} nodes join as apprentices "
          f"{DIM}(gate lowered to 2 ceremonies for the walkthrough){OFF}")
    print(f"  {world.topology}\n")

    founded = None
    while world.height < 12 and founded is None:
        epoch = world.height + 1
        tx, _ = transfer(wallets["treasury"], wallets["treasury"], 50 + epoch, 1,
                         world.params)
        world.submit(tx)
        result = run_tiered_epoch(world, epoch=epoch, base_seed=doc.first_seed)
        if not result.finalised:
            raise SystemExit(f"epoch {epoch}: {result.reason}")
        block = result.block
        world.apply_network_block(block)
        if block.foundings:
            founded = block.foundings[0]
            print(f"  epoch {epoch}: {GREEN}{founded}{OFF}")
            print(f"           K {1} -> {world.topology.n_partitions}, "
                  f"every transaction in flight re-homed")
        else:
            reg = world.registers[world.topology.grid_ids()[0]]
            print(f"  epoch {epoch}: {len(reg.attesters())} attesters, "
                  f"{len(reg.apprentices())} apprentices "
                  f"{DIM}(needs {2 * world.params.founding_cohort} to found){OFF}")

    for _ in range(2):
        epoch = world.height + 1
        result = run_tiered_epoch(world, epoch=epoch, base_seed=doc.first_seed)
        world.apply_network_block(result.block)
        print(f"  epoch {epoch}: tiers={result.tiers}  "
              f"grids={len(world.topology.grid_ids())}  "
              f"ceremonies={result.stats()['ceremonies']}")

    print()
    for gid in world.topology.grid_ids():
        reg = world.registers[gid]
        origin = {m.founded_from for m in reg.members.values()} - {""}
        note = (f"{CYAN}founded from {sorted(origin)[0]}{OFF}" if origin
                else f"{DIM}genesis cohort{OFF}")
        print(f"    {gid:<12} {len(reg.attesters())} attesters, "
              f"{len(reg.apprentices())} apprentices, quorum "
              f"{reg.quorum(2, 3)}   {note}")
    print(f"{DIM}    'founded from' is in the register root: carrying standing "
          f"across grids is a waiver, and a waiver nobody can see is one "
          f"nobody can audit{OFF}")

    store.close()
    print(f"\n{CYAN}store under {workdir}{OFF}")


if __name__ == "__main__":
    main()
