"""End-to-end demonstration.   python3 -m chain.demo [--strong]"""
from __future__ import annotations

import sys
import time

from .ceremony import EquivocatingLeader, Grid, SilentLeader, run_epoch
from .crypto import h_hex
from .network import bootstrap, transfer
from .params import DEMO, STRONG

BOLD, DIM, GREEN, RED, CYAN, OFF = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[36m", "\033[0m")


def rule(title):
    print(f"\n{BOLD}{title}{OFF}\n{DIM}{'─' * 72}{OFF}")


def main(argv=None):
    argv = argv or sys.argv[1:]
    params = STRONG if "--strong" in argv else DEMO
    validators = [f"v{i:02d}" for i in range(13)]
    quorum = params.quorum_size(len(validators))

    rule(f"1. Network — {len(validators)} validators, preset '{params.name}'")
    t = time.time()
    nodes, wallets, genesis = bootstrap(
        validators, {"alice": [1000, 800], "bob": [250], "carol": []}, params)
    print(f"   genesis {genesis} in {time.time() - t:.2f}s")
    print(f"   note = {params.n_note} coords ({params.note_blinders} blinders), "
          f"range {params.range_bits} bits, {params.zk_rounds} ZK rounds")
    print(f"   balances: " + "  ".join(
        f"{n}={w.balance()}" for n, w in wallets.items()))
    print(f"   {DIM}the chain stores only commitments; these balances are the "
          f"wallets' own secret openings{OFF}")

    rule("2. A transfer — alice pays bob 300, fee 5")
    t = time.time()
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, params)
    build_s = time.time() - t
    ts_shape = f"{len(tx.inputs)}in/{len(tx.output_cms)}out"
    print(f"   built in {build_s:.2f}s   {ts_shape}   "
          f"proof {tx.proof_bytes() / 1024:.0f} KB   v has {len(tx.v)} rows")
    print(f"   on chain: nullifier {tx.nullifiers[0][:22]}…")
    print(f"             outputs   {', '.join(c[:14] + '…' for c in tx.output_cms)}")
    print(f"             fee       {tx.fee} (public)")
    print(f"   {DIM}amounts, output owners and note randomness never appear{OFF}")
    t = time.time()
    for n in nodes.values():
        ok, why = n.submit(tx)
        assert ok, why
    print(f"   all {len(nodes)} validators verified and admitted it "
          f"({(time.time() - t) / len(nodes) * 1000:.0f} ms each)")

    rule("3. The ceremony grid")
    seed = h_hex("view", "demo", 1, 0)
    grid = Grid.seat(validators, params.row_size, seed)
    print(grid.render())
    print(f"   {DIM}seating derives from the previous block's hash, so nobody "
          f"picks their neighbours{OFF}")

    rule("4. Ceremony for block 1")
    t = time.time()
    epoch = run_epoch(nodes, params, height=1, epoch=1, base_seed="demo")
    result = epoch.result
    print(f"   {'round':>6} {'seats with proposal':>21} {'attestations held':>19}")
    for row in result.trace:
        bar = "█" * row["with_proposal"]
        print(f"   {row['round']:>6} {row['with_proposal']:>10} {bar:<14}"
              f"{row['max_attestations']:>10}")
    print(f"\n   {GREEN}{result.status}{OFF} in {result.rounds} rounds "
          f"({time.time() - t:.1f}s), {len(result.accepted())}/{len(validators)} "
          f"seats accepted, quorum {quorum}")
    print(f"   {result.directed_messages} directed messages "
          f"({result.directed_messages // result.rounds} per round, "
          f"degree 2 per seat)")
    validator_keys = {n.id: n.public_hex for n in nodes.values()}
    ok, why = result.quorum_cert.verify(quorum, result.block.hash(), validator_keys)
    print(f"   quorum certificate verifies standalone: {GREEN if ok else RED}{ok}{OFF} ({why})")

    for n in nodes.values():
        n.apply(result.block)
    print(f"   applied — every validator at height "
          f"{ {n.state.height for n in nodes.values()} }, utxo roots agree: "
          f"{len({n.state.utxo.root for n in nodes.values()}) == 1}")

    rule("5. A leader that equivocates")
    seed2 = h_hex("view", "demo2", 2, 0)
    bad_leader = Grid.seat(validators, params.row_size, seed2).leader
    tx2, _ = transfer(wallets["alice"], wallets["carol"], 200, 5, params)
    for n in nodes.values():
        n.submit(tx2)
    print(f"   {bad_leader} sends block A into even columns of row 1 and block B "
          f"into odd ones.")
    print(f"   {DIM}both blocks are individually valid, so no seat can catch "
          f"this on its own{OFF}")
    epoch2 = run_epoch(nodes, params, height=2, epoch=2, base_seed="demo2",
                       behaviours={bad_leader: EquivocatingLeader()})
    first = epoch2.attempts[0]
    reports = [f for f in first.faults if f.kind == "equivocation"]
    print(f"   attempt 0 (leader {first.grid.leader}): {RED}{first.status}{OFF} "
          f"— {first.reason}")
    print(f"   {len(reports)} seats filed equivocation reports; evidence "
          f"self-substantiating: {all(f.substantiated() for f in reports)}")
    print(f"   {CYAN}the rings did it{OFF}: two columns of one row held "
          f"different blocks, and a row is a ring")
    print(f"   view change → leader {epoch2.result.grid.leader}: "
          f"{GREEN}{epoch2.result.status}{OFF} after {len(epoch2.attempts)} attempts")
    for n in nodes.values():
        n.apply(epoch2.result.block)

    rule("6. A leader that says nothing")
    seed3 = h_hex("view", "demo3", 3, 0)
    silent = Grid.seat(validators, params.row_size, seed3).leader
    tx3, _ = transfer(wallets["bob"], wallets["carol"], 100, 5, params)
    for n in nodes.values():
        n.submit(tx3)
    epoch3 = run_epoch(nodes, params, height=3, epoch=3, base_seed="demo3",
                       behaviours={silent: SilentLeader()})
    print(f"   leader {silent} proposes nothing → "
          f"{RED}{epoch3.attempts[0].status}{OFF} "
          f"({epoch3.attempts[0].reason[:44]})")
    print(f"   view change → leader {epoch3.result.grid.leader}: "
          f"{GREEN}{epoch3.result.status}{OFF}")
    for n in nodes.values():
        n.apply(epoch3.result.block)

    rule("7. Final state")
    node = nodes["v00"]
    print(f"   height {node.state.height}   "
          f"{len(node.state.utxo)} unspent notes   "
          f"{len(node.state.nullifiers)} nullifiers   "
          f"{node.state.burned_fees} in fees burned")
    print(f"   balances: " + "  ".join(
        f"{n}={w.balance()}" for n, w in wallets.items()))
    agree = (len({n.state.utxo.root for n in nodes.values()}) == 1
             and len({n.state.tip for n in nodes.values()}) == 1)
    print(f"   all {len(nodes)} validators agree on the tip and both roots: "
          f"{GREEN if agree else RED}{agree}{OFF}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
