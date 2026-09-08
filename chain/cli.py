"""fin6 — lay out a testnet, run it, look at it, break it.

    fin6 genesis new  testnet/ --nodes 7 --preset local
    fin6 net up       testnet/
    fin6 net status   testnet/
    fin6 net kill     testnet/ fin6-n03
    fin6 tx send      testnet/ --from treasury --to treasury --amount 100
    fin6 net down     testnet/

`net up` holds the child processes, so it runs in the foreground until
interrupted; every other command is a one-shot client.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import genesis as genesis_mod
from .net import supervisor as sv
from .net.peer import ask


def _status(root, exit_on_disagreement=True):
    net = sv.Testnet(root)
    status = net.status()
    agreement = net.agreement(status)
    print(sv.render_status(status, agreement))
    if exit_on_disagreement and not agreement[0]:
        return 1
    return 0


def cmd_genesis_new(args):
    info = sv.new_testnet(args.root, nodes=args.nodes, preset=args.preset,
                          epoch_millis=args.epoch_millis, force=args.force)
    print(f"wrote {info['root']}/genesis.json and net.json")
    print(f"  chain_id     {info['chain_id']}")
    print(f"  roster       {len(info['nodes'])} nodes, quorum {info['quorum']}, "
          f"tolerates {len(info['nodes']) - info['quorum']} faults")
    print(f"  cadence      {info['epoch_millis'] / 1000:.2f} s per epoch")
    print(f"  next         fin6 net up {args.root}")
    return 0


def cmd_net_up(args):
    net = sv.Testnet(args.root)
    net.up(until_epoch=args.until)
    print(f"started {len(net.procs)} nodes; ctrl-c to stop")
    try:
        while net.running():
            time.sleep(0.5)
            if args.until is not None and not net.running():
                break
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        net.down()
    return 0


def cmd_net_status(args):
    return _status(args.root, exit_on_disagreement=not args.no_fail)


def cmd_net_down(args):
    net = sv.Testnet(args.root)
    stopped = 0
    for node_id, spec in net.net["nodes"].items():
        host, port = spec["listen"]
        try:
            ask(host, port, net.doc.chain_id, "status", timeout=0.5)
            stopped += 1
        except OSError:
            pass
    print(f"{stopped} nodes are still answering; stop `net up` to end them")
    return 0


def cmd_tx_send(args):
    """Build a transfer from the genesis wallets and gossip it to one node.

    The genesis openings are derivable from the document (see the note in
    `bootstrap_world`), which is what makes a testnet wallet possible at all
    and is exactly what the genesis mint of design §2 would replace.
    """
    from .network import transfer
    from .net.frame import pack
    import socket

    root, net_cfg, doc = sv.load(args.root)
    world, wallets = genesis_mod.boot(doc)
    if args.sender not in wallets or args.to not in wallets:
        print(f"wallets are {sorted(wallets)}", file=sys.stderr)
        return 2
    tx, _ = transfer(wallets[args.sender], wallets[args.to], args.amount,
                     args.fee, world.params)
    target = args.node or sorted(net_cfg["nodes"])[0]
    host, port = net_cfg["nodes"][target]["listen"]
    with socket.create_connection((host, port), timeout=3) as sock:
        sock.sendall(pack("hello", doc.chain_id, {"node_id": "fin6-cli"}))
        sock.sendall(pack("tx", doc.chain_id, {"tx": tx}))
    print(f"sent {tx.txid[:20]}… ({tx.proof_bytes():,} B of proof) to {target}")
    return 0


def cmd_net_kill(args):
    print("`kill` needs the supervisor that started the nodes; run it from a "
          "python session holding the Testnet, or stop `net up`.",
          file=sys.stderr)
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fin6")
    sub = ap.add_subparsers(dest="group", required=True)

    g = sub.add_parser("genesis").add_subparsers(dest="cmd", required=True)
    new = g.add_parser("new", help="lay out a testnet")
    new.add_argument("root")
    new.add_argument("--nodes", type=int, default=7)
    new.add_argument("--preset", default="local")
    new.add_argument("--epoch-millis", dest="epoch_millis", type=int,
                     default=None)
    new.add_argument("--force", action="store_true")
    new.set_defaults(fn=cmd_genesis_new)

    n = sub.add_parser("net").add_subparsers(dest="cmd", required=True)
    up = n.add_parser("up", help="start every node")
    up.add_argument("root")
    up.add_argument("--until", type=int, default=None)
    up.set_defaults(fn=cmd_net_up)
    st = n.add_parser("status", help="heights, roots, agreement")
    st.add_argument("root")
    st.add_argument("--no-fail", action="store_true",
                    help="exit 0 even if the nodes disagree")
    st.set_defaults(fn=cmd_net_status)
    dn = n.add_parser("down")
    dn.add_argument("root")
    dn.set_defaults(fn=cmd_net_down)
    kl = n.add_parser("kill")
    kl.add_argument("root")
    kl.add_argument("node_id")
    kl.set_defaults(fn=cmd_net_kill)

    t = sub.add_parser("tx").add_subparsers(dest="cmd", required=True)
    send = t.add_parser("send")
    send.add_argument("root")
    send.add_argument("--from", dest="sender", default="treasury")
    send.add_argument("--to", default="treasury")
    send.add_argument("--amount", type=int, default=100)
    send.add_argument("--fee", type=int, default=1)
    send.add_argument("--node", default=None)
    send.set_defaults(fn=cmd_tx_send)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
