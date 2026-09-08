"""fin6 — lay out a testnet, run it, look at it, break it.

    fin6 genesis new  testnet/ --nodes 7 --preset local
    fin6 net up       testnet/
    fin6 light sync   testnet/                              # follow, verified
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


# ═══════════════════════════════════════════════════════════════════════════════
# Wallets
# ═══════════════════════════════════════════════════════════════════════════════

def _wallet_paths(root, name):
    home = os.path.join(os.path.abspath(root), "wallets")
    os.makedirs(home, exist_ok=True)
    return (os.path.join(home, f"{name}.seed"),
            os.path.join(home, f"{name}.notes.json"))


def _open_wallet(root, name, doc, params):
    from .keys import WalletKeys
    from .wallet import Wallet
    seed_path, notes_path = _wallet_paths(root, name)
    if not os.path.exists(seed_path):
        raise SystemExit(f"no wallet {name!r} — try: fin6 wallet new {root} "
                         f"--name {name}")
    with open(seed_path) as fh:
        keys = WalletKeys.from_phrase(fh.read().strip())
    if os.path.exists(notes_path):
        return Wallet.load(notes_path, keys, params), notes_path
    return Wallet(keys, params, chain_id=doc.chain_id, name=name), notes_path


def _client_for(root, net_cfg, doc, node_id=None):
    from .net.client import Client
    target = node_id or sorted(net_cfg["nodes"])[0]
    host, port = net_cfg["nodes"][target]["listen"]
    return Client(host, port, doc.chain_id), target


def cmd_wallet_new(args):
    from .keys import WalletKeys
    seed_path, notes_path = _wallet_paths(args.root, args.name)
    if os.path.exists(seed_path) and not args.force:
        raise SystemExit(f"{seed_path} exists; pass --force to replace it")
    phrase = args.phrase or args.name
    with open(seed_path, "w") as fh:
        fh.write(phrase + "\n")
    os.chmod(seed_path, 0o600)
    keys = WalletKeys.from_phrase(phrase)
    print(f"wallet {args.name}")
    print(f"  seed      {seed_path}  (mode 600 — this is the money)")
    print(f"  address   {keys.address.encode()}")
    if not args.phrase:
        print(f"  {'':10}the seed phrase is the wallet name, which is fine for "
              f"a testnet and nowhere else")
    return 0


def cmd_wallet_address(args):
    root, net_cfg, doc = sv.load(args.root)
    wallet, _ = _open_wallet(root, args.name, doc, doc.chain_params())
    print(wallet.address.encode())
    return 0


def cmd_wallet_sync(args):
    root, net_cfg, doc = sv.load(args.root)
    params = doc.chain_params()
    wallet, notes_path = _open_wallet(root, args.name, doc, params)
    client, target = _client_for(root, net_cfg, doc, args.node)
    before = wallet.balance()
    if args.tags is not None:
        result = client.scan_by_tag(wallet, bits=args.tags)
        wallet.save(notes_path)
        print(f"synced {args.name} against {target} to height "
              f"{result['height']}, node-sorted at {result['bits']} bits")
        print(f"  fetched {result['fetched']} of {result['scanned']} outputs "
              f"({result['reduction']:.0f}x less to read)")
        print(f"  found {result['found']} new note(s)")
        print(f"  balance {before} -> {wallet.balance()}")
        print("  the node now knows a set your outputs are hiding in; see "
              "chain/notes.py detection_tag")
        return 0
    result = client.sync(wallet)
    wallet.save(notes_path)
    print(f"synced {args.name} against {target} to height {result['height']}")
    print(f"  found {result['found']} new note(s), {result['spent']} spent")
    print(f"  balance {before} -> {result['balance']}")
    return 0


def cmd_wallet_balance(args):
    root, net_cfg, doc = sv.load(args.root)
    wallet, _ = _open_wallet(root, args.name, doc, doc.chain_params())
    print(f"{wallet.balance()}  in {len(wallet.unspent())} note(s), "
          f"scanned to height {wallet.scanned_to}")
    for held in sorted(wallet.unspent(), key=lambda h: -h.value):
        print(f"  {held.value:>8}  {held.cm[:20]}…  from height {held.height}")
    return 0


def cmd_wallet_send(args):
    from .keys import Address
    root, net_cfg, doc = sv.load(args.root)
    params = doc.chain_params()
    wallet, notes_path = _open_wallet(root, args.name, doc, params)
    to = Address.decode(args.to)
    tx, change = wallet.send(to, args.amount, fee=args.fee)
    client, target = _client_for(root, net_cfg, doc, args.node)
    client.submit(tx)
    wallet.save(notes_path)
    print(f"sent {args.amount} (+{args.fee} fee) to {to.short()} via {target}")
    print(f"  txid      {tx.txid}")
    print(f"  proof     {tx.proof_bytes():,} B in {sorted(tx.proofs)}")
    print(f"  sealed    {len(tx.output_notes)} openings, "
          f"{sum(len(x) for x in tx.output_notes)} B")
    print(f"  next      fin6 wallet sync {args.root} --name {args.name}")
    return 0


def cmd_wallet_import_genesis(args):
    """Reconstruct a genesis holder's wallet.

    Genesis issues notes outside any transaction, so they carry no sealed
    opening and cannot be found by scanning.  The openings are derivable from
    the document — see `bootstrap_world` — which is what makes this possible
    and is exactly why the genesis mint of design §2 is the real answer.
    """
    from .keys import WalletKeys
    from .notes import note_id, note_vector
    from .wallet import Held, Wallet
    root, net_cfg, doc = sv.load(args.root)
    params = doc.chain_params()
    world, holders = genesis_mod.boot(doc)
    if args.holder not in holders:
        print(f"genesis holders are {sorted(holders)}", file=sys.stderr)
        return 2
    seed_path, notes_path = _wallet_paths(root, args.name)
    phrase = f"genesis:{args.holder}"
    with open(seed_path, "w") as fh:
        fh.write(phrase + "\n")
    os.chmod(seed_path, 0o600)
    wallet = Wallet(WalletKeys.from_phrase(phrase), params,
                    chain_id=doc.chain_id, name=args.name)
    for note in holders[args.holder].notes:
        cm = note_id(note_vector(note, params))
        wallet.held[cm] = Held(note=note, cm=cm, height=0)
    wallet.save(notes_path)
    print(f"imported {len(wallet.held)} genesis note(s) for {args.holder}")
    print(f"  address   {wallet.address.encode()}")
    print(f"  balance   {wallet.balance()}")
    return 0


# ── the light client ─────────────────────────────────────────────────────────

def _light_path(root):
    return os.path.join(os.path.abspath(root), "light.json")


def cmd_light_sync(args):
    """Take one verified step along the spine."""
    from .light import LightClient
    root, net_cfg, doc = sv.load(args.root)
    client, target = _client_for(root, net_cfg, doc, args.node)
    light = LightClient.load(_light_path(root), doc, client)
    was = light.trusted.height
    step = light.follow()
    light.save(_light_path(root))
    print(f"followed {target} to height {step['height']}")
    print(f"  tip       {step['tip'][:26]}…")
    print(f"  checked   {step['attestations']} attestations against "
          f"{step['grids']} verified register(s)")
    if step["ancestry"]:
        print(f"  ancestry  {step['ancestry']} block(s) skipped, one path, "
              f"from height {was}")
    else:
        print("  ancestry  nothing to prove — first sight of this chain")
    return 0


def cmd_light_verify(args):
    """Prove every note a wallet believes it holds."""
    from .light import LightClient
    root, net_cfg, doc = sv.load(args.root)
    params = doc.chain_params()
    wallet, _ = _open_wallet(root, args.name, doc, params)
    client, target = _client_for(root, net_cfg, doc, args.node)
    light = LightClient.load(_light_path(root), doc, client)
    light.follow()
    light.save(_light_path(root))
    proved, unproved, checks = light.verified_balance(wallet)
    print(f"{args.name} against {target}, at height {light.trusted.height}")
    for c in checks:
        mark = "proved  " if c.proved else "UNPROVED"
        print(f"  {mark} {c.value:>8}  {c.cm[:22]}…  {c.reason}")
    print(f"  proved   {proved}")
    if unproved:
        print(f"  unproved {unproved}  — this client will not count these")
    return 0 if not unproved else 1


def cmd_light_adjudicate(args):
    """Ask every node, check the work, and say what the work says."""
    from .light import Adjudicator
    root, net_cfg, doc = sv.load(args.root)
    adj = Adjudicator(doc)
    sources = {nid: _client(spec, doc)
               for nid, spec in sorted(net_cfg["nodes"].items())}
    verdict = adj.weigh(sources)
    print(verdict["decision"])
    for b in verdict["branches"]:
        mark = "ok      " if b.ok else "REFUSED "
        print(f"  {mark} {b.source:<12} h={b.height:<4} "
              f"weight={b.cumulative:>12,}  {b.stamps} stamps"
              + ("" if b.ok else f"  — {b.reason}"))
    depth = adj.settled_depth(args.share)
    print(f"  a holder of {args.share:.0%} of the pool could rewrite at most "
          f"{depth} block(s)")
    if not verdict["agree"] and verdict.get("winner"):
        print(f"  heaviest  {verdict['winner'][:26]}… by "
              f"{verdict['margin']:,}")
    return 0 if verdict["agree"] else 1


def _client(spec, doc):
    from .net.client import Client
    host, port = spec["listen"]
    return Client(host, port, doc.chain_id)


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

    w = sub.add_parser("wallet").add_subparsers(dest="cmd", required=True)
    wn = w.add_parser("new", help="create a wallet")
    wn.add_argument("root"); wn.add_argument("--name", required=True)
    wn.add_argument("--phrase", default=None)
    wn.add_argument("--force", action="store_true")
    wn.set_defaults(fn=cmd_wallet_new)
    wa = w.add_parser("address"); wa.add_argument("root")
    wa.add_argument("--name", required=True); wa.set_defaults(fn=cmd_wallet_address)
    ws = w.add_parser("sync", help="scan the chain for money")
    ws.add_argument("root"); ws.add_argument("--name", required=True)
    ws.add_argument("--node", default=None)
    ws.add_argument("--tags", type=int, default=None, metavar="BITS",
                    help="let the node sort the chain, at this precision")
    ws.set_defaults(fn=cmd_wallet_sync)
    wb = w.add_parser("balance"); wb.add_argument("root")
    wb.add_argument("--name", required=True); wb.set_defaults(fn=cmd_wallet_balance)
    wsd = w.add_parser("send"); wsd.add_argument("root")
    wsd.add_argument("--name", required=True)
    wsd.add_argument("--to", required=True)
    wsd.add_argument("--amount", type=int, required=True)
    wsd.add_argument("--fee", type=int, default=1)
    wsd.add_argument("--node", default=None); wsd.set_defaults(fn=cmd_wallet_send)
    wi = w.add_parser("import-genesis", help="reconstruct a genesis holder")
    wi.add_argument("root"); wi.add_argument("--holder", default="treasury")
    wi.add_argument("--name", default="treasury")
    wi.set_defaults(fn=cmd_wallet_import_genesis)

    li = sub.add_parser("light").add_subparsers(dest="cmd", required=True)
    lsy = li.add_parser("sync", help="follow the spine, verified")
    lsy.add_argument("root"); lsy.add_argument("--node", default=None)
    lsy.set_defaults(fn=cmd_light_sync)
    la = li.add_parser("adjudicate", help="weigh the nodes' branches")
    la.add_argument("root")
    la.add_argument("--share", type=float, default=1 / 3,
                    help="attacker's share of the turn pool")
    la.set_defaults(fn=cmd_light_adjudicate)
    lv = li.add_parser("verify", help="prove every note a wallet holds")
    lv.add_argument("root"); lv.add_argument("--name", required=True)
    lv.add_argument("--node", default=None); lv.set_defaults(fn=cmd_light_verify)

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
