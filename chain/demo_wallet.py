"""Pay a stranger.

    python3 -m chain.demo_wallet

Seven node processes, real sockets, and a wallet that has been told nothing but
its own seed.  It is paid, finds the money by trial-decrypting outputs it has
no other reason to look at, and spends it onward.  Every other demo in this
repository drives the chain from inside one process; this one is a user.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time

from .genesis import boot, load as load_genesis
from .keys import WalletKeys
from .net import supervisor as sv
from .net.client import Client, ClientError
from .notes import note_id, note_vector
from .wallet import Held, Wallet


def say(*a):
    print(*a, flush=True)


def confirmed(client, txid, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        try:
            answer = client.txstatus(txid)
        except ClientError:
            time.sleep(0.5)
            continue
        if answer.get("height") is not None:
            return answer["height"]
        time.sleep(0.5)
    raise SystemExit(f"{txid[:16]}… never confirmed")


def main(root=None, nodes=7, base_port=7600):
    owned = root is None
    root = root or tempfile.mkdtemp(prefix="fin6-wallet-demo-")
    try:
        info = sv.new_testnet(root, nodes=nodes, preset="local",
                              epoch_millis=2000, base_port=base_port,
                              force=True)
        doc = load_genesis(os.path.join(root, "genesis.json"))
        params = doc.chain_params()
        client = Client("127.0.0.1", base_port, doc.chain_id)
        net = sv.Testnet(root).up(start_in_ms=2500)
        say(f"── {nodes} nodes up, quorum {info['quorum']}, "
            f"{info['chain_id'][:22]}…")
        try:
            net.wait_for_height(1, timeout=90)

            # The treasury is derivable from the genesis document: its notes
            # are issued outside any transaction and carry no sealed opening,
            # which is exactly why `import-genesis` exists.
            _, holders = boot(doc)
            treasury = Wallet(WalletKeys.from_phrase("genesis:treasury"),
                              params, chain_id=doc.chain_id, name="treasury")
            for note in holders["treasury"].notes:
                cm = note_id(note_vector(note, params))
                treasury.held[cm] = Held(note=note, cm=cm, height=0)
            say(f"── treasury  {treasury.address.short()}  "
                f"{treasury.balance()} in {len(treasury.held)} notes")

            bob = Wallet(WalletKeys.generate(), params, chain_id=doc.chain_id,
                         name="bob")
            say(f"── bob       {bob.address.short()}  "
                f"{bob.balance()} — a seed and nothing else")

            t0 = time.time()
            tx, _ = treasury.send(bob.address, 250, fee=5)
            say(f"── built {tx.txid[:18]}…  250 to bob, fee 5, "
                f"{sum(len(c) for c in tx.output_notes)} B of sealed openings "
                f"({time.time() - t0:.2f}s)")
            client.submit(tx)
            say(f"── confirmed at height {confirmed(client, tx.txid)}")

            found = client.sync(bob)
            say(f"── bob scanned to {found['height']}: found "
                f"{found['found']} note, balance {found['balance']}")
            say(f"── treasury reconciled to "
                f"{client.sync(treasury)['balance']}")

            carol = Wallet(WalletKeys.generate(), params,
                           chain_id=doc.chain_id, name="carol")
            second, _ = bob.send(carol.address, 100, fee=2)
            client.submit(second)
            say(f"── bob's payment confirmed at height "
                f"{confirmed(client, second.txid)}")
            say(f"── carol     {carol.address.short()}  "
                f"{client.sync(carol)['balance']}")
            say(f"── bob now {client.sync(bob)['balance']}  "
                f"(250 − 100 − 2, as change)")

            ok, height, detail = net.agreement(net.status())
            say(f"── {detail}")
        finally:
            net.down()
    finally:
        if owned:
            shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
