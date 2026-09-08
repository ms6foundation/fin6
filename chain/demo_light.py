"""Prove it, do not believe it.

    python3 -m chain.demo_light

The wallet demo ends with a number a node told us.  This one ends with the same
number, arrived at differently: every note behind it has been proved live
against a root that came out of a header this client checked the signatures on
itself.  Then the client goes away for several blocks and comes back on a
single path, which is the property that makes an intermittent wallet possible.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time

from .genesis import boot, load as load_genesis
from .keys import WalletKeys
from .light import Adjudicator, LightClient, LightError
from .net import supervisor as sv
from .net.client import Client, ClientError
from .notes import note_id, note_vector
from .seal import leaf_value
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


def main(root=None, nodes=4, base_port=7650):
    owned = root is None
    root = root or tempfile.mkdtemp(prefix="fin6-light-demo-")
    try:
        info = sv.new_testnet(root, nodes=nodes, preset="local",
                              epoch_millis=2000, base_port=base_port,
                              force=True)
        doc = load_genesis(os.path.join(root, "genesis.json"))
        params = doc.chain_params()
        client = Client("127.0.0.1", base_port, doc.chain_id)
        net = sv.Testnet(root).up(start_in_ms=2500)
        say(f"── {nodes} nodes up, quorum {info['quorum']}")
        try:
            net.wait_for_height(1, timeout=90)

            _, holders = boot(doc)
            treasury = Wallet(WalletKeys.from_phrase("genesis:treasury"),
                              params, chain_id=doc.chain_id, name="treasury")
            for note in holders["treasury"].notes:
                cm = note_id(note_vector(note, params))
                treasury.held[cm] = Held(note=note, cm=cm, height=0)
            bob = Wallet(WalletKeys.generate(), params, chain_id=doc.chain_id,
                         name="bob")
            tx, _ = treasury.send(bob.address, 250, fee=5)
            client.submit(tx)
            say(f"── paid bob 250 at height {confirmed(client, tx.txid)}")
            say(f"── bob's wallet says {client.sync(bob)['balance']} — "
                f"because a node said so")

            light = LightClient(doc, client)
            step = light.follow()
            say(f"── followed to height {step['height']}: "
                f"{step['attestations']} attestations checked against "
                f"{step['grids']} register(s) recomputed from their records")

            counted = light.scan(bob)
            say(f"── scanned to {counted['height']}: {counted['outputs']} "
                f"outputs and {counted['nullifiers']} nullifiers, exactly what "
                f"the headers say the range holds")

            proved, unproved, checks = light.verified_balance(bob)
            for c in checks:
                proof = client.inclusion(c.cm)["proof"]
                size = 32 * len(proof["siblings"]) + 8
                say(f"── proved {c.value} live: {c.cm[:20]}… "
                    f"({size} B of path, {len(proof['siblings'])} siblings)")
            say(f"── verified balance {proved}"
                + (f", unproved {unproved}" if unproved else ""))

            was = light.trusted.height
            net.wait_for_height(was + 4, timeout=90)
            step = light.follow()
            say(f"── away for {step['ancestry']} blocks, back on one path "
                f"to height {step['height']}")

            # ── and what it refuses ─────────────────────────────────────
            spend, _ = bob.send(treasury.address, 100, fee=2)
            client.submit(spend)
            confirmed(client, spend.txid)
            light.follow()
            say(f"── bob spent that note; his own cache still says "
                f"{bob.balance()} because it has not reconciled")
            stale = light.check_notes(bob)
            say(f"── the light client proves "
                f"{sum(c.value for c in stale if c.proved)} and refuses "
                f"{sum(c.value for c in stale if not c.proved)}: "
                f"{stale[0].reason}")

            client.sync(treasury)
            # ── the node sorts the chain without being able to read it ────
            twin = Wallet(bob.keys, params, chain_id=doc.chain_id, name="twin")
            for bits in (24, 4, 1):
                t = Wallet(bob.keys, params, chain_id=doc.chain_id)
                r = client.scan_by_tag(t, bits=bits, since=0)
                say(f"── tags at {bits:>2} bits: fetched {r['fetched']} of "
                    f"{r['scanned']} outputs, found {r['found']}, "
                    f"balance {t.balance()}")

            # ── the appeal court ──────────────────────────────────────────
            adj = Adjudicator(doc)
            sources = {f"n{i:02d}": Client("127.0.0.1", base_port + i,
                                           doc.chain_id)
                       for i in range(nodes)}
            verdict = adj.weigh(sources)
            say(f"── {verdict['decision']}; "
                f"{sum(1 for b in verdict['branches'] if b.ok)}/"
                f"{len(verdict['branches'])} branches verified from their "
                f"stamps")
            for b in verdict["branches"][:2]:
                say(f"     {b}")
            say(f"── a third of the pool could rewrite at most "
                f"{adj.settled_depth(1 / 3)} blocks")

            answer = client.inclusion(treasury.unspent()[0].cm)
            if answer.get("live"):
                from .seal import verify_witness
                wrong = leaf_value("utxo", "nc:" + "00" * 32)
                say("── a path that opens to somebody else's leaf: "
                    + ("accepted — BUG" if verify_witness(
                        wrong, answer["proof"], light.trusted.witness_root)
                       else "refused"))

        finally:
            net.down()
    finally:
        if owned:
            shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
