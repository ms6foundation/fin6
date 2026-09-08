"""The witness tree, the spine, and a client that will not take a node's word.

The interesting tests here are the ones where the node is lying. A light client
that verifies a happy path is a light client that has not been tested: every
check in `light.py` exists because some specific lie would otherwise get
through, and each of those lies is written out below.
"""
import dataclasses
import os
import shutil
import tempfile
import time

from ..genesis import boot, load as load_genesis
from ..keys import WalletKeys
from ..light import LightClient, LightError
from ..net import supervisor as sv
from ..net.client import Client, ClientError
from ..net.frame import CLIENT_KINDS, KINDS
from ..notes import note_id, note_vector
from ..seal import (HeaderHistory, SealAccumulator, WitnessTree, leaf_value,
                    verify_ancestry, verify_witness)
from ..wallet import Held, Wallet


# ── the witness tree ─────────────────────────────────────────────────────────

def test_a_leaf_opens_to_the_root_and_a_wrong_one_does_not():
    tree = WitnessTree("utxo")
    for i in range(50):
        tree.append(f"utxo:cm{i}")
    proof = tree.path(7)
    assert verify_witness("utxo:cm7", proof, tree.root)
    assert not verify_witness("utxo:cm8", proof, tree.root)
    assert not verify_witness("utxo:cm7", proof, WitnessTree("utxo").root)


def test_a_proof_is_about_half_a_kilobyte():
    """The number the whole second tree exists for: the seal tree's own proof
    of the same leaf is 80 KiB at this size."""
    tree = WitnessTree("utxo")
    for i in range(50_000):
        tree.append(f"utxo:cm{i}")
    size = tree.size_bytes(31_337)
    assert 400 < size < 700, size
    assert len(tree.path(31_337)["siblings"]) == 16, "one per occupied level"


def test_an_update_moves_the_root_and_kills_the_old_proof():
    tree = WitnessTree("utxo")
    for i in range(20):
        tree.append(f"utxo:cm{i}")
    before, proof = tree.root, tree.path(5)
    tree.set(5, "utxo:fin6:spent:cm5")
    assert tree.root != before
    assert not verify_witness("utxo:cm5", proof, tree.root)
    assert verify_witness("utxo:fin6:spent:cm5", tree.path(5), tree.root)


def test_a_forged_proof_is_refused_rather_than_parsed():
    tree = WitnessTree("utxo")
    for i in range(20):
        tree.append(f"utxo:cm{i}")
    good = tree.path(3)
    for bad in ({}, {"pos": 3}, dict(good, present=0),
                dict(good, siblings=[]), dict(good, pos=4),
                dict(good, height=-1), dict(good, siblings=["zz"])):
        assert not verify_witness("utxo:cm3", bad, tree.root), bad


# ── the accumulator ──────────────────────────────────────────────────────────

def test_the_two_trees_hold_the_same_leaves():
    acc = SealAccumulator("utxo")
    for i in range(40):
        acc.add(f"nc:{i:064x}")
    cm = f"nc:{9:064x}"
    assert verify_witness(leaf_value("utxo", cm), acc.witness_path(cm),
                          acc.witness_root)
    rebuilt = SealAccumulator.load("utxo", acc.items, acc.dead)
    assert rebuilt.witness_root == acc.witness_root
    assert rebuilt.root == acc.root, "and the seal root, from the same dump"


def test_a_spent_note_has_no_proof_that_it_is_live():
    """§3 of the design: unspent is a positive statement, and this is it."""
    acc = SealAccumulator("utxo")
    for i in range(40):
        acc.add(f"nc:{i:064x}")
    cm = f"nc:{9:064x}"
    before = acc.witness_path(cm)
    acc.spend(cm)
    assert acc.witness_path(cm) is None
    assert not verify_witness(leaf_value("utxo", cm), before, acc.witness_root)
    assert f"nc:{8:064x}" in acc, "and its neighbours are untouched"


def test_a_clone_copies_the_witness_tree_rather_than_rebuilding_it():
    acc = SealAccumulator("utxo")
    for i in range(200):
        acc.add(f"nc:{i:064x}")
    twin = acc.clone()
    assert twin.witness_root == acc.witness_root
    twin.add("nc:" + "ff" * 32)
    assert twin.witness_root != acc.witness_root, "and they share nothing"


# ── the spine ────────────────────────────────────────────────────────────────

def test_ancestry_is_one_path_however_long_the_gap():
    spine = HeaderHistory(f"nb:{i:064x}" for i in range(1, 4001))
    proof = spine.proof(1)
    assert verify_ancestry(f"nb:{1:064x}", proof, spine.root)
    assert 32 * len(proof["siblings"]) + 8 < 500, "4,000 blocks, one path"


def test_a_prefix_root_is_the_root_that_prefix_had():
    spine, roots = HeaderHistory(), {}
    for i in range(1, 60):
        roots[i - 1] = spine.root
        spine.append(f"nb:{i:064x}")
    assert all(spine.root_at(k) == r for k, r in roots.items())
    for cut in (1, 2, 17, 32, 33, 59):
        for target in (1, cut):
            proof = spine.proof(target, under=cut)
            assert verify_ancestry(proof["block_hash"], proof,
                                   spine.root_at(cut)), (target, cut)


def test_a_proof_under_one_root_does_not_verify_under_another():
    spine = HeaderHistory(f"nb:{i:064x}" for i in range(1, 60))
    proof = spine.proof(3, under=10)
    assert not verify_ancestry(proof["block_hash"], proof, spine.root_at(11))
    assert not verify_ancestry(f"nb:{4:064x}", proof, spine.root_at(10))


def test_a_rolled_back_block_leaves_the_spine():
    spine = HeaderHistory(f"nb:{i:064x}" for i in range(1, 21))
    at_ten = spine.root_at(10)
    spine.truncate_to(10)
    assert len(spine) == 10 and spine.root == at_ten
    assert spine.hash_at(11) is None


# ── the wire ─────────────────────────────────────────────────────────────────

def test_every_client_kind_is_a_kind():
    assert CLIENT_KINDS <= set(KINDS)
    for name in ("params", "tip", "headers", "ancestry", "inclusion",
                 "register"):
        assert name in CLIENT_KINDS, name
    for never in ("env", "getblock", "hello"):
        assert never not in CLIENT_KINDS, f"{never} is a peer's message"


# ── a client that does not take the node's word ──────────────────────────────

class _Liar:
    """A node that answers truthfully until told which answer to spoil."""

    def __init__(self, real):
        self.real = real
        self.spoil = None

    def __getattr__(self, name):
        def call(*a, **kw):
            answer = getattr(self.real, name)(*a, **kw)
            if self.spoil and self.spoil[0] == name:
                return self.spoil[1](answer)
            return answer
        return call


def _testnet(port_base):
    root = tempfile.mkdtemp(prefix="fin6-light-net-")
    sv.new_testnet(root, nodes=4, preset="local", epoch_millis=2500,
                   base_port=port_base, force=True)
    doc = load_genesis(os.path.join(root, "genesis.json"))
    return root, doc


def _treasury(doc):
    params = doc.chain_params()
    _, holders = boot(doc)
    wallet = Wallet(WalletKeys.from_phrase("genesis:treasury"), params,
                    chain_id=doc.chain_id, name="treasury")
    for note in holders["treasury"].notes:
        cm = note_id(note_vector(note, params))
        wallet.held[cm] = Held(note=note, cm=cm, height=0)
    return wallet


def _confirmed(client, txid, timeout=75):
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
    raise AssertionError(f"{txid[:16]}… never confirmed")


def test_a_light_client_proves_a_balance_on_a_running_network():
    """The whole part, on four processes and real sockets.

    Follow the tip, check the certificate against a register recomputed from
    its own records, prove one note live under the trusted root, then jump
    several blocks on a single ancestry path — and refuse each of four lies.
    """
    root, doc = _testnet(7940 + (os.getpid() % 20) * 10)
    port = 7940 + (os.getpid() % 20) * 10
    params = doc.chain_params()
    client = Client("127.0.0.1", port, doc.chain_id)
    net = sv.Testnet(root)
    try:
        net.up(start_in_ms=4000)
        try:
            net.wait_for_height(1, timeout=75)
            treasury = _treasury(doc)
            bob = Wallet(WalletKeys.generate(), params, chain_id=doc.chain_id,
                         name="bob")
            tx, _ = treasury.send(bob.address, 250, fee=5)
            client.submit(tx)
            _confirmed(client, tx.txid)
            assert client.sync(bob)["balance"] == 250

            light = LightClient(doc, client)
            step = light.follow()
            assert step["attestations"] >= 3, step
            assert step["ancestry"] == 0, "nothing to prove on first sight"

            proved, unproved, checks = light.verified_balance(bob)
            assert (proved, unproved) == (250, 0), (proved, unproved, checks)
            assert all(c.proved for c in checks)

            # ── and the same client, several blocks later, on one path ──────
            was = light.trusted.height
            net.wait_for_height(was + 2, timeout=75)
            step = light.follow()
            assert step["ancestry"] >= 2, step
            assert light.trusted.height > was

            # ── four lies ──────────────────────────────────────────────────
            liar = _Liar(client)
            forged = LightClient(doc, liar)

            liar.spoil = ("tip", lambda a: dict(a, cert=None))
            _refuses(forged, "no certificate")

            liar.spoil = ("tip", lambda a: dict(
                a, header=dataclasses.replace(a["header"], utxo_root=1)))
            _refuses(forged, "another block")

            liar.spoil = ("register", lambda a: dict(
                a, roots={g: "1" for g in a["roots"]}))
            _refuses(forged, "recompute")

            liar.spoil = None
            forged.follow()
            liar.spoil = ("ancestry", lambda a: {"proof": None,
                                                 "tip": a.get("tip")})
            forged.trusted.height = max(1, forged.trusted.height - 1)
            _refuses(forged, "ancestry proof")

            # ── and a note the node claims is live but cannot prove ─────────
            liar.spoil = None
            honest = LightClient(doc, liar)
            honest.follow()
            liar.spoil = ("inclusion", lambda a: dict(
                a, leaf=leaf_value("utxo", "nc:" + "00" * 32)))
            checks = honest.check_notes(bob)
            assert checks and not any(c.proved for c in checks)
            assert "not this note" in checks[0].reason, checks[0].reason
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _refuses(light, fragment):
    try:
        light.follow()
    except LightError as exc:
        assert fragment in str(exc), f"expected {fragment!r}, got {exc}"
        return
    raise AssertionError(f"accepted a tip it should have refused ({fragment})")
