"""The witness tree, the spine, and a client that will not take a node's word.

The interesting tests here are the ones where the node is lying. A light client
that verifies a happy path is a light client that has not been tested: every
check in `light.py` exists because some specific lie would otherwise get
through, and each of those lies is written out below.
"""
import dataclasses
import json
import os
import shutil
import tempfile
import time

from ..genesis import boot, load as load_genesis
from ..keys import WalletKeys
from ..light import Adjudicator, LightClient, LightError
from ..net import supervisor as sv
from ..net.client import Client, ClientError
from ..net.frame import CLIENT_KINDS, KINDS
from ..notes import Note, note_id, note_vector
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


def _testnet(port_base, nodes=4):
    root = tempfile.mkdtemp(prefix="fin6-light-net-")
    sv.new_testnet(root, nodes=nodes, preset="local", epoch_millis=2500,
                   base_port=port_base, force=True)
    doc = load_genesis(os.path.join(root, "genesis.json"))
    return root, doc


def _tighten(root, node_id, **limits):
    """Give one node a small budget, so a flood can be pointed at it."""
    path = os.path.join(root, "net.json")
    with open(path) as fh:
        net = json.load(fh)
    net["nodes"][node_id]["limits"] = limits
    with open(path, "w") as fh:
        json.dump(net, fh, indent=2)


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


# ── detection tags ───────────────────────────────────────────────────────────

def test_the_address_carries_a_third_key_and_still_round_trips():
    from ..keys import Address
    keys = WalletKeys.from_phrase("bob")
    text = keys.address.encode()
    assert Address.decode(text) == keys.address
    assert keys.address.detect_hex not in ("", keys.address.view_hex)
    assert keys.detection_secret() != keys.viewing_secret(), \
        "handing over the detection key must not hand over the viewing key"


def test_only_the_recipient_recomputes_the_tag():
    from ..notes import Note, note_id, note_vector, seal_output, tag_from_shared
    import dataclasses as _dc
    from ..params import DEMO
    params = _dc.replace(DEMO)
    bob, carol = WalletKeys.from_phrase("bob"), WalletKeys.from_phrase("carol")
    note = Note.create(250, bob.address.spend_hex, params)
    cm = note_id(note_vector(note, params))
    sealed, tag = seal_output(note, bob.address, cm, params)
    epk = sealed[:32]
    assert tag_from_shared(bob.detect_exchange(epk)) == tag
    assert tag_from_shared(carol.detect_exchange(epk)) != tag


def test_precision_is_the_knob_and_it_behaves_like_one():
    """At p bits a stranger matches about one output in 2^p.

    Measured rather than asserted from theory, because the whole value of the
    tag is this ratio and a construction that quietly got it wrong would still
    look like it worked.
    """
    from ..notes import Note, note_id, note_vector, seal_output
    from ..notes import tag_from_shared, tag_matches
    import dataclasses as _dc
    from ..params import DEMO
    params = _dc.replace(DEMO)
    watcher = WalletKeys.from_phrase("watcher")
    tags, epks = [], []
    for i in range(600):
        who = WalletKeys.from_phrase(f"stranger-{i}")
        note = Note.create(1, who.address.spend_hex, params)
        cm = note_id(note_vector(note, params))
        sealed, tag = seal_output(note, who.address, cm, params)
        tags.append(tag)
        epks.append(sealed[:32])
    for bits, low, high in ((1, 0.35, 0.65), (4, 0.02, 0.12)):
        hits = sum(
            tag_matches(tag, tag_from_shared(watcher.detect_exchange(epk)),
                        bits)
            for tag, epk in zip(tags, epks))
        share = hits / len(tags)
        assert low <= share <= high, (bits, share)


def test_the_tags_are_bound_into_the_transaction():
    """Rewriting a tag is not theft; it is a way to make a payment invisible
    to the person it was for.  So the proof covers it."""
    import dataclasses as _dc
    from ..params import DEMO
    from ..transaction import verify_transaction
    params = _dc.replace(DEMO, proof_backends=("mpcith",),
                         default_backend="mpcith",
                         proof_policy=(("local", "mpcith"),))
    chain = "fin6:" + "ab" * 32
    alice = Wallet(WalletKeys.from_phrase("alice"), params, chain_id=chain)
    note = Note.create(1000, alice.address.spend_hex, params)
    cm = note_id(note_vector(note, params))
    alice.held[cm] = Held(note=note, cm=cm, height=1)
    tx, _ = alice.send(WalletKeys.from_phrase("bob").address, 250, fee=5)
    assert len(tx.output_tags) == len(tx.output_cms)
    assert verify_transaction(tx, params, chain_id=chain)[0]
    swapped = dataclasses.replace(tx,
                                  output_tags=tuple(reversed(tx.output_tags)))
    assert not verify_transaction(swapped, params, chain_id=chain)[0]
    assert not verify_transaction(
        dataclasses.replace(tx, output_tags=()), params, chain_id=chain)[0]


# ── scan completeness ────────────────────────────────────────────────────────

def test_the_header_counts_what_the_chain_has_produced():
    """Two numbers, and they are what make a scan checkable."""
    from ..seal import SealAccumulator
    acc = SealAccumulator("utxo")
    for i in range(10):
        acc.add(f"nc:{i:064x}")
    acc.spend(f"nc:{3:064x}")
    assert acc.size == 10, "size counts everything ever issued"
    assert len(acc) == 9, "length counts what is live"


def test_a_short_answer_is_caught_by_the_count():
    outs = [(1, "cm", b"", i) for i in range(5)]
    from ..light import _spans
    assert _spans(outs, 0, 5, "output")[0]
    ok, why = _spans(outs[:-1], 0, 5, "output")
    assert not ok and "4 outputs" in why, why


def test_a_padded_answer_is_caught_by_contiguity():
    """Without the position check a node could answer a request for five rows
    with five copies of one row and the count would still add up."""
    from ..light import _spans
    padded = [(1, "cm", b"", 0)] * 5
    ok, why = _spans(padded, 0, 5, "output")
    assert not ok and "not contiguous" in why, why
    reordered = [(1, "cm", b"", i) for i in (0, 2, 1, 3, 4)]
    assert not _spans(reordered, 0, 5, "output")[0]


# ── the adjudicating client ──────────────────────────────────────────────────

def _era_and_history(turns=64, width=4, bits=8):
    from ..hardening.params import HardeningParams
    from ..hardening.pool import Era
    params = HardeningParams(name="test", turns=turns, era_seconds=600,
                             width=width, difficulty_bits=bits, tree_height=8)
    era = Era(0, b"\x07" * 32, params.tree_height, params.turns)
    return era, params


class _Blk:
    def __init__(self, tag):
        self._tag = tag

    def hash(self):
        return f"nb:{self._tag}"


def test_the_adjudicator_prefers_the_branch_with_more_work():
    """Two tips, two certificates, and only work can settle it."""
    from ..hardening.history import NetworkHistory
    from ..light import Adjudicator, Branch
    era, params = _era_and_history()
    heavy = NetworkHistory(era.spec, params)
    light_ = NetworkHistory(era.spec, params)
    for i in range(3):
        hb = heavy.harden(_Blk(f"h{i}"), era)
        assert heavy.accept(hb)[0]
    hb = light_.harden(_Blk("l0"), era)
    assert light_.accept(hb)[0]

    adj = Adjudicator.__new__(Adjudicator)
    adj.params, adj.spec, adj.doc = params, era.spec, None
    branches = [
        Branch(source="a", ok=True, tip=heavy.tip_hash, height=heavy.height,
               cumulative=heavy.cumulative_weight),
        Branch(source="b", ok=True, tip=light_.tip_hash, height=light_.height,
               cumulative=light_.cumulative_weight)]
    adj.examine = lambda client, name=None: dict(zip("ab", branches))[name]
    out = adj.weigh({"a": None, "b": None})
    assert not out["agree"]
    assert out["winner"] == heavy.tip_hash
    assert out["winner_source"] == "a"
    assert out["margin"] > 0


def test_the_adjudicator_refuses_a_branch_it_cannot_check():
    """A weight a node reports is not work; the stamps are."""
    import dataclasses as _dc
    from ..hardening.history import NetworkHistory
    from ..light import Adjudicator
    era, params = _era_and_history()
    real = NetworkHistory(era.spec, params)
    hb = real.harden(_Blk("a"), era)
    assert real.accept(hb)[0]

    adj = Adjudicator.__new__(Adjudicator)
    adj.params, adj.spec, adj.doc = params, era.spec, None

    def row(block):
        return {"height": block.height, "block_hash": block.block_hash,
                "prev": block.prev_hash, "era_id": block.era_id,
                "drawn": list(block.drawn), "stamps": list(block.stamps),
                "weight": str(block.weight),
                "cumulative": str(block.cumulative),
                "spent_root": str(block.spent_root)}

    class _Node:
        def __init__(self, rows):
            self.rows, self.host, self.port = rows, "h", 0

        def weight(self, since=1, to=None, limit=None):
            return {"era": {"root": era.spec.root.hex()}, "blocks": self.rows}

    honest = adj.examine(_Node([row(hb)]), name="honest")
    assert honest.ok, honest.reason
    assert honest.cumulative == hb.weight

    inflated = row(_dc.replace(hb, weight=hb.weight * 100,
                               cumulative=hb.cumulative * 100))
    assert not adj.examine(_Node([inflated]), name="liar").ok

    stripped = row(_dc.replace(hb, stamps=()))
    assert not adj.examine(_Node([stripped]), name="empty").ok

    other_era = _Node([row(hb)])
    other_era.weight = lambda **kw: {"era": {"root": "00" * 32}, "blocks": []}
    assert "another era" in adj.examine(other_era, name="stranger").reason


def test_settlement_depth_is_a_bound_not_a_convention():
    from ..light import Adjudicator
    _, params = _era_and_history(turns=64, width=4)
    adj = Adjudicator.__new__(Adjudicator)
    adj.params, adj.spec, adj.doc = params, None, None
    assert adj.settled_depth(1 / 2) == 8, "32 unspent turns, width 4"
    assert adj.settled_depth(1 / 4) == 4
    assert adj.is_settled(9, 1 / 2) and not adj.is_settled(8, 1 / 2)


def test_the_four_answers_on_a_running_network():
    """Metering, tags, a counted scan, and the appeal court — on real sockets.

    One testnet, because each of these is cheap to check and expensive to
    stand up, and because the interesting failures are the ones that only
    appear when a node is doing all four things at once.
    """
    port = 7970 + (os.getpid() % 15) * 10
    root, doc = _testnet(port)
    _tighten(root, "fin6-n03", capacity=25, rate=1)
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

            # ── a scan that can tell it was shown everything ────────────────
            light = LightClient(doc, client)
            light.follow()
            out = light.scan(bob)
            assert out["complete"] and bob.balance() == 250, out
            assert out["outputs"] == out["expected"][0], out
            assert light.verified_balance(bob)[0] == 250

            # ── the node sorts the chain without being able to read it ──────
            twin = Wallet(bob.keys, params, chain_id=doc.chain_id, name="twin")
            sorted_ = client.scan_by_tag(twin, bits=24, since=0)
            assert sorted_["found"] == 1 and twin.balance() == 250, sorted_
            assert sorted_["fetched"] < sorted_["scanned"], \
                "sorting that returns everything has sorted nothing"
            stranger = Wallet(WalletKeys.generate(), params,
                              chain_id=doc.chain_id)
            assert client.scan_by_tag(stranger, bits=24,
                                      since=0)["found"] == 0

            # ── the appeal court, convened on a network that agrees ─────────
            net.wait_for_height(3, timeout=75)
            time.sleep(3)
            adj = Adjudicator(doc)
            sources = {f"n{i:02d}": Client("127.0.0.1", port + i, doc.chain_id)
                       for i in range(4)}
            verdict = adj.weigh(sources)
            assert verdict["agree"], verdict
            checked = [b for b in verdict["branches"] if b.ok]
            assert len(checked) == 4, verdict["branches"]
            assert all(b.stamps >= 1 for b in checked)
            assert adj.settled_depth(1 / 3) > 0

            # ── and the meter ───────────────────────────────────────────────
            # n03 was started on a deliberately tiny budget, because the
            # default is calibrated so that an ordinary wallet never meets it
            # — a meter a real client trips over is a broken meter.
            tight = Client("127.0.0.1", port + 2, doc.chain_id)
            refused, served = 0, 0
            for _ in range(30):
                try:
                    tight.outputs(since=0)
                    served += 1
                except ClientError:
                    refused += 1
            assert served > 0, "the meter is not a wall"
            assert refused > 0, "a client that never stops asking is never told no"
            assert client.outputs(since=0)["tip"] >= 1, \
                "and it is per source: the other nodes are unaffected"
            time.sleep(3)
            assert tight.status()["height"] >= 1, "and the budget comes back"
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)
