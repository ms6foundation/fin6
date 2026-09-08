"""What a node will do for a stranger, and how often.

Part eight left one number sitting on its own: a submission costs about 26 ms
of proof verification and nothing meters it. Two answers here, tested
separately because they defend different things — a cheaper `no` for rubbish,
and a budget for everything else, including the transactions that are perfectly
valid and still arriving faster than a node can want them.
"""
import dataclasses
import time

from chain.crypto import Signer
from wallet.keys import WalletKeys
from chain.net.limits import Bucket, COSTS, Limiter
from chain.node import MAX_INPUTS, MAX_OUTPUTS, Node
from chain.notes import Note, note_id, note_vector
from chain.params import DEMO
from chain.state import ChainState
from wallet.store import Held, Wallet

PARAMS = dataclasses.replace(DEMO, proof_backends=("mpcith",),
                             default_backend="mpcith",
                             proof_policy=(("local", "mpcith"),))
CHAIN = "fin6:" + "ab" * 32


# ── the bucket ───────────────────────────────────────────────────────────────

def test_a_burst_is_allowed_and_then_it_is_not():
    bucket = Bucket(100, 10, now=0.0)
    assert [bucket.take(25, now=0.0)[0] for _ in range(4)] == [True] * 4
    ok, wait = bucket.take(25, now=0.0)
    assert not ok and abs(wait - 2.5) < 1e-9, wait


def test_the_budget_refills_at_its_rate_and_no_further():
    bucket = Bucket(100, 10, now=0.0)
    bucket.take(100, now=0.0)
    assert not bucket.take(50, now=1.0)[0], "10 tokens back after a second"
    assert bucket.take(50, now=5.0)[0]
    bucket.take(50, now=5.0)
    assert bucket.take(100, now=1_000.0)[0], "and it caps at capacity"
    assert not bucket.take(1, now=1_000.0)[0]


def test_a_peer_gets_a_larger_budget_than_a_stranger():
    lim = Limiter()
    t = 100.0
    stranger = sum(lim.check(("1.1.1.1", 1), "tx", now=t)[0] for _ in range(50))
    peer = sum(lim.check(("2.2.2.2", 1), "tx", peer=True, now=t)[0]
               for _ in range(50))
    assert stranger < peer, (stranger, peer)
    assert stranger == 240 // COSTS["tx"], stranger


def test_a_peer_and_a_client_from_one_address_do_not_share_a_budget():
    """Found on a testnet, where everything arrives from 127.0.0.1.

    Keyed on the address alone, a validator's promotion handed its budget to
    every wallet dialling from the same host — and on a laptop that is all of
    them.  A peer is metered under the name it claims; everybody else under
    the address they came from.
    """
    lim = Limiter()
    for _ in range(200):
        lim.check(("peer", "fin6-n02"), "env", peer=True, now=0.0)
    spent = sum(not lim.check(("client", "127.0.0.1"), "tx", now=0.0)[0]
                for _ in range(10))
    assert spent > 0, "the client bucket was never touched by the peer's"


def test_a_source_that_turns_out_to_be_a_peer_is_promoted():
    """A connection says `hello` after its first frame, not before.

    Promotion raises the rate; it does not hand back a full bucket. Refilling
    on promotion would let anyone who reconnects and claims a roster id reset
    their budget at will, and `hello` is a claim rather than a credential.
    """
    lim = Limiter()
    for _ in range(20):
        lim.check(("3.3.3.3", 1), "tx", now=0.0)
    assert not lim.check(("3.3.3.3", 1), "tx", peer=True, now=0.0)[0], \
        "promotion is not a refill"
    assert lim.check(("3.3.3.3", 1), "tx", peer=True, now=0.1)[0], \
        "but it refills at a peer's rate from then on"


def test_cost_follows_what_the_request_makes_the_node_do():
    assert COSTS["tx"] > COSTS["getoutputs"] > COSTS["inclusion"] > COSTS["status"]


def test_quiet_sources_are_forgotten():
    lim = Limiter(idle_after=10.0)
    lim.check(("4.4.4.4", 1), "status", now=0.0)
    assert lim.stats()["sources"] == 1
    lim.check(("5.5.5.5", 1), "status", now=100.0)
    assert lim.stats()["sources"] == 1, "the idle one was swept"


# ── the cheaper no ───────────────────────────────────────────────────────────

def _node_and_tx():
    state = ChainState(PARAMS, chain_id=CHAIN)
    alice = Wallet(WalletKeys.from_phrase("alice"), PARAMS, chain_id=CHAIN)
    note = Note.create(1000, alice.address.spend_hex, PARAMS)
    cm = note_id(note_vector(note, PARAMS))
    state.issue(cm)
    alice.held[cm] = Held(note=note, cm=cm, height=0)
    node = Node("v0", Signer.from_seed("v0"), PARAMS, state)
    bob = WalletKeys.from_phrase("bob")
    tx, _ = alice.send(bob.address, 250, fee=5)
    return node, tx, alice


def test_a_good_transaction_still_gets_in():
    node, tx, _ = _node_and_tx()
    ok, why = node.submit(tx)
    assert ok, why
    assert node.admitted == 1 and node.refused == 0


def test_rubbish_is_refused_without_touching_the_proof():
    """The point of the whole exercise: a transaction spending nothing real is
    refused by set lookup, three orders of magnitude cheaper than by proof."""
    node, tx, _ = _node_and_tx()
    orphan = dataclasses.replace(tx, output_cms=tx.output_cms)
    node.state.utxo.spend(tx.input_cms[0])          # the input is gone
    t = time.perf_counter()
    ok, why = node.admissible(orphan)
    cheap = time.perf_counter() - t
    assert not ok and "unspent note" in why, why
    t = time.perf_counter()
    node.submit(orphan)
    whole = time.perf_counter() - t
    assert cheap < 0.002, f"the cheap check took {cheap * 1000:.1f} ms"
    assert whole < 0.05, "and submit did not fall through to the proof"


def test_the_shape_of_a_transaction_is_bounded_before_anything_is_read():
    node, tx, _ = _node_and_tx()
    huge = dataclasses.replace(tx, output_cms=tx.output_cms * (MAX_OUTPUTS + 1))
    ok, why = node.admissible(huge)
    assert not ok and "outside the shape" in why, why
    empty = dataclasses.replace(tx, inputs=())
    assert not node.admissible(empty)[0]


def test_a_transaction_for_another_chain_never_reaches_the_prover():
    node, tx, _ = _node_and_tx()
    stray = dataclasses.replace(tx, chain_id="fin6:" + "cd" * 32)
    ok, why = node.admissible(stray)
    assert not ok and "for chain" in why, why


def test_a_bad_proof_is_still_refused_and_counted():
    node, tx, _ = _node_and_tx()
    forged = dataclasses.replace(tx, v=tuple([1] * len(tx.v)))
    ok, _ = node.submit(forged)
    assert not ok
    assert node.bad_proofs == 1, "the expensive path still runs when it must"
