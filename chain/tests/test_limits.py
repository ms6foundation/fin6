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
from chain.net.limits import (BYTES_PER_TOKEN, Bucket, COSTS, Limiter,
                              bytes_cost)
from chain.node import (MAX_INPUTS, MAX_MEMPOOL, MAX_OUTPUTS,
                        MAX_REFUSED_PROOFS, PROOF_STRIKES, Node)
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


def test_a_mangled_body_is_refused_before_the_proof_and_counted_as_such():
    """Part nine split the check in two, so the counters now say which half
    refused.  A transaction whose `v` does not reproduce its own declared
    commitments is caught by authentication at 0.12 ms; nothing reaches the
    prover, and `bad_proofs` — which means "25 ms was spent" — stays at zero."""
    node, tx, _ = _node_and_tx()
    forged = dataclasses.replace(tx, v=tuple([1] * len(tx.v)))
    t = time.perf_counter()
    ok, why = node.submit(forged)
    spent = time.perf_counter() - t
    assert not ok
    assert node.unauthenticated == 1 and node.bad_proofs == 0, why
    assert spent < 0.005, f"authentication took {spent * 1000:.1f} ms"


def test_a_bad_proof_is_still_refused_and_counted():
    """And the expensive path still runs when it must: a body that
    authenticates carrying a proof that does not verify is the one case where
    the 25 ms is unavoidable."""
    node, tx, alice = _node_and_tx()
    other = Note.create(400, alice.address.spend_hex, PARAMS)
    other_cm = note_id(note_vector(other, PARAMS))
    node.state.issue(other_cm)
    alice.held[other_cm] = Held(note=other, cm=other_cm, height=0)
    donor, _ = alice.send(WalletKeys.from_phrase("carol").address, 100, fee=3)
    spliced = dataclasses.replace(tx, proofs=donor.proofs)
    ok, why = node.submit(spliced)
    assert not ok and "proof" in why, why
    assert node.bad_proofs == 1, "the expensive path still runs when it must"


# ── the two halves, and the cache between them ───────────────────────────────

def _donor_proofs(alice, node, n=1, start=400):
    """n transactions from `alice`, for their proofs alone.

    Splicing another transaction's proof onto this body is the cheapest way to
    make a submission that authenticates and then fails, which is exactly the
    shape part nine is about: steps 1-4 never look at the proof bytes.
    """
    out = []
    for i in range(n):
        note = Note.create(start + i, alice.address.spend_hex, PARAMS)
        cm = note_id(note_vector(note, PARAMS))
        node.state.issue(cm)
        alice.held[cm] = Held(note=note, cm=cm, height=0)
        donor, _ = alice.send(WalletKeys.from_phrase(f"donor{i}").address,
                              100 + i, fee=3)
        out.append(donor.proofs)
    return out


def test_authentication_costs_a_fraction_of_the_proof():
    """The seam part nine is built on.  Both halves run on every honest
    submission; only one of them is worth metering."""
    node, tx, _ = _node_and_tx()
    t = time.perf_counter()
    ok, why, auth = node.authenticate(tx)
    cheap = time.perf_counter() - t
    assert ok, why
    t = time.perf_counter()
    ok, why = node.verify_and_admit(tx, auth)
    dear = time.perf_counter() - t
    assert ok, why
    assert cheap < 0.005, f"authentication took {cheap * 1000:.2f} ms"
    assert dear > cheap * 5, (f"{dear * 1000:.1f} ms proof vs "
                              f"{cheap * 1000:.2f} ms authentication")


def test_a_replayed_bad_proof_is_refused_from_the_cache():
    node, tx, alice = _node_and_tx()
    spliced = dataclasses.replace(tx, proofs=_donor_proofs(alice, node)[0])

    t = time.perf_counter()
    assert not node.submit(spliced)[0]
    first = time.perf_counter() - t
    assert node.bad_proofs == 1, "the first one has to be checked"

    t = time.perf_counter()
    ok, why = node.submit(spliced)
    again = time.perf_counter() - t
    assert not ok and "already been refused" in why, why
    assert node.bad_proofs == 1, "and the second one does not"
    assert node.stale_proofs == 1
    assert again < first / 3, (f"replay cost {again * 1000:.1f} ms against "
                               f"{first * 1000:.1f} ms")


def test_splicing_bad_proofs_onto_a_body_cannot_censor_it():
    """The reason `PROOF_STRIKES` demotes rather than refuses.

    An attacker watches a transaction go past in gossip, splices bad proofs
    onto its body, and submits them.  If strikes were a refusal threshold the
    real transaction would then be refused by every node it reached, having
    done nothing wrong — a censorship primitive built out of a DoS defence.
    """
    node, tx, alice = _node_and_tx()
    for proofs in _donor_proofs(alice, node, n=PROOF_STRIKES + 1):
        assert not node.submit(dataclasses.replace(tx, proofs=proofs))[0]

    assert node.strikes_against(tx) > PROOF_STRIKES
    assert node.suspect(tx), "the body is suspect, which is a priority signal"

    ok, why = node.submit(tx)
    assert ok, f"the honest transaction was censored: {why}"
    assert tx.txid in node.mempool


def test_the_negative_cache_does_not_grow_without_bound():
    node, tx, _ = _node_and_tx()
    for i in range(MAX_REFUSED_PROOFS + 50):
        node._refused_proofs[f"f{i}"] = True
        node._strikes[f"t{i}"] = 1
        if len(node._refused_proofs) > MAX_REFUSED_PROOFS:
            node._refused_proofs.clear()
    assert len(node._refused_proofs) <= MAX_REFUSED_PROOFS

    node2, tx2, alice2 = _node_and_tx()
    for proofs in _donor_proofs(alice2, node2, n=2):
        node2.submit(dataclasses.replace(tx2, proofs=proofs))
    assert 0 < len(node2._refused_proofs) <= MAX_REFUSED_PROOFS
    assert 0 < len(node2._strikes) <= MAX_REFUSED_PROOFS


# ── paying for bytes before they are decoded ─────────────────────────────────

def test_bytes_are_priced_in_proportion_and_not_quantised():
    """Rounding up taxed the small frequent frames this was never aimed at: a
    light client's `status` went from 1 token to 3."""
    assert bytes_cost(0) == 0
    assert bytes_cost(BYTES_PER_TOKEN) == 1
    assert bytes_cost(2 * BYTES_PER_TOKEN) == 2
    assert bytes_cost(60) < 0.01, "a request frame is not a surcharge"
    assert bytes_cost(8 << 20) == (8 << 20) / BYTES_PER_TOKEN


def test_a_small_request_still_costs_what_its_kind_costs():
    lim = Limiter()
    lim.check(("client", "a"), "status", nbytes=60)
    used = 240 - lim._buckets[("client", "a")].tokens
    assert abs(used - COSTS["status"]) < 0.05, used


def test_a_frame_costs_its_bytes_as_well_as_its_kind():
    """Two charges, not one: the bytes pay for the decode and the kind pays
    for the work."""
    lim = Limiter()
    small = Bucket(1e9, 0)
    assert lim.cost_of("tx") == COSTS["tx"]
    ok, why = lim.check(("client", "a"), "tx", nbytes=600 * 1024)
    assert ok, why
    # 600 KB is 75 tokens, plus 50 for the kind, out of a 240 burst.
    used = 240 - lim._buckets[("client", "a")].tokens
    assert abs(used - (75 + COSTS["tx"])) < 0.5, used


def test_the_client_ceiling_is_one_a_client_can_actually_afford():
    """A per-frame ceiling nobody can pay for is a decoy, and the real limit
    becomes whatever the bucket happens to allow."""
    from chain.net.frame import CLIENT_MAX_FRAME
    from chain.net.limits import CLIENT_CAPACITY
    assert bytes_cost(CLIENT_MAX_FRAME) + COSTS["frame"] <= CLIENT_CAPACITY


def test_the_peer_ceiling_is_one_a_peer_can_actually_afford():
    from chain.net.frame import MAX_FRAME
    from chain.net.limits import PEER_CAPACITY
    assert bytes_cost(MAX_FRAME) + COSTS["frame"] <= PEER_CAPACITY


def test_a_megabyte_a_second_is_priced_out_of_a_clients_budget():
    """The number part nine §3 put on this: the same address used to be able
    to take 1.43 CPU-seconds per wall second in decode alone, inside its rate
    limit, because the meter ran after the decode."""
    from chain.net.frame import CLIENT_MAX_FRAME
    from chain.net.limits import CLIENT_RATE
    per_frame = bytes_cost(CLIENT_MAX_FRAME) + COSTS["frame"]
    frames_per_second = CLIENT_RATE / per_frame
    #: 45 ms of decode per megabyte, measured.
    decode_ms = 45 * (CLIENT_MAX_FRAME / (1 << 20))
    share = frames_per_second * decode_ms / 1000
    assert share < 0.02, f"a client can still take {share * 100:.0f}% of a core"


# ── the pool a flood of *valid* transactions fills ───────────────────────────

class _Held:
    """A transaction-shaped stand-in: the pool only reads a fee and an id."""

    def __init__(self, txid, fee):
        self.txid = txid
        self.fee = fee
        self.nullifiers = (f"nf:{txid}",)
        self.input_cms = (f"cm:{txid}",)


def _fill(node, fees):
    for i, fee in enumerate(fees):
        node.mempool[f"tx:{i}"] = _Held(f"tx:{i}", fee)
    return node


def test_the_pool_has_a_cap_at_all():
    """The traffic that fills it is *valid*: the epoch budget bounds how much
    verification a node will do and nothing bounded how much of the result it
    would keep."""
    node, _, _ = _node_and_tx()
    assert node.max_mempool == MAX_MEMPOOL
    assert MAX_MEMPOOL > 0


def test_a_full_pool_refuses_a_transaction_that_does_not_beat_the_floor():
    node, tx, _ = _node_and_tx()
    node.max_mempool = 3
    _fill(node, [10, 20, 30])
    cheap = dataclasses.replace(tx, fee=5)
    ok, why = node.admissible(cheap)
    assert not ok and "does not beat" in why, why


def test_a_full_pool_admits_one_that_does_and_drops_the_cheapest():
    node, tx, _ = _node_and_tx()          # this one pays a fee of 5
    node.max_mempool = 3
    _fill(node, [1, 2, 3])
    assert node.submit(tx)[0], "a 5-fee transaction against a floor of 1"
    assert len(node.mempool) == 3, "the cap held"
    assert "tx:0" not in node.mempool, "and the cheapest went"
    assert node.evicted == 1
    assert tx.txid in node.mempool


def test_the_floor_is_the_lowest_fee_and_the_oldest_of_a_tie():
    """So a flood of identical zero-fee transactions displaces itself rather
    than the pool."""
    node, _, _ = _node_and_tx()
    _fill(node, [0, 0, 0, 7])
    assert node._cheapest() == ("tx:0", 0)


def test_eviction_releases_what_the_evicted_transaction_reserved():
    """Or the note it was spending stays locked and nothing can replace it."""
    node, tx, _ = _node_and_tx()
    node.max_mempool = 1
    _fill(node, [1])
    node._reserved_nf["nf:tx:0"] = "tx:0"
    node._reserved_cm["cm:tx:0"] = "tx:0"
    assert node.submit(tx)[0]
    assert "nf:tx:0" not in node._reserved_nf
    assert "cm:tx:0" not in node._reserved_cm


def test_a_full_pool_is_not_a_fee_market():
    """Worth pinning, because it is the thing this must not be mistaken for.
    Two nodes with different caps still agree on every block: the cap changes
    what a node *holds*, never what a block may contain."""
    from chain.node import Node as _Node
    small = _Node("a", Signer.from_seed("a"), PARAMS,
                  ChainState(PARAMS, chain_id=CHAIN), max_mempool=1)
    large = _Node("b", Signer.from_seed("b"), PARAMS,
                  ChainState(PARAMS, chain_id=CHAIN), max_mempool=99)
    assert small.max_mempool != large.max_mempool
    assert small.params is large.params, "no consensus parameter moved"
