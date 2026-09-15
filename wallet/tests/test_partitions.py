"""Spending more than one note, in a chain that spreads notes across grids.

Review B3. `TxSystem` has always handled k inputs; `Wallet.send` refused to use
more than one and said so — *"multi-note spends are not built yet, the design's
open item"* — so a wallet holding change could be unable to spend what it
plainly had. That is the item this closes, and closing it is what makes B3
live, because the moment a transaction has two inputs they can land in two
different grids.

A note is spendable in exactly one grid: `partition_of_nullifier` is what makes
a cross-grid double spend structurally impossible rather than merely
detectable. A transaction spending notes from two grids would need two grids to
agree about it — the thing partitioning exists to avoid — so it has no home.
Not refused, *homeless*: it used to be accepted by a node and sit in mempools
until it was forgotten.

Three answers, and all three are here. The wallet does not build one
(`select`). A node does not take one in. And change is steered back into the
partition it came from, so a balance does not scatter across grids one payment
at a time until it can no longer make a payment at all.
"""
import dataclasses

from chain.crypto import Signer
from chain.locality import (note_in_partition, partition_of_note,
                            partition_of_nullifier, tx_partition)
from chain.node import MAX_INPUTS
from chain.notes import Note, note_id, note_vector
from chain.params import DEMO
from chain.transaction import verify_transaction
from wallet.keys import WalletKeys
from wallet.store import Held, Wallet, WalletError

PARAMS = dataclasses.replace(DEMO, proof_backends=("mpcith",),
                             default_backend="mpcith",
                             proof_policy=((0, "mpcith"),))
CHAIN = "fin6:" + "cd" * 32
K = 4


def _wallet(phrase, n_partitions=K):
    return Wallet(WalletKeys.from_phrase(phrase), PARAMS, chain_id=CHAIN,
                  name=phrase, n_partitions=n_partitions)


def _fund_in(wallet, value, partition):
    """Give a wallet a note that lives in a particular grid."""
    note = note_in_partition(value, wallet.address.spend_hex, PARAMS,
                             partition, wallet.n_partitions)
    cm = note_id(note_vector(note, PARAMS))
    wallet.held[cm] = Held(note=note, cm=cm, height=1)
    return note


# ── where a note lives ───────────────────────────────────────────────────────

def test_a_holder_can_tell_where_a_note_lives_before_spending_it():
    """The nullifier is a function of the note alone — no key material — so
    the partition is knowable the moment the note is. That is what lets a
    wallet choose inputs instead of discovering at proving time that it has
    built something no grid will take."""
    alice = _wallet("alice")
    note = _fund_in(alice, 100, 2)
    assert partition_of_note(note, PARAMS, K) == 2
    held = next(iter(alice.held.values()))
    assert alice.partition_of(held) == 2


def test_a_note_can_be_drawn_into_the_grid_it_is_wanted_in():
    """`rho` is randomness the payer draws anyway, and the partition is a hash
    of the note, so steering costs a few draws and no information: a note's
    partition is public from the moment it is spent."""
    pk = Signer.from_seed("x").public_hex
    for part in range(K):
        note = note_in_partition(50, pk, PARAMS, part, K)
        assert partition_of_note(note, PARAMS, K) == part


def test_one_grid_means_everything_is_in_partition_zero():
    alice = _wallet("alice", n_partitions=1)
    for value in (10, 20, 30):
        _fund_in(alice, value, 0)
    assert set(alice.by_partition()) == {0}


# ── selection stays inside one grid ──────────────────────────────────────────

def test_selection_never_crosses_a_partition():
    alice = _wallet("alice")
    _fund_in(alice, 40, 0)
    _fund_in(alice, 40, 0)
    _fund_in(alice, 90, 1)
    chosen, total, part = alice.select(70)
    assert {alice.partition_of(h) for h in chosen} == {part}
    assert total >= 70


def test_the_fewest_notes_wins_because_a_proof_covers_every_input():
    alice = _wallet("alice")
    for value in (10, 10, 10, 10, 10, 10, 10, 10):
        _fund_in(alice, value, 0)
    _fund_in(alice, 80, 1)
    chosen, total, part = alice.select(70)
    assert len(chosen) == 1 and part == 1, [h.value for h in chosen]


def test_a_balance_spread_too_thin_says_so_and_says_what_to_do():
    """The honest failure. The money is there and no grid holds enough of it,
    which is a different problem from being poor and has a different answer."""
    alice = _wallet("alice")
    _fund_in(alice, 60, 0)
    _fund_in(alice, 60, 1)
    assert alice.balance() == 120
    try:
        alice.select(100)
    except WalletError as exc:
        said = str(exc)
        assert "no single grid holds" in said
        assert "consolidate" in said
    else:
        raise AssertionError("selected across two grids")


def test_being_poor_is_reported_as_being_poor():
    alice = _wallet("alice")
    _fund_in(alice, 10, 0)
    try:
        alice.select(500)
    except WalletError as exc:
        assert "cannot cover" in str(exc)
    else:
        raise AssertionError("paid more than it held")


def test_more_inputs_than_the_chain_admits_is_not_a_selection():
    alice = _wallet("alice", n_partitions=1)
    for _ in range(MAX_INPUTS + 4):
        _fund_in(alice, 1, 0)
    try:
        alice.select(MAX_INPUTS + 2)
    except WalletError as exc:
        assert "no single grid holds" in str(exc) or "cannot cover" in str(exc)
    else:
        raise AssertionError(f"selected more than {MAX_INPUTS} inputs")


# ── the transaction that comes out ───────────────────────────────────────────

def test_a_multi_note_spend_proves_and_has_a_home():
    alice, bob = _wallet("alice"), _wallet("bob")
    _fund_in(alice, 40, 3)
    _fund_in(alice, 40, 3)
    tx, change = alice.send(bob.address, 70, fee=2)
    assert len(tx.inputs) == 2
    ok, why = verify_transaction(tx, PARAMS, chain_id=CHAIN)
    assert ok, why
    assert tx_partition(tx, K) == 3, "every input in the grid that owns it"


def test_change_comes_home_to_the_partition_it_came_from():
    """Otherwise a wallet's notes scatter one payment at a time, and a balance
    spread thin enough can no longer make a payment at all.

    Repeated, because one unsteered change note lands in the right grid one
    time in four by accident: a single payment proves nothing here.
    """
    alice, bob = _wallet("alice"), _wallet("bob")
    _fund_in(alice, 400, 2)
    for _ in range(8):
        held = next(iter(alice.held.values()))
        assert alice.partition_of(held) == 2
        tx, change = alice.send(bob.address, 5, fee=1)
        assert partition_of_note(change, PARAMS, K) == 2
        alice.held.clear()
        cm = note_id(note_vector(change, PARAMS))
        alice.held[cm] = Held(note=change, cm=cm, height=1)


def test_the_payment_itself_is_wherever_it_lands():
    """The payee's note is not steered: where the recipient's money lives is
    the recipient's business, and a payer choosing it would be deciding which
    grid somebody else has to spend in.

    Asserted by looking, which needs the recipient: only Bob can open what was
    sealed to Bob.
    """
    from wallet.sealing import decrypt_opening

    alice, bob = _wallet("alice"), _wallet("bob")
    _fund_in(alice, 400, 0)
    seen = set()
    for _ in range(12):
        tx, change = alice.send(bob.address, 5, fee=1)
        note = decrypt_opening(bytes(tx.output_notes[0]), bob.keys,
                               tx.output_cms[0], PARAMS)
        assert note is not None and note.value == 5
        seen.add(partition_of_note(note, PARAMS, K))
        # spend the change next time round, so each payment is a fresh draw
        alice.held.clear()
        cm = note_id(note_vector(change, PARAMS))
        alice.held[cm] = Held(note=change, cm=cm, height=1)
    assert len(seen) > 1, "the payee's partition is drawn, not chosen"


# ── consolidation ────────────────────────────────────────────────────────────

def test_consolidation_gathers_one_grids_notes_into_one_note_there():
    alice = _wallet("alice")
    for value in (10, 20, 30):
        _fund_in(alice, value, 1)
    _fund_in(alice, 99, 0)
    tx, gathered = alice.consolidate(1, fee=1)
    assert len(tx.inputs) == 3
    assert gathered.value == 59
    assert partition_of_note(gathered, PARAMS, K) == 1, \
        "gathering into another grid would be moving the problem"
    ok, why = verify_transaction(tx, PARAMS, chain_id=CHAIN)
    assert ok, why


def test_consolidation_defaults_to_the_grid_that_needs_it_most():
    alice = _wallet("alice")
    _fund_in(alice, 50, 0)
    for value in (5, 5, 5):
        _fund_in(alice, value, 2)
    tx, gathered = alice.consolidate(fee=1)
    assert len(tx.inputs) == 3 and gathered.value == 14


def test_consolidating_one_note_is_a_fee_for_nothing():
    alice = _wallet("alice")
    _fund_in(alice, 50, 0)
    try:
        alice.consolidate(0)
    except WalletError as exc:
        assert "fee for nothing" in str(exc)
    else:
        raise AssertionError("paid a fee to change nothing")


def test_a_consolidated_balance_can_make_the_payment_it_could_not():
    """The whole point of having the escape hatch: the failure in
    `test_a_balance_spread_too_thin_says_so_and_says_what_to_do` is
    recoverable, and this is the recovery."""
    alice, bob = _wallet("alice"), _wallet("bob")
    _fund_in(alice, 60, 0)
    _fund_in(alice, 30, 0)
    _fund_in(alice, 60, 1)
    try:
        alice.send(bob.address, 100, fee=1)
    except WalletError as exc:
        assert "no single grid holds" in str(exc)
    else:
        raise AssertionError("spent across two grids")
    tx, gathered = alice.consolidate(0, fee=1)
    assert gathered.value == 89
