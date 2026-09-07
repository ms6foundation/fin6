"""Transaction soundness: what the single MQ proof does and does not let through."""
from mq.ms6 import P

from ..crypto import Signer
from ..notes import Note, note_id, note_vector
from ..params import DEMO
from ..transaction import (TxError, build_transaction, verify_transaction,
                           verify_transaction_vs6)
from .helpers import forge_transaction, raw_note

ALICE = Signer.from_seed("alice")
BOB = Signer.from_seed("bob")
MALLORY = Signer.from_seed("mallory")


def _spend(value=1000, out=(300, 695), fee=5):
    note = Note.create(value, ALICE.public_hex, DEMO)
    outs = [Note.create(out[0], BOB.public_hex, DEMO, asset=note.asset),
            Note.create(out[1], ALICE.public_hex, DEMO, asset=note.asset)]
    return note, outs, fee


def test_valid_transaction_verifies():
    note, outs, fee = _spend()
    tx = build_transaction([(note, ALICE)], outs, fee, DEMO)
    ok, why = verify_transaction(tx, DEMO)
    assert ok, why


def test_valid_transaction_verifies_under_independent_vs6_verifier():
    note, outs, fee = _spend()
    tx = build_transaction([(note, ALICE)], outs, fee, DEMO)
    ok, why = verify_transaction_vs6(tx, DEMO)
    assert ok, why


def test_builder_refuses_non_conserving_values():
    note, outs, _ = _spend()
    try:
        build_transaction([(note, ALICE)], outs, 999, DEMO)
    except TxError as exc:
        assert "conserve" in str(exc)
        return
    raise AssertionError("builder accepted a non-conserving transaction")


def test_inflation_by_negative_output_is_caught_by_the_range_rows():
    """The attack the range proof exists to stop.

    Values live in F_P, so an attacker can pick a huge output and a negative
    one that cancel mod P: conservation alone is satisfied and the attacker
    walks away with a note worth far more than the input.  Only the bit
    decomposition rules it out.
    """
    note = Note.create(1000, ALICE.public_hex, DEMO)
    huge = raw_note(1_000_000, BOB.public_hex, DEMO, asset=note.asset)
    negative = raw_note(1000 - 1_000_000, ALICE.public_hex, DEMO,
                        asset=note.asset)
    tx, ts = forge_transaction([(note, ALICE)], [huge, negative], DEMO,
                               declared_fee=0)

    # The sum row is perfectly happy: the forged values do conserve mod P.
    assert tx.v[ts.sum_row] == 0, "the attack should satisfy conservation"

    ok, why = verify_transaction(tx, DEMO)
    assert not ok
    assert "range" in why, why


def test_output_above_range_bound_is_rejected():
    note = Note.create(1000, ALICE.public_hex, DEMO)
    over = raw_note(DEMO.max_value + 7, BOB.public_hex, DEMO, asset=note.asset)
    under = raw_note(1000 - DEMO.max_value - 7, ALICE.public_hex, DEMO,
                     asset=note.asset)
    tx, _ = forge_transaction([(note, ALICE)], [over, under], DEMO,
                              declared_fee=0)
    ok, why = verify_transaction(tx, DEMO)
    assert not ok and "range" in why, why


def test_declared_fee_must_match_the_sum_row():
    note, outs, fee = _spend()
    tx = build_transaction([(note, ALICE)], outs, fee, DEMO)
    lying = type(tx)(**{**tx.__dict__, "fee": fee + 1})
    ok, why = verify_transaction(lying, DEMO)
    assert not ok, "a restated fee must break the binding or the sum row"


def test_tampered_public_vector_is_rejected():
    note, outs, fee = _spend()
    tx = build_transaction([(note, ALICE)], outs, fee, DEMO)
    for row in (0, len(tx.v) // 2, len(tx.v) - 1):
        bad_v = list(tx.v)
        bad_v[row] = (bad_v[row] + 1) % P
        bad = type(tx)(**{**tx.__dict__, "v": tuple(bad_v)})
        ok, _ = verify_transaction(bad, DEMO)
        assert not ok, f"tampering with row {row} was not caught"


def test_proof_cannot_be_lifted_onto_another_transaction():
    """The binding scalar is a revealed coordinate, so it enters the proof's
    Fiat-Shamir statement: a proof is welded to one body."""
    note_a, outs_a, fee = _spend()
    tx_a = build_transaction([(note_a, ALICE)], outs_a, fee, DEMO)
    note_b = Note.create(1000, ALICE.public_hex, DEMO)
    outs_b = [Note.create(400, BOB.public_hex, DEMO, asset=note_b.asset),
              Note.create(595, ALICE.public_hex, DEMO, asset=note_b.asset)]
    tx_b = build_transaction([(note_b, ALICE)], outs_b, fee, DEMO)

    spliced = type(tx_b)(**{**tx_b.__dict__, "proofs": tx_a.proofs})
    ok, why = verify_transaction(spliced, DEMO)
    assert not ok and "proof" in why, why


def test_spending_key_must_own_the_note():
    note = Note.create(1000, ALICE.public_hex, DEMO)
    outs = [Note.create(300, BOB.public_hex, DEMO, asset=note.asset),
            Note.create(700, ALICE.public_hex, DEMO, asset=note.asset)]
    tx, _ = forge_transaction([(note, ALICE)], outs, DEMO, declared_fee=0,
                              sign_with=[MALLORY])
    ok, why = verify_transaction(tx, DEMO)
    assert not ok and "owner" in why, why


def test_builder_refuses_a_key_that_does_not_own_the_note():
    note, outs, fee = _spend()
    try:
        build_transaction([(note, MALLORY)], outs, fee, DEMO)
    except TxError as exc:
        assert "own" in str(exc)
        return
    raise AssertionError("builder let the wrong key spend a note")


def test_assets_cannot_be_mixed():
    note = Note.create(1000, ALICE.public_hex, DEMO, asset="USD")
    outs = [raw_note(300, BOB.public_hex, DEMO),               # USD
            raw_note(700, ALICE.public_hex, DEMO)]
    outs[0] = Note(**{**outs[0].__dict__,
                      "asset": __import__("chain.notes", fromlist=["x"]).asset_field("EUR")})
    tx, _ = forge_transaction([(note, ALICE)], outs, DEMO, declared_fee=0)
    ok, why = verify_transaction(tx, DEMO)
    assert not ok and "asset" in why, why


def test_declared_output_commitment_must_match_the_proof():
    note, outs, fee = _spend()
    decoy = Note.create(999, MALLORY.public_hex, DEMO, asset=note.asset)
    real_cms = [note_id(note_vector(n, DEMO)) for n in outs]
    tx, _ = forge_transaction(
        [(note, ALICE)], outs, DEMO, declared_fee=fee,
        declared_out_cms=[note_id(note_vector(decoy, DEMO)), real_cms[1]])
    ok, why = verify_transaction(tx, DEMO)
    assert not ok, why


def test_wrong_chain_id_is_rejected():
    note, outs, fee = _spend()
    tx = build_transaction([(note, ALICE)], outs, fee, DEMO)
    ok, why = verify_transaction(tx, DEMO, chain_id="other-chain")
    assert not ok and "chain" in why, why


def test_state_hooks_catch_unknown_input_and_double_spend():
    note, outs, fee = _spend()
    tx = build_transaction([(note, ALICE)], outs, fee, DEMO)
    ok, why = verify_transaction(tx, DEMO, utxo_has=lambda cm: False)
    assert not ok and "unspent" in why, why
    ok, why = verify_transaction(tx, DEMO, nf_has=lambda nf: True)
    assert not ok and "double spend" in why, why
