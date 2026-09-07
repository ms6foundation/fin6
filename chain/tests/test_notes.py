"""Note commitments and nullifiers."""
from ..crypto import Signer
from ..notes import (Note, asset_field, note_id, note_vector, nullifier_id,
                     nullifier_value, system_for)
from ..params import DEMO, STRONG

ALICE = Signer.from_seed("alice")


def test_commitment_is_deterministic():
    n = Note.create(100, ALICE.public_hex, DEMO)
    assert note_vector(n, DEMO) == note_vector(n, DEMO)
    assert n.commit(DEMO)[0] == n.commit(DEMO)[0]


def test_equal_values_get_different_commitments():
    """Blinders are what make a small, guessable value unrecoverable."""
    a = Note.create(100, ALICE.public_hex, DEMO)
    b = Note.create(100, ALICE.public_hex, DEMO)
    assert a.commit(DEMO)[0] != b.commit(DEMO)[0]


def test_commitment_binds_every_coordinate():
    base = Note.create(100, ALICE.public_hex, DEMO)
    for field, value in (("value", 101), ("asset", asset_field("EUR")),
                         ("owner", 12345), ("rho", 999)):
        other = Note(**{**base.__dict__, field: value})
        assert other.commit(DEMO)[0] != base.commit(DEMO)[0], field


def test_nullifier_is_deterministic_and_note_specific():
    a = Note.create(100, ALICE.public_hex, DEMO)
    b = Note.create(100, ALICE.public_hex, DEMO)
    assert a.nullifier(DEMO) == a.nullifier(DEMO)
    assert a.nullifier(DEMO) != b.nullifier(DEMO)


def test_nullifier_changes_with_rho():
    a = Note.create(100, ALICE.public_hex, DEMO)
    b = Note(**{**a.__dict__, "rho": (a.rho + 1)})
    assert nullifier_value(a.coords()) != nullifier_value(b.coords())


def test_note_system_is_shared_and_cached():
    assert system_for(DEMO) is system_for(DEMO)
    assert system_for(DEMO) is not system_for(STRONG)
    assert system_for(DEMO).n == DEMO.n_note


def test_value_must_be_in_range_at_creation():
    try:
        Note.create(DEMO.max_value, ALICE.public_hex, DEMO)
    except ValueError:
        return
    raise AssertionError("out-of-range value was accepted")
