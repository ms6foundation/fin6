"""Handing an auditor less than everything.

The open item was that a viewing key is a permanent, unscoped grant: give one
away and the holder can read every note ever sent to that address, including
the notes nobody has sent yet. Revocation in the ordinary sense is not on
offer — bytes cannot be un-given — so what is on offer is bounds set in
advance, and two of them are available without touching the chain at all.

**Diversified addresses** make the bound "this address": one seed, many
addresses, so a counterparty or a period can have its own and a disclosure is
that relationship rather than a life.

**Per-output keys** make the bound "these notes": the key that opens one
sealed opening, derived from that output's own ephemeral key, useless against
any other.
"""
import dataclasses

from chain.crypto import owner_field
from chain.notes import Note, note_id, note_vector
from chain.params import DEMO
from chain.state import ChainState

from ..keys import WalletKeys
from ..sealing import (decrypt_opening, disclosure_key, open_disclosed,
                       opening_key, seal_output)
from ..store import Held, Wallet

PARAMS = DEMO
CHAIN = "fin6:" + "ab" * 32


def _wallet(phrase="alice", name="alice"):
    return Wallet(WalletKeys.from_phrase(phrase), PARAMS, chain_id=CHAIN,
                  name=name)


def _pay(to_address, value=250, asset=None):
    """One sealed output to an address, as the chain would carry it."""
    note = Note.create(value, to_address.spend_hex, PARAMS, asset=asset)
    cm = note_id(note_vector(note, PARAMS))
    blob, tag = seal_output(note, to_address, cm, PARAMS)
    return note, cm, blob


# ── diversified addresses ────────────────────────────────────────────────────

def test_one_seed_many_addresses():
    keys = WalletKeys.from_phrase("alice")
    a, b = keys.address, keys.at(1).address
    assert a.encode() != b.encode()
    assert a.spend_hex != b.spend_hex and a.view_hex != b.view_hex
    assert a.detect_hex != b.detect_hex, "the detection grant is scoped too"


def test_index_zero_is_what_it_always_was():
    """Every address, genesis holder and stored wallet in existence is index
    zero, so it has to be byte-identical or this is a migration."""
    keys = WalletKeys.from_phrase("alice")
    assert WalletKeys(keys.seed).address.encode() == keys.address.encode()
    assert keys.at(0).address.encode() == keys.address.encode()


def test_a_viewing_key_opens_its_own_address_and_no_other():
    """The whole point of diversifying. An auditor holding address 1's
    viewing key learns nothing about address 0's money."""
    keys = WalletKeys.from_phrase("alice")
    scoped = keys.at(1)
    _, cm0, blob0 = _pay(keys.address)
    _, cm1, blob1 = _pay(scoped.address)

    assert decrypt_opening(blob1, scoped, cm1, PARAMS) is not None
    assert decrypt_opening(blob0, scoped, cm0, PARAMS) is None, \
        "address 1's key read a note sent to address 0"
    assert decrypt_opening(blob1, keys, cm1, PARAMS) is None, \
        "and it does not work the other way either"


def test_a_wallet_finds_money_at_every_address_it_watches():
    w = _wallet()
    second = w.new_address()
    _, cm0, blob0 = _pay(w.address, 100)
    _, cm1, blob1 = _pay(second, 250)
    assert w.scan([(1, cm0, blob0), (1, cm1, blob1)]) == 2
    assert w.balance() == 350
    assert w.held[cm1].index == 1, "and remembers which address received it"


def test_a_note_is_spent_by_the_address_that_received_it():
    """The owner coordinate is part of the commitment, so a wallet that
    assumed index 0 would sign with the wrong key and build a statement it
    cannot prove."""
    w = _wallet()
    second = w.new_address()
    note, cm, blob = _pay(second, 500)
    assert w.scan([(1, cm, blob)]) == 1
    held = w.held[cm]
    assert held.index == 1
    assert held.note.owner == owner_field(second.spend_hex)
    assert w.keys_for(1).signer.public_hex == second.spend_hex


def test_change_goes_back_to_the_address_that_paid():
    """Otherwise scoping is defeated quietly: disclose one address and the
    change from every other address's notes is sitting in it."""
    w = _wallet()
    second = w.new_address()
    note, cm, blob = _pay(second, 1000)
    w.scan([(1, cm, blob)])
    bob = WalletKeys.from_phrase("bob").address
    tx, change = w.send(bob, 250, fee=5)
    assert change.owner == owner_field(second.spend_hex), \
        "change leaked into another address's scope"


def test_the_diversifiers_survive_a_restore(tmp=None):
    import tempfile, os
    w = _wallet()
    w.new_address()
    w.new_address()
    _, cm, blob = _pay(w.addresses[2], 42)
    w.scan([(3, cm, blob)])
    path = os.path.join(tempfile.mkdtemp(prefix="fin6-div-"), "notes.json")
    w.save(path)
    back = Wallet.load(path, WalletKeys.from_phrase("alice"), PARAMS)
    assert sorted(back.addresses) == [0, 1, 2], \
        "a restore that forgets which addresses were used loses the money"
    assert back.balance() == 42
    assert back.held[cm].index == 2


# ── per-output disclosure keys ───────────────────────────────────────────────

def test_a_disclosure_key_opens_exactly_one_output():
    keys = WalletKeys.from_phrase("alice")
    note_a, cm_a, blob_a = _pay(keys.address, 100)
    note_b, cm_b, blob_b = _pay(keys.address, 700)

    key_a = disclosure_key(keys, blob_a, cm_a)
    opened = open_disclosed(blob_a, key_a, cm_a, keys.spend_hex, PARAMS)
    assert opened is not None and opened.value == 100

    assert open_disclosed(blob_b, key_a, cm_b, keys.spend_hex, PARAMS) is None, \
        "one output's key opened another"


def test_a_disclosure_key_is_not_a_viewing_key():
    """What makes it the narrowest grant available: it carries no ability to
    read anything that has not been named."""
    keys = WalletKeys.from_phrase("alice")
    _, cm, blob = _pay(keys.address, 100)
    key = disclosure_key(keys, blob, cm)
    assert key != keys.viewing_secret()
    # A future payment to the same address is untouched by it.
    _, later_cm, later_blob = _pay(keys.address, 999)
    assert open_disclosed(later_blob, key, later_cm, keys.spend_hex,
                          PARAMS) is None


def test_disclosure_is_self_proving():
    """The auditor is not taking the holder's word for the amount: the key
    either opens the ciphertext under that commitment or it does not, and the
    reconstructed note has to reproduce the commitment."""
    keys = WalletKeys.from_phrase("alice")
    note, cm, blob = _pay(keys.address, 250)
    key = disclosure_key(keys, blob, cm)
    assert open_disclosed(blob, key, cm, keys.spend_hex, PARAMS).value == 250
    # A holder claiming this key belongs to some other commitment gets nothing.
    assert open_disclosed(blob, key, "cm:" + "00" * 32, keys.spend_hex,
                          PARAMS) is None
    # And a garbled key opens nothing rather than opening something wrong.
    assert open_disclosed(blob, "ff" * 32, cm, keys.spend_hex, PARAMS) is None
    assert open_disclosed(blob, "not hex", cm, keys.spend_hex, PARAMS) is None


def test_the_wallet_discloses_only_what_it_holds():
    w = _wallet()
    note, cm, blob = _pay(w.address, 250)
    w.scan([(1, cm, blob)])
    _, other_cm, other_blob = _pay(WalletKeys.from_phrase("bob").address, 9)

    out = w.disclose([cm, other_cm, "cm:nonsense"], {cm: blob,
                                                     other_cm: other_blob})
    assert set(out) == {cm}, "it offered a key for somebody else's note"
    opened = open_disclosed(blob, out[cm]["key"], cm, out[cm]["owner"], PARAMS)
    assert opened is not None and opened.value == 250


def test_disclosure_spans_addresses_without_disclosing_them():
    """Three payments across two addresses, shown one at a time — and the
    viewing key of neither address changes hands."""
    w = _wallet()
    second = w.new_address()
    rows, sealed = [], {}
    for i, (addr, value) in enumerate([(w.address, 10), (second, 20),
                                       (second, 30)]):
        _, cm, blob = _pay(addr, value)
        rows.append((i + 1, cm, blob))
        sealed[cm] = blob
    w.scan(rows)
    shown = [rows[0][1], rows[2][1]]
    out = w.disclose(shown, sealed)
    assert set(out) == set(shown)
    values = sorted(open_disclosed(sealed[cm], out[cm]["key"], cm,
                                   out[cm]["owner"], PARAMS).value
                    for cm in out)
    assert values == [10, 30]
    # The one that was not named stays shut.
    hidden = rows[1][1]
    for cm in out:
        assert open_disclosed(sealed[hidden], out[cm]["key"], hidden,
                              out[cm]["owner"], PARAMS) is None


def test_what_disclosure_does_not_prove():
    """Completeness. Every key here is authenticity — what you were shown is
    real — and nothing stops a holder showing two payments out of three. An
    auditor that needs "you showed me everything" needs the detection secret
    for a range, or the output count the header already commits."""
    w = _wallet()
    rows, sealed = [], {}
    for i, value in enumerate([10, 20, 30]):
        _, cm, blob = _pay(w.address, value)
        rows.append((i + 1, cm, blob))
        sealed[cm] = blob
    w.scan(rows)
    partial = w.disclose([rows[0][1]], sealed)
    assert len(partial) == 1 and len(w.held) == 3
