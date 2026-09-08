"""The user's side: keys, addresses, sealed openings, and a wallet.

The interesting tests here are the negative ones. A wallet's whole job is to
recognise its own money and nothing else, so what matters is not that Bob can
open the note addressed to him — that is one line — but that Carol cannot,
that a ciphertext moved to another output is refused, and that swapping the
ciphertexts inside a transaction breaks the proof rather than silently
redirecting the payment.

The last test pays a stranger across seven real node processes.
"""
import dataclasses
import os
import shutil
import tempfile
import time

from ..genesis import boot, load as load_genesis
from ..keys import Address, AddressError, WalletKeys, ephemeral
from ..net import supervisor as sv
from ..net.client import Client, ClientError
from ..notes import (Note, decrypt_opening, encrypt_opening, note_id,
                     note_vector)
from ..params import DEMO
from ..transaction import build_transaction, verify_transaction
from ..wallet import Held, Wallet, WalletError

PARAMS = dataclasses.replace(DEMO, proof_backends=("mpcith",),
                             default_backend="mpcith",
                             proof_policy=(("local", "mpcith"),))
CHAIN = "fin6:" + "ab" * 32


def _wallet(phrase, params=PARAMS):
    return Wallet(WalletKeys.from_phrase(phrase), params, chain_id=CHAIN,
                  name=phrase)


def _fund(wallet, value, params=PARAMS):
    note = Note.create(value, wallet.address.spend_hex, params)
    cm = note_id(note_vector(note, params))
    wallet.held[cm] = Held(note=note, cm=cm, height=1)
    return note, cm


# ── keys and addresses ───────────────────────────────────────────────────────

def test_a_seed_gives_the_same_wallet_every_time():
    a, b = WalletKeys.from_phrase("alice"), WalletKeys.from_phrase("alice")
    assert a.address == b.address
    assert a.address != WalletKeys.from_phrase("alicf").address


def test_an_address_round_trips_through_its_text():
    addr = WalletKeys.from_phrase("alice").address
    assert Address.decode(addr.encode()) == addr
    assert addr.encode().startswith("fin6")


def test_a_corrupted_address_is_refused_rather_than_decoded():
    """The checksum is what stops money going to an address nobody holds."""
    text = WalletKeys.from_phrase("alice").address.encode()
    caught = 0
    for i in range(4, 40):          # inside the payload, not the padding tail
        bad = text[:i] + ("a" if text[i] != "a" else "b") + text[i + 1:]
        try:
            Address.decode(bad)
        except AddressError:
            caught += 1
    assert caught == 36, f"only {caught}/36 single-character typos were caught"


def test_an_address_from_another_scheme_is_refused():
    for bad in ("", "fin7abc", "fin6", "fin6" + "a" * 20, "fin6!!!!"):
        try:
            Address.decode(bad)
        except AddressError:
            continue
        raise AssertionError(f"accepted {bad!r}")


def test_the_two_keys_are_not_the_same_key():
    keys = WalletKeys.from_phrase("alice")
    assert keys.spend_hex != keys.view_hex
    assert keys.viewing_secret() != keys.seed.hex()


# ── sealed openings ──────────────────────────────────────────────────────────

def test_the_recipient_recovers_the_note_and_nobody_else_does():
    bob, carol = WalletKeys.from_phrase("bob"), WalletKeys.from_phrase("carol")
    note = Note.create(250, bob.address.spend_hex, PARAMS)
    cm = note_id(note_vector(note, PARAMS))
    sealed = encrypt_opening(note, bob.address, cm, PARAMS)
    assert decrypt_opening(sealed, bob, cm, PARAMS) == note
    assert decrypt_opening(sealed, carol, cm, PARAMS) is None


def test_a_ciphertext_moved_to_another_output_is_refused():
    """The commitment is the associated data, so a sealed opening only opens
    the output it was made for."""
    bob = WalletKeys.from_phrase("bob")
    note = Note.create(250, bob.address.spend_hex, PARAMS)
    cm = note_id(note_vector(note, PARAMS))
    sealed = encrypt_opening(note, bob.address, cm, PARAMS)
    assert decrypt_opening(sealed, bob, "nc:" + "00" * 32, PARAMS) is None
    for i in (0, 40, len(sealed) - 1):
        torn = sealed[:i] + bytes([sealed[i] ^ 1]) + sealed[i + 1:]
        assert decrypt_opening(torn, bob, cm, PARAMS) is None
    assert decrypt_opening(b"", bob, cm, PARAMS) is None


def test_a_sealed_opening_costs_what_the_design_says():
    bob = WalletKeys.from_phrase("bob")
    note = Note.create(250, bob.address.spend_hex, PARAMS)
    cm = note_id(note_vector(note, PARAMS))
    assert len(encrypt_opening(note, bob.address, cm, PARAMS)) == 272


def test_swapping_the_ciphertexts_breaks_the_proof():
    """The openings are bound into the transaction, so an attacker who moves
    them cannot redirect a payment — the statement no longer verifies."""
    alice, bob = _wallet("alice"), _wallet("bob")
    note, _ = _fund(alice, 1000)
    tx, _ = alice.send(bob.address, 250, fee=5)
    assert verify_transaction(tx, PARAMS, chain_id=CHAIN)[0]
    swapped = dataclasses.replace(tx, output_notes=tuple(
        reversed(tx.output_notes)))
    assert not verify_transaction(swapped, PARAMS, chain_id=CHAIN)[0]
    stripped = dataclasses.replace(tx, output_notes=())
    assert not verify_transaction(stripped, PARAMS, chain_id=CHAIN)[0]


# ── the wallet ───────────────────────────────────────────────────────────────

def test_a_wallet_finds_only_its_own_money():
    alice, bob, carol = _wallet("alice"), _wallet("bob"), _wallet("carol")
    _fund(alice, 1000)
    tx, _ = alice.send(bob.address, 250, fee=5)
    outputs = [(7, cm, blob)
               for cm, blob in zip(tx.output_cms, tx.output_notes)]
    assert bob.scan(outputs) == 1 and bob.balance() == 250
    assert carol.scan(outputs) == 0 and carol.balance() == 0
    assert bob.scan(outputs) == 0, "scanning twice must not double-count"


def test_a_spent_note_disappears_when_its_nullifier_appears():
    alice, bob = _wallet("alice"), _wallet("bob")
    _fund(alice, 1000)
    tx, change = alice.send(bob.address, 250, fee=5)
    alice.scan([(7, cm, blob)
                for cm, blob in zip(tx.output_cms, tx.output_notes)])
    assert alice.reconcile(tx.nullifiers, height=7) == 1
    assert alice.balance() == 745, "1000 − 250 − 5, as change"


def test_selection_is_smallest_first_and_says_so_when_it_cannot_pay():
    alice = _wallet("alice")
    for value in (10, 50, 100):
        _fund(alice, value)
    chosen, total = alice.select(55)
    assert [h.value for h in chosen] == [10, 50] and total == 60
    try:
        alice.select(1000)
    except WalletError as exc:
        assert "cannot cover" in str(exc)
        return
    raise AssertionError("paid more than it held")


def test_a_multi_note_spend_refuses_rather_than_building_a_bad_proof():
    alice, bob = _wallet("alice"), _wallet("bob")
    _fund(alice, 10)
    _fund(alice, 50)
    try:
        alice.send(bob.address, 55)
    except WalletError as exc:
        assert "multi-note" in str(exc)
        return
    raise AssertionError("built a transaction it cannot prove")


def test_the_note_store_is_a_cache_that_round_trips():
    alice = _wallet("alice")
    _fund(alice, 1000)
    alice.scanned_to = 9
    path = os.path.join(tempfile.mkdtemp(prefix="fin6-wallet-"), "notes.json")
    try:
        alice.save(path)
        back = Wallet.load(path, WalletKeys.from_phrase("alice"), PARAMS)
        assert back.balance() == 1000 and back.scanned_to == 9
        assert back.address == alice.address
        try:
            Wallet.load(path, WalletKeys.from_phrase("bob"), PARAMS)
        except WalletError as exc:
            assert "different seed" in str(exc)
        else:
            raise AssertionError("opened another wallet's store")
    finally:
        shutil.rmtree(os.path.dirname(path), ignore_errors=True)


# ── seven processes, one stranger ────────────────────────────────────────────

def test_a_stranger_is_paid_on_a_running_network():
    """The one that makes the wallet real.

    A wallet that has been told nothing but its own seed is paid across seven
    node processes, finds the money by scanning, and spends it onward.
    """
    root = tempfile.mkdtemp(prefix="fin6-wallet-net-")
    base_port = 7900 + (os.getpid() % 50) * 10
    try:
        sv.new_testnet(root, nodes=4, preset="local", epoch_millis=2500,
                       base_port=base_port, force=True)
        doc = load_genesis(os.path.join(root, "genesis.json"))
        params = doc.chain_params()
        client = Client("127.0.0.1", base_port, doc.chain_id)
        net = sv.Testnet(root)
        net.up(start_in_ms=4000)
        try:
            net.wait_for_height(1, timeout=75)

            _, holders = boot(doc)
            treasury = Wallet(WalletKeys.from_phrase("genesis:treasury"),
                              params, chain_id=doc.chain_id, name="treasury")
            for note in holders["treasury"].notes:
                cm = note_id(note_vector(note, params))
                treasury.held[cm] = Held(note=note, cm=cm, height=0)
            assert treasury.balance() == 4000

            bob = Wallet(WalletKeys.generate(), params, chain_id=doc.chain_id,
                         name="bob")
            tx, _ = treasury.send(bob.address, 250, fee=5)
            client.submit(tx)
            assert _confirmed(client, tx.txid) is not None

            got = client.sync(bob)
            assert got["found"] == 1 and got["balance"] == 250, got
            assert client.sync(treasury)["balance"] == 3745

            carol = Wallet(WalletKeys.generate(), params,
                           chain_id=doc.chain_id, name="carol")
            second, _ = bob.send(carol.address, 100, fee=2)
            client.submit(second)
            assert _confirmed(client, second.txid) is not None
            assert client.sync(carol)["balance"] == 100
            assert client.sync(bob)["balance"] == 148
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)


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
