"""What an address says about itself, and why that field exists now.

A6 in the pre-genesis review: the address format is at its last cheap moment.
Diversified addresses and per-output disclosure keys both ship and neither
touches the chain. Era-derived viewing keys — the thing that would fix what
diversifiers only mitigate, a viewing key handed over today still opening
payments made tomorrow — cannot be a software change, because the additive
tweak has to happen in Edwards form with an unclamped scalar, and that is a
different key-agreement scheme wearing the same 32 bytes.

An address with no scheme field would have to change shape to say which one it
is in, and by then every address in circulation is the old shape. So the field
goes in before any address is published, and this module is about what it does:
it makes an unimplemented scheme a *refusal* rather than a payment sealed to a
key nobody can read.

The construction itself is not built. docs/address_format_decision.md says why,
and what changes when it is.
"""
from ..keys import (Address, AddressError, ADDRESS_VERSION, ERA_ROTATING,
                    IMPLEMENTED, SCHEMES, X25519_STATIC, WalletKeys)

ALICE = WalletKeys.from_phrase("alice")


def test_an_address_round_trips_and_keeps_its_scheme():
    text = ALICE.address.encode()
    back = Address.decode(text)
    assert back == ALICE.address
    assert back.scheme == X25519_STATIC
    assert back.scheme_name() == "x25519-static-view"


def test_the_scheme_is_inside_the_checksummed_body():
    """Not a hint alongside the address — part of it. Editing the byte breaks
    the checksum, which is what stops a scheme downgrade being a typo nobody
    notices."""
    a = ALICE.address
    b = Address(a.spend_hex, a.view_hex, a.detect_hex, scheme=ERA_ROTATING)
    assert a.encode() != b.encode()
    assert a.payload()[1] == X25519_STATIC


def test_an_address_in_a_scheme_this_build_cannot_do_is_refused():
    """The whole reason for the field. Paying to keys this build misreads
    means sealing an opening to something the holder cannot open: money that
    arrives and cannot be spent, with nothing on chain to say why."""
    a = ALICE.address
    future = Address(a.spend_hex, a.view_hex, a.detect_hex,
                     scheme=ERA_ROTATING).encode()
    try:
        Address.decode(future)
    except AddressError as exc:
        assert "does not implement" in str(exc)
        assert SCHEMES[ERA_ROTATING] in str(exc)
    else:
        raise AssertionError("an unimplemented scheme was accepted")


def test_only_the_static_scheme_is_implemented_today():
    assert IMPLEMENTED == (X25519_STATIC,)
    assert ERA_ROTATING in SCHEMES and ERA_ROTATING not in IMPLEMENTED


def test_a_wallet_publishes_the_scheme_it_can_actually_read():
    assert ALICE.address.scheme in IMPLEMENTED


def test_the_version_moved_with_the_shape():
    """A new field is a new version, so an old decoder says 'version 2', not
    'checksum does not match' — the first is a message somebody can act on."""
    assert ADDRESS_VERSION == 3
    assert len(ALICE.address.payload()) == 2 + 96


def test_a_truncated_or_mistyped_address_still_fails_loudly():
    text = ALICE.address.encode()
    for bad in (text[:-1], text[:-2] + "aa", "fin6" + "zz"):
        try:
            Address.decode(bad)
        except AddressError:
            pass
        else:
            raise AssertionError(f"{bad[:20]}… was accepted")
