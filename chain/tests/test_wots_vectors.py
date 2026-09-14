"""Known answers for the one-time signature scheme, and the name it goes by.

A7 in the pre-genesis review: `chain/hardening/wots.py` is a teaching
implementation, and a subtle bug in it is a retroactive forgery surface across
all of history. The review's advice is to adopt a reviewed implementation
(RFC 8391), and the decision — written up in docs/wots_decision.md — is that
this is a swap that has to be *checkable*, because era 0's leaves are committed
at genesis and the parameters stop being negotiable the moment a chain exists.

Two things make it checkable, and this module is the test for both:

  * the scheme has a name, it travels in the genesis document, and it is inside
    the chain id;
  * the scheme has known answers, so a replacement is verified against bytes
    rather than against a reading of a specification.

These vectors are not a security property. They are a *compatibility* property:
they say that whatever verifies a stamp tomorrow computes what signed it today.
"""
import hashlib
import json
import os

from ..hardening import wots
from ..hardening.params import DEMO, HardeningParams
from ..hardening.pool import new_era

VECTORS = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                       "hardening", "vectors", "wots.json")


def _load():
    with open(VECTORS) as fh:
        return json.load(fh)


def test_the_parameters_are_the_ones_the_vectors_were_made_under():
    assert _load()["params"] == wots.params()


def test_every_vector_reproduces():
    """The whole point: a replacement implementation passes this file or it is
    not a replacement, whatever its specification says."""
    data = _load()
    seed = bytes.fromhex(data["master_seed"])
    pub = bytes.fromhex(data["pub_seed"])
    for v in data["vectors"]:
        index, msg = v["index"], bytes.fromhex(v["message"])
        pk = wots.public_key(seed, pub, index)
        assert pk.hex() == v["public_key"], f"public key at turn {index}"
        sig = wots.sign(seed, pub, index, msg)
        assert hashlib.sha256(sig).hexdigest() == v["signature_sha256"], \
            f"signature at turn {index}"
        assert sig[:32].hex() == v["signature_prefix"]
        assert wots.verify(sig, pub, index, msg, pk)


def test_a_vector_signature_is_the_documented_length():
    assert wots.SIGNATURE_BYTES == 67 * 32 == 2144


def test_the_scheme_is_named_in_the_chains_own_parameters():
    """So a build whose implementation answers to a different name refuses to
    produce leaves rather than producing ones nobody else's turns match."""
    assert HardeningParams().wots_scheme == wots.SCHEME
    try:
        HardeningParams(wots_scheme="rfc8391-xmss-wots+-sha256-w16")
    except ValueError as exc:
        assert "this build signs turns with" in str(exc)
    else:
        raise AssertionError("a foreign scheme was accepted silently")


def test_the_scheme_is_part_of_an_eras_identity():
    """A leaf is only a public key relative to a scheme, so two eras that agree
    on every number and disagree about the algorithm are not the same era."""
    import dataclasses

    era = new_era(0, b"seed" * 8, DEMO.tree_height, DEMO.turns)
    spec = era.spec
    other = dataclasses.replace(spec, scheme="rfc8391-xmss-wots+-sha256-w16")
    assert spec.digest() != other.digest()


def test_a_message_that_is_not_the_digest_is_refused():
    """The bug the vectors found. A short message produced a short signature —
    an object shaped like a signature that no verifier would ever accept, and
    nothing said why."""
    for bad in (b"", b"fin6", bytes(31), bytes(33)):
        try:
            wots.sign(b"s" * 32, b"p" * 32, 0, bad)
        except ValueError as exc:
            assert "32-byte digest" in str(exc)
        else:
            raise AssertionError(f"{len(bad)}-byte message was signed")


def test_a_turn_that_signs_twice_publishes_its_own_forgery_material():
    """Not new, and worth pinning next to the vectors: the one-time property is
    the mechanism here, not a hazard to engineer around."""
    seed, pub = b"s" * 32, b"p" * 32
    pk = wots.public_key(seed, pub, 7)
    a, b = bytes(32), bytes(range(32))
    sig_a, sig_b = (wots.sign(seed, pub, 7, m) for m in (a, b))
    assert wots.verify(sig_a, pub, 7, a, pk)
    assert wots.verify(sig_b, pub, 7, b, pk)
    assert sig_a != sig_b, "two messages, one key, two signatures anyone can see"
