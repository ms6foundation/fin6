"""Proving a name, and what used to happen without it.

The attack these tests are about is not forgery.  Nothing in the consensus
layer was ever forgeable — `Envelope.add_attestation` and `Seat._take_header`
both check the roster and verify signatures.  The attack was on the *meter*:
a peer's token bucket was keyed on the name a connection claimed in its hello,
so a stranger claiming `v3` spent out of `v3`'s budget until the real `v3`
found its own gossip refused and silently dropped.
"""
import queue
import socket
import time

from chain.crypto import Signer
from chain.net import handshake
from chain.net.frame import FrameError, Reader, pack
from chain.net.limits import COSTS, Limiter
from chain.net.peer import Mesh

CHAIN = "fin6:" + "ab" * 32
EPOCH = 7

SIGNERS = {n: Signer.from_seed(f"validator:{n}") for n in ("v1", "v2", "v3")}
VALIDATORS = {n: s.public_hex for n, s in SIGNERS.items()}


def _verifier(node_id="v1", epoch=EPOCH, **kw):
    return handshake.Verifier(CHAIN, node_id, VALIDATORS, lambda: epoch, **kw)


# ── the hello itself ─────────────────────────────────────────────────────────

def test_a_signed_hello_authenticates():
    v = _verifier()
    ok, why, who = v.check(handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1",
                                           EPOCH))
    assert ok and who == "v2", why


def test_an_unsigned_hello_is_refused():
    """What the old one looked like: a name and nothing else."""
    ok, why, who = _verifier().check({"node_id": "v2"})
    assert not ok and who is None, why


def test_a_forged_signature_is_refused():
    v = _verifier()
    payload = handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH)
    payload["signature"] = SIGNERS["v3"].sign(b"something else").replace(
        "0", "1", 1)
    ok, why, _ = v.check(payload)
    assert not ok and "did not sign" in why, why


def test_v3_cannot_be_impersonated_by_signing_as_itself():
    """The whole point: v2 has a roster key and still cannot become v3."""
    ok, why, _ = _verifier().check(
        {**handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH),
         "node_id": "v3"})
    assert not ok and "did not sign" in why, why


def test_a_name_that_is_not_in_the_roster_is_refused():
    ok, why, _ = _verifier().check(
        handshake.build(Signer.from_seed("nobody"), CHAIN, "v9", "v1", EPOCH))
    assert not ok and "not in the roster" in why, why


# ── what the signature has to cover ──────────────────────────────────────────

def test_a_hello_cannot_be_relayed_to_another_listener():
    """A signature for one listener is worthless at another, so an attacker
    cannot collect v2's hello to v1 and open a connection to v3 with it."""
    ok, why, _ = _verifier(node_id="v3").check(
        handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH))
    assert not ok and "addressed to" in why, why


def test_a_hello_cannot_be_replayed_onto_another_chain():
    other = "fin6:" + "cd" * 32
    ok, why, _ = _verifier().check(
        handshake.build(SIGNERS["v2"], other, "v2", "v1", EPOCH))
    assert not ok and "did not sign" in why, why


def test_a_hello_cannot_be_replayed_tomorrow():
    v = _verifier()
    ok, why, _ = v.check(handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1",
                                         EPOCH - 50))
    assert not ok and "epoch" in why, why


def test_a_hello_in_flight_across_an_epoch_boundary_is_accepted():
    v = _verifier()
    for epoch in (EPOCH - 1, EPOCH, EPOCH + 1):
        ok, why, _ = v.check(handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1",
                                             epoch))
        assert ok, (epoch, why)


def test_the_same_hello_twice_is_refused():
    v = _verifier()
    payload = handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH)
    assert v.check(payload)[0]
    ok, why, _ = v.check(payload)
    assert not ok and "nonce" in why, why


def test_reconnecting_honestly_is_not_a_replay():
    v = _verifier()
    for _ in range(5):
        assert v.check(handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1",
                                       EPOCH))[0]


# ── the order of the checks, and what depends on it ──────────────────────────

def test_the_cheap_checks_come_before_the_signature():
    """Refused for the reason a dictionary lookup found, not for the signature
    — so a flood of forged hellos costs lookups and not 74 µs apiece."""
    v = _verifier()
    stray = handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH)
    for change, expected in (({"node_id": "v9"}, "not in the roster"),
                             ({"to": "v8"}, "addressed to"),
                             ({"epoch": 900}, "epoch"),
                             ({"nonce": ""}, "no nonce")):
        ok, why, _ = v.check({**stray, **change, "signature": "00" * 64})
        assert not ok and expected in why, (change, why)


def test_a_guessed_nonce_cannot_lock_out_the_real_validator():
    """Nonces are recorded only once the signature has verified.  Recording
    them earlier would let anyone burn a validator's nonces by guessing —
    the same shape of mistake as refusing a transaction body because someone
    spliced a bad proof onto it."""
    v = _verifier()
    real = handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH)
    assert not v.check({**real, "signature": "00" * 64})[0]
    ok, why, who = v.check(real)                 # the honest one still works
    assert ok and who == "v2", why


def test_the_nonce_window_is_bounded():
    v = _verifier(max_seen=8)
    for i in range(40):
        v.check(handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH))
    assert len(v._seen) <= 8 + 1, len(v._seen)


def test_a_hello_is_metered_at_all():
    """It used to be the one kind that reached `continue` before the limiter
    was consulted, which made replaying it free."""
    assert "hello" in COSTS and COSTS["hello"] > 0


# ── over a real socket ───────────────────────────────────────────────────────

def _mesh(port, inbox, limiter):
    return Mesh("v1", CHAIN, ("127.0.0.1", port),
                # v2 is a peer this node would dial; the address is dead, which
                # only means the dial loop retries into nothing.
                {"v2": ("127.0.0.1", port + 1)}, inbox,
                limiter=limiter, signer=SIGNERS["v1"], validators=VALIDATORS,
                epoch_now=lambda: EPOCH)


def _speak(port, frames, wait=0.4):
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        for kind, payload in frames:
            sock.sendall(pack(kind, CHAIN, payload, epoch=EPOCH))
            time.sleep(0.05)
        time.sleep(wait)
    finally:
        sock.close()


def test_an_unauthenticated_claim_never_reaches_a_validators_bucket():
    """The squatting attack, and the fix.

    Claiming `v2` used to promote the caller onto v2's 2,000-token budget and,
    worse, made it *v2's* bucket — so the real v2 was throttled out of the
    ceremony by a stranger spending its tokens.  Now the claim is refused and
    the bucket is never created.
    """
    port = 7930
    inbox, limiter = queue.Queue(), Limiter()
    mesh = _mesh(port, inbox, limiter)
    mesh.start()
    try:
        _speak(port, [("hello", {"node_id": "v2"}),      # the old, bare hello
                      ("env", {"attestations": []})])
        assert ("peer", "v2") not in limiter._buckets, \
            "an unsigned claim reached v2's budget"
        assert inbox.empty(), "and its next frame was served anyway"
    finally:
        mesh.stop()


def test_an_authenticated_peer_does_reach_its_own_bucket():
    port = 7940
    inbox, limiter = queue.Queue(), Limiter()
    mesh = _mesh(port, inbox, limiter)
    mesh.start()
    try:
        hello = handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH)
        _speak(port, [("hello", hello), ("env", {"attestations": []})])
        assert ("peer", "v2") in limiter._buckets, "a proven name was refused"
        who, msg, _ = inbox.get(timeout=1)
        assert who == "v2" and msg["kind"] == "env"
    finally:
        mesh.stop()


def test_a_wallet_still_gets_served_without_any_hello():
    """A client never sends a hello and must not be caught by any of this."""
    port = 7950
    inbox, limiter = queue.Queue(), Limiter()
    answered = []
    mesh = _mesh(port, inbox, limiter)
    mesh.on_request = lambda msg: answered.append(msg["kind"]) or (
        "status_reply", {"ok": True})
    mesh.start()
    try:
        _speak(port, [("status", {})])
        assert answered == ["status"], answered
        assert ("client", "127.0.0.1") in limiter._buckets
        assert ("peer", "v2") not in limiter._buckets
    finally:
        mesh.stop()
