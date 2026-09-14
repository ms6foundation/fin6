"""Binding the stream, not just the first frame.

Review B6. The hello proves that whoever composed it holds the roster key it
names, and for a while nothing after it was bound to the same party: frames are
plaintext over TCP, so an attacker on the path could take a connection over
once the hello had passed and inherit the seat, the budget and the attribution.

The note in `handshake.py` said closing it needed a transport or a shared
secret to MAC with, and that the roster holds signing keys rather than
agreement keys. The first half was right and the conclusion was wrong: **a MAC
needs a shared secret, a signature does not.** The roster's Ed25519 keys sign
frames perfectly well — 25 µs to sign, 79 µs to verify, against 132 directed
messages in a 19.75-second epoch.

So every frame from a seated connection carries a sequence number and a
signature over the session its hello opened. These tests are about the four
things that closes, and the one it does not.
"""
import os
import queue
import socket
import time

from ..crypto import Signer
from ..net import handshake
from ..net.frame import Reader, pack, seal_of, sealed_digest
from ..net.peer import Mesh
from ..store import codec

CHAIN = "fin6:" + "ab" * 32
SIGNERS = {n: Signer.from_seed(n) for n in ("v0", "v1", "v2")}
VALIDATORS = {n: s.public_hex for n, s in SIGNERS.items()}
EPOCH = 7


def _session(from_id="v1", to_id="v0", epoch=EPOCH, nonce="n0"):
    return handshake.session_id(CHAIN, from_id, to_id, epoch, nonce)


def _sealed(sealer, kind="env", payload=None, epoch=EPOCH):
    raw = pack(kind, CHAIN, payload if payload is not None else {"a": 1},
               epoch=epoch, sealer=sealer)
    return list(Reader(CHAIN).feed(raw))[0]


# ── the session is derived, not exchanged ────────────────────────────────────

def test_both_ends_name_the_connection_the_same_way():
    """Nothing is exchanged to agree on a session: it is a function of the
    hello, which one side wrote and the other verified."""
    hello = handshake.build(SIGNERS["v1"], CHAIN, "v1", "v0", EPOCH)
    sender = handshake.session_id(CHAIN, "v1", "v0", hello["epoch"],
                                  hello["nonce"])
    receiver = handshake.session_id(CHAIN, hello["node_id"], "v0",
                                    hello["epoch"], hello["nonce"])
    assert sender == receiver


def test_a_session_is_this_connection_and_no_other():
    base = _session()
    assert base != _session(from_id="v2")
    assert base != _session(to_id="v2")
    assert base != _session(epoch=EPOCH + 1)
    assert base != _session(nonce="n1")


# ── what the seal closes ─────────────────────────────────────────────────────

def test_a_frame_in_sequence_verifies():
    sealer = handshake.Sealer(SIGNERS["v1"], _session())
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    for _ in range(3):
        ok, why = check.check(*seal_of(_sealed(sealer)))
        assert ok, why
    assert check.last_seq == 3


def test_a_replayed_frame_is_refused():
    """Injection's cheapest form: send the peer's own frame again."""
    sealer = handshake.Sealer(SIGNERS["v1"], _session())
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    msg = _sealed(sealer)
    assert check.check(*seal_of(msg))[0]
    ok, why = check.check(*seal_of(msg))
    assert not ok and "replayed or reordered" in why


def test_frames_out_of_order_are_refused():
    sealer = handshake.Sealer(SIGNERS["v1"], _session())
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    first, second = _sealed(sealer), _sealed(sealer)
    assert check.check(*seal_of(second))[0]
    assert not check.check(*seal_of(first))[0]


def test_a_dropped_frame_does_not_kill_the_connection():
    """Strictly increasing rather than exactly-one-more: a gap means the path
    dropped something, which is a denial of service and not a forgery, and
    refusing everything after it would turn one lost packet into a dead seat."""
    sealer = handshake.Sealer(SIGNERS["v1"], _session())
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    _sealed(sealer)                                  # lost on the way
    ok, why = check.check(*seal_of(_sealed(sealer)))
    assert ok, why


def test_an_edited_frame_is_refused():
    """The signature is over the frame, so changing a byte of the payload
    breaks it — which is what a path attacker would want to do."""
    sealer = handshake.Sealer(SIGNERS["v1"], _session())
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    msg = _sealed(sealer, payload={"attestations": []})
    msg["payload"] = {"attestations": ["forged"]}
    ok, why = check.check(*seal_of(msg))
    assert not ok and "does not verify" in why


def test_a_frame_from_another_session_is_worthless_here():
    """Takeover, the interesting case: an attacker with a recording of another
    connection cannot splice it into this one."""
    elsewhere = handshake.Sealer(SIGNERS["v1"], _session(nonce="other"))
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    ok, why = check.check(*seal_of(_sealed(elsewhere)))
    assert not ok and "does not verify" in why


def test_a_frame_signed_by_the_wrong_key_is_refused():
    sealer = handshake.Sealer(SIGNERS["v2"], _session())
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    assert not check.check(*seal_of(_sealed(sealer)))[0]


def test_a_frame_with_no_seal_at_all_is_refused():
    check = handshake.SealCheck(_session(), VALIDATORS["v1"])
    bare = list(Reader(CHAIN).feed(pack("env", CHAIN, {"a": 1})))[0]
    ok, why = check.check(*seal_of(bare))
    assert not ok and "sequence number" in why


def test_the_digest_is_over_everything_but_the_signature():
    """So a receiver checks exactly the bytes the sender signed, which the
    canonical codec is what makes possible."""
    sealer = handshake.Sealer(SIGNERS["v1"], _session())
    msg = _sealed(sealer)
    unsigned = {k: v for k, v in msg.items() if k != "sig"}
    assert seal_of(msg)[2] == sealed_digest(codec.encode(unsigned))


# ── and on a socket ──────────────────────────────────────────────────────────

def _port():
    return 8500 + (os.getpid() % 30) * 4


def _mesh(port, inbox):
    return Mesh("v0", CHAIN, ("127.0.0.1", port), {}, inbox,
                signer=SIGNERS["v0"], validators=VALIDATORS,
                epoch_now=lambda: EPOCH)


def test_a_seated_connection_that_stops_sealing_is_hung_up_on():
    """The scenario B6 is about, on a real socket: the hello passes, and then
    somebody else writes into the stream."""
    inbox, port = queue.Queue(), _port()
    mesh = _mesh(port, inbox)
    mesh.start()
    try:
        hello = handshake.build(SIGNERS["v1"], CHAIN, "v1", "v0", EPOCH)
        sealer = handshake.Sealer(SIGNERS["v1"], handshake.session_id(
            CHAIN, "v1", "v0", EPOCH, hello["nonce"]))
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            sock.sendall(pack("hello", CHAIN, hello, epoch=EPOCH))
            sock.sendall(pack("env", CHAIN, {"a": 1}, epoch=EPOCH,
                              sealer=sealer))
            time.sleep(0.4)
            who, msg, _ = inbox.get(timeout=2)
            assert who == "v1" and msg["kind"] == "env"
            # Now the hijack: a frame nobody signed for this session.
            sock.sendall(pack("env", CHAIN, {"a": 2}, epoch=EPOCH))
            time.sleep(0.4)
            assert inbox.empty(), "an unsealed frame reached the node"
            assert mesh.unsealed >= 1
        finally:
            sock.close()
    finally:
        mesh.stop()


def test_a_wallet_needs_none_of_this():
    """A client has no roster key and its frames are metered rather than
    authenticated; sealing must not have quietly become a requirement for
    talking to a node at all."""
    inbox, port = queue.Queue(), _port() + 1
    answered = []
    mesh = Mesh("v0", CHAIN, ("127.0.0.1", port), {}, inbox,
                signer=SIGNERS["v0"], validators=VALIDATORS,
                epoch_now=lambda: EPOCH)
    mesh.on_request = lambda msg: answered.append(msg["kind"]) or (
        "status_reply", {"ok": True})
    mesh.start()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            sock.sendall(pack("hello", CHAIN, {"node_id": "a-wallet"}))
            sock.sendall(pack("status", CHAIN, None))
            time.sleep(0.4)
        finally:
            sock.close()
        assert "status" in answered, answered
    finally:
        mesh.stop()
