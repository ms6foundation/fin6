"""What the handshake decides, and what it turned out not to decide.

Part nine authenticated the name a connection claims. These are the three
things it left behind, each one a test that fails on the code as it stood:

  * a peer message from a connection that never proved a seat was accepted
    and acted on — the handshake chose the *budget*, not who may take part;
  * a fault report was the one signed statement that did not name its chain,
    so it verified on any fin6 network;
  * the replay cache evicted nonces that were still inside the window, which
    is a replay window that can be emptied.
"""
import dataclasses
import os
import queue
import shutil
import socket
import tempfile
import time

from ..block import FaultReport
from ..crypto import Signer
from ..net import handshake
from ..net.frame import CLIENT_KINDS, KINDS, OPEN_KINDS, PEER_KINDS, pack
from ..net.peer import Mesh
from ..node import Node
from ..params import DEMO
from ..state import ChainState

CHAIN = "fin6:" + "ab" * 32
OTHER = "fin6:" + "cd" * 32


# ── who may say what ─────────────────────────────────────────────────────────

def test_the_two_sets_partition_every_kind():
    assert OPEN_KINDS | PEER_KINDS == set(KINDS)
    assert not (OPEN_KINDS & PEER_KINDS)


def test_a_wallet_can_still_say_everything_a_wallet_says():
    """The submission path is unauthenticated on purpose and metered instead."""
    assert CLIENT_KINDS <= OPEN_KINDS
    for kind in ("hello", "tx"):
        assert kind in OPEN_KINDS, kind


def test_the_ceremony_is_closed_to_strangers():
    """The four ingest paths that had no `who` check at all."""
    for kind in ("env", "block", "stamps", "getblock"):
        assert kind in PEER_KINDS, kind


# ── and the wire enforces it ─────────────────────────────────────────────────

VALIDATORS = {"v0": Signer.from_seed("v0").public_hex,
              "v1": Signer.from_seed("v1").public_hex}
EPOCH = 1


def _mesh(port, inbox):
    return Mesh("v0", CHAIN, ("127.0.0.1", port), {"v1": ("127.0.0.1", 1)},
                inbox, signer=Signer.from_seed("v0"), validators=VALIDATORS,
                epoch_now=lambda: EPOCH)


def _send(port, frames, hello=None, wait=0.45, signer=None):
    """Open a connection, optionally say hello, send frames.

    A hello from a seat opens a *session*, and every frame after it has to be
    signed for that session (review B6) — so a caller that says hello as a
    validator passes the signer too, exactly as a real node would.
    """
    sealer = None
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        if hello is not None:
            sock.sendall(pack("hello", CHAIN, hello))
            if signer is not None:
                sealer = handshake.Sealer(signer, handshake.session_id(
                    CHAIN, hello["node_id"], "v0", hello["epoch"],
                    hello["nonce"]))
        for kind, payload in frames:
            sock.sendall(pack(kind, CHAIN, payload, sealer=sealer))
        time.sleep(wait)


def _port():
    return 8100 + (os.getpid() % 40) * 4


def test_a_stranger_cannot_push_an_envelope_into_a_seat():
    """The gap: signatures meant nothing could be *forged*, and a stranger
    could still make a node spend verification time and evict from bounded
    caches the bodies it actually needed."""
    inbox, port = queue.Queue(), _port()
    mesh = _mesh(port, inbox)
    mesh.start()
    try:
        _send(port, [("env", {"proposals": [], "attestations": []}),
                     ("block", {"block": None}),
                     ("stamps", {"block_hash": "nb:00", "stamps": []})])
        assert inbox.empty(), \
            f"a stranger reached the inbox with {inbox.get_nowait()[1]['kind']}"
    finally:
        mesh.stop()


def test_a_wallet_is_unaffected():
    inbox, port = queue.Queue(), _port() + 1
    mesh = _mesh(port, inbox)
    mesh.start()
    try:
        _send(port, [("tx", {"tx": None})],
              hello={"node_id": "fin6-client"})
        who, msg, _ = inbox.get(timeout=2)
        assert msg["kind"] == "tx" and who == "?"
    finally:
        mesh.stop()


def test_a_peer_that_proved_its_seat_is_admitted():
    inbox, port = queue.Queue(), _port() + 2
    mesh = _mesh(port, inbox)
    mesh.start()
    try:
        hello = handshake.build(Signer.from_seed("v1"), CHAIN, "v1", "v0", EPOCH)
        _send(port, [("env", {"proposals": [], "attestations": []})],
              hello=hello, signer=Signer.from_seed("v1"))
        who, msg, _ = inbox.get(timeout=2)
        assert who == "v1" and msg["kind"] == "env"
    finally:
        mesh.stop()


def test_an_unproved_claim_to_a_seat_is_still_fatal():
    inbox, port = queue.Queue(), _port() + 3
    mesh = _mesh(port, inbox)
    mesh.start()
    try:
        _send(port, [("env", {})],
              hello={"node_id": "v1", "to": "v0", "epoch": 1,
                     "nonce": "00", "signature": "ff" * 64})
        assert inbox.empty()
        assert mesh.handshake.refused >= 1
    finally:
        mesh.stop()


# ── a fault report names its chain ───────────────────────────────────────────

def _reporter():
    state = ChainState(DEMO, chain_id=CHAIN)
    return Node("v0", Signer.from_seed("v0"), DEMO, state)


def test_a_fault_report_verifies_and_names_its_chain():
    report = _reporter().report("invalid_block", 3, 3, "did not apply")
    assert report.verify()
    assert report.chain_id == CHAIN


def test_a_fault_report_does_not_verify_on_another_chain():
    """Every other signed statement here binds the chain id. This one did not,
    so a complaint made on one network was a valid complaint on every other."""
    report = _reporter().report("invalid_block", 3, 3, "did not apply")
    moved = dataclasses.replace(report, chain_id=OTHER)
    assert not moved.verify()
    assert report.key() != moved.key(), "and it is a different complaint"


def test_the_signed_statement_still_covers_everything_it_did():
    report = _reporter().report("invalid_block", 3, 3, "did not apply")
    for field, value in (("reporter", "someone-else"), ("kind", "equivocation"),
                         ("height", 4), ("epoch", 9), ("detail", "other")):
        assert not dataclasses.replace(report, **{field: value}).verify(), field


# ── the replay window cannot be emptied ──────────────────────────────────────

def test_a_used_nonce_is_refused():
    keys = {"v1": Signer.from_seed("v1").public_hex}
    v = handshake.Verifier(CHAIN, "v0", keys, lambda: 5)
    hello = handshake.build(Signer.from_seed("v1"), CHAIN, "v1", "v0", 5)
    assert v.check(hello)[0]
    assert not v.check(hello)[0]


def test_a_full_window_refuses_rather_than_forgetting():
    """The cache used to evict by insertion order when every entry was still
    in the window — which turns the replay cache into a way to defeat it."""
    signer = Signer.from_seed("v1")
    keys = {"v1": signer.public_hex}
    epoch = 5
    v = handshake.Verifier(CHAIN, "v0", keys, lambda: epoch, max_seen=8)
    first = handshake.build(signer, CHAIN, "v1", "v0", epoch)
    assert v.check(first)[0]
    for i in range(1, 20):
        v.check(handshake.build(signer, CHAIN, "v1", "v0", epoch))
    ok, why, _ = v.check(first)
    assert not ok, "the first nonce was forgotten while still in the window"
    assert "already used" in why or "full" in why, why


def test_the_window_reopens_once_its_entries_age_out():
    signer = Signer.from_seed("v1")
    keys = {"v1": signer.public_hex}
    epoch = [5]
    v = handshake.Verifier(CHAIN, "v0", keys, lambda: epoch[0], max_seen=4)
    for _ in range(6):
        v.check(handshake.build(signer, CHAIN, "v1", "v0", epoch[0]))
    epoch[0] = 40
    ok, why, _ = v.check(handshake.build(signer, CHAIN, "v1", "v0", 40))
    assert ok, why
    assert v.stats()["nonces"] <= 4


def test_a_seat_this_node_does_not_dial_is_still_a_seat():
    """The roster authorises; `net.json` only says where to dial.

    These two were the same set for as long as every node's file named every
    other node, and the seated test was `who in self.peers` — the dial list.
    Peer discovery (review C6) makes them differ: a node may be handed one
    address and learn the rest, and until that moment a validator dialling
    *in* was treated as a stranger and refused for sending peer traffic, which
    is a partition that heals only if somebody edits a file.
    """
    inbox = queue.Queue()
    port = _port() + 3
    # A mesh that dials nobody at all: `v1` is a seat on the roster and not in
    # this node's peer list.
    mesh = Mesh("v0", CHAIN, ("127.0.0.1", port), {}, inbox,
                signer=Signer.from_seed("v0"), validators=VALIDATORS,
                epoch_now=lambda: EPOCH)
    mesh.start()
    try:
        hello = handshake.build(Signer.from_seed("v1"), CHAIN, "v1", "v0",
                                EPOCH)
        _send(port, [("env", {"epoch": 1})], hello=hello,
              signer=Signer.from_seed("v1"))
        kinds = []
        while not inbox.empty():
            kinds.append(inbox.get_nowait()[1]["kind"])
        assert "env" in kinds, "a proven seat was refused for not being dialled"
    finally:
        mesh.stop()


def test_a_stranger_is_still_a_stranger_when_the_dial_list_is_empty():
    """The other half: dropping the dial-list test must not drop the check."""
    inbox = queue.Queue()
    port = _port() + 4
    mesh = Mesh("v0", CHAIN, ("127.0.0.1", port), {}, inbox,
                signer=Signer.from_seed("v0"), validators=VALIDATORS,
                epoch_now=lambda: EPOCH)
    mesh.start()
    try:
        _send(port, [("env", {"epoch": 1})],
              hello={"node_id": "some-wallet"})
        kinds = []
        while not inbox.empty():
            kinds.append(inbox.get_nowait()[1]["kind"])
        assert "env" not in kinds
    finally:
        mesh.stop()
