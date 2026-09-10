"""Who gets a socket, and for how long.

Everything part nine metered until now was a frame that had *arrived*. The
cheapest attack on a node was therefore to send nothing at all: an idle socket
is charged nothing by a meter that charges for frames, and it still cost a
thread, a buffer, and an entry in a list that was never pruned.
"""
import queue
import socket
import time

from chain.crypto import Signer
from chain.net import handshake
from chain.net.frame import pack
from chain.net.gate import (MAX_CONNECTIONS, MAX_PER_ADDRESS, Deadlines, Gate)
from chain.net.limits import Limiter
from chain.net.peer import Mesh

CHAIN = "fin6:" + "ab" * 32
EPOCH = 5
SIGNERS = {n: Signer.from_seed(f"validator:{n}") for n in ("v1", "v2")}
VALIDATORS = {n: s.public_hex for n, s in SIGNERS.items()}


# ── the counters ─────────────────────────────────────────────────────────────

def test_a_ceiling_exists_at_all():
    assert MAX_CONNECTIONS > 0 and MAX_PER_ADDRESS > 0
    assert MAX_PER_ADDRESS < MAX_CONNECTIONS, \
        "a per-address cap above the total cap is not a cap"


def test_one_address_cannot_hold_more_than_its_share():
    g = Gate(max_connections=100, max_per_address=2)
    assert g.admit("a")[0] and g.admit("a")[0]
    ok, why = g.admit("a")
    assert not ok and "already holds 2" in why, why
    assert g.admit("b")[0], "and it is per address, not global"


def test_the_total_ceiling_holds_across_addresses():
    g = Gate(max_connections=2, max_per_address=99)
    assert g.admit("a")[0] and g.admit("b")[0]
    ok, why = g.admit("c")
    assert not ok and "ceiling" in why, why


def test_releasing_gives_the_slot_back():
    g = Gate(max_connections=1, max_per_address=1)
    assert g.admit("a")[0]
    assert not g.admit("a")[0]
    g.release("a")
    assert g.admit("a")[0]
    assert g.stats()["open"] == 1


def test_releasing_something_never_admitted_is_harmless():
    g = Gate()
    g.release("nobody")
    assert g.stats()["open"] == 0


# ── the penalty box ──────────────────────────────────────────────────────────

def test_a_violation_costs_the_address_a_wait():
    """A `FrameError` disconnect used to cost one `connect()`, which the
    handshake made more relevant rather than less: failing authentication now
    closes the connection."""
    g = Gate(penalty_seconds=2.0)
    assert g.penalise("a", now=0.0) == 2.0
    ok, why = g.admit("a", now=0.5)
    assert not ok and "penalty box" in why, why
    assert g.admit("a", now=3.0)[0], "and it expires"


def test_the_wait_doubles_for_a_repeat_offender():
    """The first offence is usually a version skew or a half-finished client.
    The tenth is not."""
    g = Gate(penalty_seconds=1.0, penalty_max=8.0)
    waits = [g.penalise("a", now=0.0) for _ in range(5)]
    assert waits == [1.0, 2.0, 4.0, 8.0, 8.0], waits


def test_the_box_is_bounded_because_an_attacker_picks_its_keys():
    """Remembering offenders is state an attacker can grow by offending from
    many addresses, so the box is a cache with an eviction policy."""
    g = Gate(penalty_seconds=100.0, max_penalised=8)
    for i in range(50):
        g.penalise(f"a{i}", now=0.0)
    assert g.stats()["penalised"] <= 8


def test_expired_penalties_are_swept():
    g = Gate(penalty_seconds=1.0)
    g.penalise("a", now=0.0)
    g.penalise("b", now=100.0)          # the sweep runs on the way past
    assert not g.penalised("a", now=100.0)


# ── the two deadlines ────────────────────────────────────────────────────────

def test_silence_is_tolerated_up_to_the_idle_deadline():
    d = Deadlines(idle=10.0, partial=2.0, now=0.0)
    assert d.expired(now=9.0) == (False, "ok")
    done, why = d.expired(now=11.0)
    assert done and "idle" in why, why


def test_a_partial_frame_gets_a_shorter_rope_than_silence():
    """Holding a buffer against a promise is more suspicious than silence: a
    connection that announced 8 MB and then dribbled used to hold a worker
    until the process died."""
    d = Deadlines(idle=100.0, partial=2.0, now=0.0)
    d.saw_partial(now=0.0)
    assert d.expired(now=1.0) == (False, "ok")
    done, why = d.expired(now=3.0)
    assert done and "partial" in why, why


def test_completing_a_frame_clears_the_partial_clock():
    d = Deadlines(idle=100.0, partial=2.0, now=0.0)
    d.saw_partial(now=0.0)
    d.saw_frame(now=1.0)
    assert d.expired(now=5.0) == (False, "ok")


# ── over real sockets ────────────────────────────────────────────────────────

def _mesh(port, inbox, limiter, gate=None, **kw):
    return Mesh("v1", CHAIN, ("127.0.0.1", port), {"v2": ("127.0.0.1", 1)},
                inbox, limiter=limiter, gate=gate, signer=SIGNERS["v1"],
                validators=VALIDATORS, epoch_now=lambda: EPOCH, **kw)


def test_a_refused_connection_is_closed_at_once():
    port = 8210
    inbox = queue.Queue()
    gate = Gate(max_connections=100, max_per_address=2)
    mesh = _mesh(port, inbox, Limiter(), gate=gate)
    mesh.start()
    held = []
    try:
        for _ in range(2):
            held.append(socket.create_connection(("127.0.0.1", port),
                                                 timeout=2))
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", port), timeout=2)
        held.append(extra)
        time.sleep(0.3)
        # The listener accepted and dropped it, so the read returns EOF.
        extra.settimeout(2)
        assert extra.recv(16) == b"", "the refused connection stayed open"
        assert gate.stats()["refused"]["address"] >= 1
    finally:
        for sock in held:
            sock.close()
        mesh.stop()


def test_a_silent_connection_does_not_hold_a_worker_for_ever():
    port = 8220
    inbox = queue.Queue()
    mesh = _mesh(port, inbox, Limiter(), gate_idle=1.0, gate_partial=0.5)
    mesh.start()
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        sock.settimeout(6)
        assert sock.recv(16) == b"", "a silent socket was held indefinitely"
        assert mesh.gate.stats()["open"] == 0, "and the slot came back"
    finally:
        sock.close()
        mesh.stop()


def test_a_dribbled_frame_is_cut_off():
    port = 8230
    inbox = queue.Queue()
    mesh = _mesh(port, inbox, Limiter(), gate_idle=30.0, gate_partial=1.0)
    mesh.start()
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        # A header announcing a frame, and then nothing that finishes it.
        from chain.store import codec
        head = bytearray(b"F6")
        head.append(1)
        codec.put_uint(head, 4096)
        sock.sendall(bytes(head) + b"x" * 10)
        sock.settimeout(8)
        assert sock.recv(16) == b"", "a partial frame was held indefinitely"
    finally:
        sock.close()
        mesh.stop()


def test_a_malformed_frame_buys_a_wait_before_the_next_connection():
    port = 8240
    inbox = queue.Queue()
    gate = Gate(penalty_seconds=30.0)
    mesh = _mesh(port, inbox, Limiter(), gate=gate)
    mesh.start()
    try:
        bad = socket.create_connection(("127.0.0.1", port), timeout=2)
        bad.sendall(b"this is not a fin6 frame at all")
        time.sleep(0.4)
        bad.close()
        assert gate.penalised("127.0.0.1"), "no penalty for a bad frame"
        again = socket.create_connection(("127.0.0.1", port), timeout=2)
        again.settimeout(2)
        assert again.recv(16) == b"", "reconnecting was still free"
        again.close()
    finally:
        mesh.stop()


def test_an_authenticated_peer_is_unaffected_by_any_of_this():
    """The bounds are generous on purpose: the roster has to keep working."""
    port = 8250
    inbox = queue.Queue()
    mesh = _mesh(port, inbox, Limiter())
    mesh.start()
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        hello = handshake.build(SIGNERS["v2"], CHAIN, "v2", "v1", EPOCH)
        sock.sendall(pack("hello", CHAIN, hello, epoch=EPOCH))
        sock.sendall(pack("env", CHAIN, {"attestations": []}, epoch=EPOCH))
        who, msg, _ = inbox.get(timeout=2)
        assert who == "v2" and msg["kind"] == "env"
        assert not mesh.gate.penalised("127.0.0.1")
    finally:
        sock.close()
        mesh.stop()
