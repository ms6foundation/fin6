"""The transport: a full mesh of TCP connections, and a mailbox.

Seven nodes is a mesh of twenty-one pairs, and each pair holds two
connections — one each way — because the grid reshuffles every epoch, so the
set of neighbours a node needs is not stable enough to be worth managing
connections around.  A node dials everyone once, keeps the dialled socket for
sending, and reads from whatever dialled it.  On a testnet that is the simplest
thing that works; the note for stage 6 is that this does not scale past a small
roster.

Everything arriving lands in one queue as `(peer_id, message)`.  A connection
that sends a malformed frame is closed rather than tolerated: `frame.py` is the
trust boundary and this is what it means operationally.
"""
from __future__ import annotations

import socket
import threading
import time

from . import handshake
from .frame import (CLIENT_KINDS, CLIENT_MAX_FRAME, MAX_FRAME,
                    FrameError, Reader, pack)

CONNECT_RETRY = 0.5
SOCKET_TIMEOUT = 1.0

#: How many hellos one connection may send.  Opening with one is what a
#: connection is *for*, so the first is free; a peer has no reason to send a
#: second, and a connection sending them in a stream is replaying handshakes.
#:
#: Not charged to the address-keyed client bucket, and that mattered more than
#: it looks: on a testnet every node dials from 127.0.0.1, so charging the
#: handshake there let peer reconnections drain the budget a wallet asks
#: questions out of — the same collision part eight split the keyspaces to
#: avoid, reintroduced for one kind.  Repeated hellos get their own keyspace,
#: and reconnecting for a fresh allowance is a connection-level cost, which is
#: stage 4's business.
MAX_HELLOS = 4


class Mesh:
    """Outbound dialling, inbound accepting, one inbox."""

    def __init__(self, node_id: str, chain_id: str, listen, peers: dict,
                 inbox, log=None, on_request=None, limiter=None,
                 signer=None, validators=None, epoch_now=None):
        self.node_id = node_id
        self.chain_id = chain_id
        self.host, self.port = listen
        self.peers = dict(peers)                 # peer_id -> (host, port)
        self.inbox = inbox
        self.log = log or (lambda *a: None)
        # Client requests are answered in the reader thread rather than through
        # the inbox, because a wallet asks while the node is asleep between
        # epochs — which is most of the time, and exactly when someone wants to
        # know whether it is alive.
        self.on_request = on_request
        self.limiter = limiter
        # Transport authentication.  Absent a signer and a roster this falls
        # back to the old behaviour of believing what a connection says about
        # itself, which is what the unit tests that build a bare Mesh want and
        # is never what a node wants.
        self.signer = signer
        self.epoch_now = epoch_now or (lambda: 0)
        self.handshake = (
            handshake.Verifier(chain_id, node_id, validators, self.epoch_now)
            if signer is not None and validators else None)
        self._last_refusal = ""
        self.out: dict = {}                      # peer_id -> socket we dialled
        self._locks: dict = {pid: threading.Lock() for pid in self.peers}
        self._stop = threading.Event()
        self._threads: list = []
        self._server = None

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(64)
        self._server.settimeout(SOCKET_TIMEOUT)
        self._spawn(self._accept_loop, "accept")
        for peer_id in sorted(self.peers):
            self._spawn(self._dial_loop, f"dial:{peer_id}", peer_id)
        return self

    def stop(self):
        self._stop.set()
        for sock in list(self.out.values()):
            _close(sock)
        if self._server is not None:
            _close(self._server)
        for thread in self._threads:
            thread.join(timeout=2)

    def _spawn(self, fn, name, *args):
        thread = threading.Thread(target=fn, args=args, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    # ── sending ──────────────────────────────────────────────────────────────

    def send(self, peer_id: str, kind: str, payload=None, *, epoch=-1) -> bool:
        sock = self.out.get(peer_id)
        if sock is None:
            return False
        try:
            blob = pack(kind, self.chain_id, payload, epoch=epoch)
        except FrameError as exc:
            self.log(f"refusing to send {kind}: {exc}")
            return False
        lock = self._locks.setdefault(peer_id, threading.Lock())
        with lock:
            try:
                sock.sendall(blob)
                return True
            except OSError:
                self.out.pop(peer_id, None)
                _close(sock)
                return False

    def broadcast(self, peer_ids, kind: str, payload=None, *, epoch=-1) -> int:
        return sum(self.send(pid, kind, payload, epoch=epoch)
                   for pid in peer_ids if pid != self.node_id)

    @property
    def connected(self):
        return sorted(self.out)

    # ── loops ────────────────────────────────────────────────────────────────

    def _dial_loop(self, peer_id: str):
        host, port = self.peers[peer_id]
        while not self._stop.is_set():
            if peer_id in self.out:
                time.sleep(CONNECT_RETRY)
                continue
            try:
                sock = socket.create_connection((host, port), timeout=2)
                sock.settimeout(None)
                sock.sendall(pack("hello", self.chain_id,
                                  self._hello_for(peer_id)))
                self.out[peer_id] = sock
                self.log(f"dialled {peer_id} at {host}:{port}")
            except OSError:
                time.sleep(CONNECT_RETRY)

    def _hello_for(self, peer_id: str) -> dict:
        """What this node says when it dials.  Signed when it can be."""
        if self.signer is None:
            return {"node_id": self.node_id}
        return handshake.build(self.signer, self.chain_id, self.node_id,
                               peer_id, self.epoch_now())

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._server.accept()
            except (socket.timeout, OSError):
                continue
            conn.settimeout(SOCKET_TIMEOUT)
            self._spawn(self._read_loop, "read", conn, addr)

    def _afford(self, source, kind: str, seated: bool, nbytes: int = 0) -> bool:
        if self.limiter is None:
            return True
        ok, why = self.limiter.check(source, kind, peer=seated, nbytes=nbytes)
        if not ok:
            self._last_refusal = why
        return ok

    def _greet(self, payload: dict, source: str):
        """Authenticate a hello, or refuse the connection.  Returns the peer id.

        Raises `FrameError` only when a hello claims a *roster* name and fails
        to prove it, which the read loop already treats as fatal: a connection
        that cannot prove the seat it claimed has no claim on the next frame.
        A hello naming anything else is a client's label — see
        `Verifier.claims_a_seat` — and is accepted and ignored.
        """
        if self.handshake is None:
            return payload.get("node_id")
        if not self.handshake.claims_a_seat(payload):
            # A wallet says hello as well, naming itself something that is not
            # in the roster.  Nothing to prove, nothing to gain: it stays on
            # the address-keyed budget and can never be seated.
            return None
        ok, why, who = self.handshake.check(payload)
        if not ok:
            raise FrameError(f"hello from {source}: {why}")
        return who

    def _read_loop(self, conn, addr=None):
        who = None
        hellos = 0
        # The bucket is keyed by host, not by host and port: a new connection
        # per request would otherwise buy a fresh budget every time, which is
        # the first thing anybody flooding a node would try.
        source = addr[0] if addr else "?"

        def gate(nbytes: int) -> bool:
            """Pay for the bytes before they are decoded.

            `who` is read live rather than captured: a connection starts
            unauthenticated and is promoted by its hello, and the tier decides
            both the budget and the ceiling.  This is the whole reason a
            per-tier ceiling is possible at all — whether a connection has
            proved a roster name is known before a byte of any body is parsed.
            """
            seated = who is not None and who in self.peers
            key = ("peer", who) if seated else ("client", source)
            return self._afford(key, "frame", seated, nbytes=nbytes)

        # An unauthenticated connection starts on the client ceiling.  8 MB is
        # for a block body and nothing a wallet sends is a block.
        reader = Reader(self.chain_id, max_frame=CLIENT_MAX_FRAME, gate=gate)
        try:
            while not self._stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                for msg in reader.feed(data):
                    if msg["kind"] == "hello":
                        # The first hello is what opening a connection means.
                        # Every one after it is metered, in its own keyspace,
                        # and a stream of them ends the connection: checking a
                        # hello is not free, and it used to be the one kind
                        # that reached `continue` before the limiter was ever
                        # consulted.
                        hellos += 1
                        if hellos > MAX_HELLOS:
                            raise FrameError(f"{hellos} hellos on one "
                                             f"connection")
                        if hellos > 1 and not self._afford(
                                ("hello", source), "hello", False):
                            continue
                        who = self._greet(msg["payload"] or {}, source)
                        # A proven peer may send a block, so it gets the real
                        # ceiling.  Nothing before the handshake could have.
                        if who is not None and who in self.peers:
                            reader.max_frame = MAX_FRAME
                        continue
                    seated = who is not None and who in self.peers
                    # Two keyspaces, not one.  On a testnet — and behind any
                    # shared address — a validator and a wallet arrive from the
                    # same host, and keying on the host alone let the
                    # validator's promotion hand its budget to everyone else
                    # dialling from there.  A peer is metered under the name it
                    # *proved*; everybody else under the address they came from.
                    #
                    # Proved is the word that changed in part nine.  While this
                    # was the name a connection merely claimed, a stranger
                    # could spend out of any validator's bucket and throttle it
                    # out of the ceremony.
                    key = ("peer", who) if seated else ("client", source)
                    if not self._afford(key, msg["kind"], seated):
                        if msg["kind"] in CLIENT_KINDS:
                            reply(conn, self.chain_id, "refused",
                                  {"kind": msg["kind"],
                                   "reason": self._last_refusal})
                        continue
                    if msg["kind"] in CLIENT_KINDS:
                        if self.on_request is not None:
                            answer = self.on_request(msg)
                            if answer is not None:
                                reply(conn, self.chain_id, answer[0], answer[1])
                        continue
                    self.inbox.put((who or "?", msg, None))
        except FrameError as exc:
            self.log(f"closing a connection from {who or 'a stranger'}: {exc}")
        finally:
            _close(conn)


def _close(sock):
    try:
        sock.close()
    except OSError:
        pass


def reply(conn, chain_id: str, kind: str, payload=None):
    """Answer a one-shot client (the CLI) on its own connection."""
    try:
        conn.sendall(pack(kind, chain_id, payload))
    except (OSError, FrameError):
        pass


def ask(host: str, port: int, chain_id: str, kind: str, payload=None,
        timeout=2.0):
    """One request, one reply, no connection kept.  Used by `fin6 net status`."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(pack(kind, chain_id, payload))
        reader = Reader(chain_id)
        sock.settimeout(timeout)
        while True:
            data = sock.recv(65536)
            if not data:
                return None
            for msg in reader.feed(data):
                return msg
