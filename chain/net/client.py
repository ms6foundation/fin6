"""What a wallet may ask a node.

A client is not a peer: it dials, asks one thing, and is answered on the same
connection.  Nothing here requires the node to trust the asker, and nothing
here lets the asker join a ceremony — a wallet is not a validator and never
becomes one.

What a client can verify for itself, and what it must take on trust, is worth
being exact about.  It can check that a note it decrypts really is the note the
commitment names, because it recomputes the commitment.  It cannot yet check
that the note is still unspent without holding the whole nullifier set, because
the accumulator's membership proofs are too large to serve — the design's open
item.  Until then a wallet believes what a node tells it about its own money,
which is why `sync` should be pointed at a node the user has a reason to trust,
or at several.
"""
from __future__ import annotations

import socket

from .frame import Reader, pack


class ClientError(Exception):
    pass


class Client:
    """One node, dialled per request."""

    def __init__(self, host: str, port: int, chain_id: str, timeout=5.0):
        self.host, self.port = host, int(port)
        self.chain_id = chain_id
        self.timeout = timeout

    # ── plumbing ─────────────────────────────────────────────────────────────

    def _ask(self, kind: str, payload=None, expect=None):
        try:
            with socket.create_connection((self.host, self.port),
                                          timeout=self.timeout) as sock:
                sock.sendall(pack(kind, self.chain_id, payload))
                sock.settimeout(self.timeout)
                reader = Reader(self.chain_id)
                while True:
                    data = sock.recv(1 << 16)
                    if not data:
                        raise ClientError(f"{self.host}:{self.port} closed "
                                          f"without answering {kind}")
                    for msg in reader.feed(data):
                        if expect and msg["kind"] != expect:
                            raise ClientError(f"expected {expect}, got "
                                              f"{msg['kind']}")
                        return msg["payload"]
        except OSError as exc:
            raise ClientError(f"{self.host}:{self.port}: {exc}") from None

    def _tell(self, kind: str, payload=None):
        try:
            with socket.create_connection((self.host, self.port),
                                          timeout=self.timeout) as sock:
                sock.sendall(pack("hello", self.chain_id,
                                  {"node_id": "fin6-client"}))
                sock.sendall(pack(kind, self.chain_id, payload))
        except OSError as exc:
            raise ClientError(f"{self.host}:{self.port}: {exc}") from None

    # ── the interface ────────────────────────────────────────────────────────

    def status(self) -> dict:
        return self._ask("status", expect="status_reply")

    def outputs(self, since: int = 0, to: int | None = None,
                limit: int | None = None) -> dict:
        """Commitments and sealed openings in a height range, plus the
        nullifiers published in it — the two things a wallet scans."""
        payload = {"from": int(since)}
        if to is not None:
            payload["to"] = int(to)
        if limit is not None:
            payload["limit"] = int(limit)
        return self._ask("getoutputs", payload, expect="outputs_reply")

    def txstatus(self, txid: str) -> dict:
        return self._ask("txstatus", {"txid": txid}, expect="txstatus_reply")

    # ── what a light client asks ─────────────────────────────────────────────

    def params(self) -> dict:
        """The genesis document.  Everything else is checked against this."""
        return self._ask("params", expect="params_reply")["genesis"]

    def tip(self) -> dict:
        """The tip header and the certificate that finalised it."""
        return self._ask("tip", expect="tip_reply")

    def headers(self, since: int = 1, to: int | None = None,
                limit: int | None = None) -> dict:
        payload = {"from": int(since)}
        if to is not None:
            payload["to"] = int(to)
        if limit is not None:
            payload["limit"] = int(limit)
        return self._ask("headers", payload, expect="headers_reply")

    def ancestry(self, height: int, under: int | None = None) -> dict:
        """A path showing the block at `height` is under a later header's spine."""
        payload = {"height": int(height)}
        if under is not None:
            payload["under"] = int(under)
        return self._ask("ancestry", payload, expect="ancestry_reply")

    def inclusion(self, cm: str) -> dict:
        """A proof that one note is live — the answer part seven could not give."""
        return self._ask("inclusion", {"cm": cm}, expect="inclusion_reply")

    def weight(self, since: int = 1, to: int | None = None,
               limit: int | None = None) -> dict:
        """Hardened blocks and the stamps behind them — the appeal court's
        evidence, and the only question here whose answer is *work*."""
        payload = {"from": int(since)}
        if to is not None:
            payload["to"] = int(to)
        if limit is not None:
            payload["limit"] = int(limit)
        return self._ask("weight", payload, expect="weight_reply")

    def tags(self, detect_secret: str, bits: int = 8, since: int = 0,
             to: int | None = None, limit: int | None = None) -> dict:
        """Ask a node to sort the chain's outputs for you.

        `bits` is the precision, and it is the whole trade: at 8 the node
        returns roughly one output in 256 plus all of yours, so the download
        falls by that factor and the node learns a set your outputs are hiding
        in.  Read `notes.detection_tag` before using this — what it bounds
        cryptographically and what it bounds only by the node's good behaviour
        are different things.
        """
        payload = {"detect": detect_secret, "bits": int(bits),
                   "from": int(since)}
        if to is not None:
            payload["to"] = int(to)
        if limit is not None:
            payload["limit"] = int(limit)
        return self._ask("tags", payload, expect="tags_reply")

    def scan_by_tag(self, wallet, bits: int = 8, since: int | None = None):
        """Scan with the node doing the sorting.  Returns what it cost."""
        start = wallet.scanned_to + 1 if since is None else int(since)
        answer = self.tags(wallet.keys.detection_secret(), bits=bits,
                           since=start)
        if answer.get("error"):
            raise ClientError(answer["error"])
        rows = tuple(map(tuple, answer["outputs"]))
        found = wallet.scan(rows)
        wallet.scanned_to = max(wallet.scanned_to, int(answer["height"]))
        scanned = int(answer["scanned"]) or 1
        return {"height": answer["height"], "found": found,
                "fetched": len(rows), "scanned": scanned,
                "reduction": scanned / max(1, len(rows)),
                "bits": answer["bits"]}

    def register(self, grid_id: str | None = None) -> dict:
        payload = {} if grid_id is None else {"grid_id": grid_id}
        return self._ask("register", payload, expect="register_reply")

    def submit(self, tx):
        """Hand a transaction to the network.

        Fire-and-forget by design at this stage: the node answers nothing, and
        a wallet finds out what happened by asking `txstatus`. That is honest
        rather than convenient — the transaction has to survive gossip, a
        grid's mempool and a ceremony before anything can be said about it.
        """
        self._tell("tx", {"tx": tx})
        return tx.txid

    # ── the wallet's side of it ──────────────────────────────────────────────

    def sync(self, wallet) -> dict:
        """Bring a wallet up to the node's tip: find money, then lose it.

        Scanning first and reconciling second matters. A note created and spent
        between two syncs must be seen before it is marked gone, or the wallet
        never learns it existed and cannot explain its own balance.
        """
        found, spent, pages = 0, 0, 0
        since = wallet.scanned_to + 1
        while True:
            answer = self.outputs(since=since)
            found += wallet.scan(tuple(map(tuple, answer["outputs"])))
            spent += wallet.reconcile([row[1] for row in answer["nullifiers"]])
            wallet.scanned_to = max(wallet.scanned_to, int(answer["height"]))
            pages += 1
            # A page ends on a height boundary and says where to resume, so a
            # wallet that stops here and comes back tomorrow is not missing the
            # second half of a block it thinks it has read.
            nxt = answer.get("next_from")
            if nxt is None:
                break
            since = int(nxt)
        return {"height": wallet.scanned_to, "found": found, "spent": spent,
                "pages": pages, "balance": wallet.balance()}
