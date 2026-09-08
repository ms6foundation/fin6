"""The following client: a wallet that will not report a balance it has not proved.

Part seven ended on an admission — `Client.sync` believes whatever a node says
about its own money.  This is the other kind of client.  It trusts the genesis
document and nothing else it is handed, and it declines to count a note it has
not seen a proof for.

What it checks, in the order it checks it:

    the tip header      is for this chain, and carries a quorum of signatures
                        from seats this chain's register knows
    the register        recomputes to the root the header commits, so the seat
                        set the certificate was checked against is not the
                        node's opinion of it
    ancestry            the tip descends from the header this client trusted
                        last time — one path, not a walk over every header in
                        between
    each note           is live under the tip's witness_root

Three of those are new roots or new questions; the fourth, ancestry, is the one
that makes an intermittently-connected wallet possible at all, because its cost
does not grow with how long the client was away.

What it does **not** check, and says so rather than implying otherwise:

  * that it was shown every output in a range.  Completeness has no commitment
    behind it yet (part eight §12), so scanning is still trusting.
  * that the register it verified is the one that was seated when the block was
    signed.  The roll of the epoch is applied before the root is taken, so the
    register under `registers_root` is one step ahead of the seats that signed.
    Membership is stable across a roll; standing is not, so the quorum this
    client computes can be off by one at a founding.
  * anything at all when two nodes disagree.  Weighing two tips is the
    adjudicating client, and it is next door in `client/adjudicate.py`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from chain.register import GridRegister
from chain.seal import leaf_value, verify_ancestry, verify_witness
from chain.tiered import registers_root


class LightError(Exception):
    pass


@dataclass
class Checked:
    """One note, and whether this client has seen it proved."""
    cm: str
    value: int
    height: int
    proved_at: int | None = None
    reason: str = "not checked"

    @property
    def proved(self) -> bool:
        return self.proved_at is not None


@dataclass
class Trusted:
    """What this client believes, and why it believes it."""
    height: int = 0
    tip: str = ""
    header: object = None
    witness_root: str = ""
    history_root: str = ""
    registers: dict = field(default_factory=dict)   # grid_id -> GridRegister
    checked_at: int = 0
    utxo_count: int = 0
    nf_count: int = 0

    def is_empty(self) -> bool:
        """Empty means *nothing trusted yet*, not "no header object".

        A client that saved its state and came back holds the height, the tip
        hash and the two roots — which is all the ancestry check needs, and is
        why a resumed client is 3 KB rather than a re-walk.
        """
        return not self.tip


class LightClient:
    """Follow the chain from a genesis document and a socket."""

    def __init__(self, doc, client, *, trusted: Trusted | None = None):
        self.doc = doc
        self.client = client
        self.chain_id = doc.chain_id
        self.trusted = trusted or Trusted()
        #: Node ids this chain has ever named.  The genesis roster seeds it and
        #: a verified register extends it; an attestation from anybody else is
        #: not a fault, it is noise, and it does not count towards a quorum.
        self.known = {n.node_id: n.public_hex for n in doc.nodes}
        #: How far a *checked* scan has got, and the counts the header at that
        #: height committed.  Kept apart from the wallet's own `scanned_to`,
        #: which advances on a scan nobody counted.
        self.scanned_to = 0
        self.scanned_counts = (0, 0)

    # ── the spine ────────────────────────────────────────────────────────────

    def follow(self) -> dict:
        """Take one step: fetch the tip, check it, and adopt it.

        Returns what was checked, so a caller can print it rather than take the
        client's word for it — which would be the same mistake one layer up.
        """
        answer = self.client.tip()
        header, cert = answer.get("header"), answer.get("cert")
        if header is None:
            raise LightError("the node offered no tip header")
        if header.chain_id != self.chain_id:
            raise LightError(f"that header is for {header.chain_id[:20]}…")

        registers = self._registers(header)
        ok, why = self._check_certificate(header, cert, registers)
        if not ok:
            raise LightError(f"tip at height {header.height}: {why}")

        steps = self._check_ancestry(header)

        self.trusted = Trusted(
            height=header.height, tip=header.hash(), header=header,
            witness_root=header.witness_root,
            history_root=header.history_root,
            registers=registers, checked_at=header.height,
            utxo_count=header.utxo_count, nf_count=header.nf_count)
        return {"height": header.height, "tip": header.hash(),
                "attestations": len(cert.attestations),
                "grids": len(registers), "ancestry": steps}

    def _registers(self, header) -> dict:
        """Fetch the registers and check them against the header's root.

        The node sends every grid's root and one grid's records.  The roots have
        to be recomputed together, because `registers_root` is over the whole
        set: a node that quietly dropped a grid would otherwise be indetectable.
        """
        answer = self.client.register()
        roots = {g: int(r) for g, r in answer["roots"].items()}
        if registers_root(roots) != header.registers_root:
            raise LightError("the registers do not recompute to the root the "
                             "header commits")
        dump = answer.get("dump")
        if dump is None:
            raise LightError(f"no register for {answer.get('grid_id')}")
        reg = GridRegister.load(dump)
        if reg.root() != roots.get(reg.grid_id):
            raise LightError(f"{reg.grid_id}: the records do not recompute to "
                             f"the root the set commits")
        return {reg.grid_id: reg}

    def _check_certificate(self, header, cert, registers):
        if cert is None:
            return False, "no certificate"
        if cert.block_hash != header.hash():
            return False, "the certificate is for another block"
        if cert.height != header.height or cert.chain_id != self.chain_id:
            return False, "the certificate is off-statement"
        seats, quorum = set(), 1
        for reg in registers.values():
            seats.update(reg.seated_members())
            quorum = max(quorum, reg.quorum())
        seen = set()
        for att in cert.attestations:
            if not att.verify():
                return False, f"bad signature from {att.node_id}"
            if (att.block_hash != cert.block_hash or att.height != cert.height
                    or att.chain_id != cert.chain_id
                    or att.epoch != cert.epoch):
                return False, f"{att.node_id} signed a different statement"
            if att.node_id in seen:
                return False, f"{att.node_id} attested twice"
            if att.node_id not in seats and att.node_id not in self.known:
                return False, f"{att.node_id} holds no seat on this chain"
            seen.add(att.node_id)
        if len(seen) < quorum:
            return False, f"{len(seen)} attestations, quorum is {quorum}"
        return True, "ok"

    def _check_ancestry(self, header) -> int:
        """Prove the new tip descends from the one this client already trusts.

        Constant work however long the client was offline, which is the whole
        point: the alternative is 232 bytes a header for every block missed.
        """
        old = self.trusted
        if old.is_empty() or old.height == 0:
            return 0
        if header.height == old.height:
            if header.hash() != old.tip:
                raise LightError("the node offers a different block at the "
                                 "height this client already trusts")
            return 0
        if header.height < old.height:
            raise LightError(f"the node is behind: {header.height} < "
                             f"{old.height}")
        answer = self.client.ancestry(old.height, under=header.height - 1)
        proof = answer.get("proof")
        if proof is None:
            raise LightError(f"no ancestry proof for height {old.height}")
        if not verify_ancestry(old.tip, proof, header.history_root):
            raise LightError(f"the tip at {header.height} does not descend "
                             f"from the block this client trusts at "
                             f"{old.height}")
        return header.height - old.height

    # ── the money ────────────────────────────────────────────────────────────

    def check_notes(self, wallet) -> list:
        """Ask for a proof of every note the wallet believes it holds.

        A note that fails here is not necessarily stolen — the commonest reason
        is that it was spent from another device — but a client that reported
        it as spendable would be repeating a claim it cannot support, which is
        exactly the habit this module exists to break.
        """
        if self.trusted.is_empty():
            raise LightError("follow the chain before checking notes")
        out = []
        for held in wallet.unspent():
            checked = Checked(cm=held.cm, value=held.value, height=held.height)
            answer = self.client.inclusion(held.cm)
            want = leaf_value("utxo", held.cm)
            if int(answer.get("height", -1)) > self.trusted.height:
                raise LightError(
                    f"the node has moved to height {answer['height']}; follow "
                    f"the chain again before checking notes against "
                    f"{self.trusted.height}")
            if not answer.get("live"):
                checked.reason = "the node has no live note at that commitment"
            elif answer.get("witness_root") != self.trusted.witness_root:
                checked.reason = ("the proof is against a root this client has "
                                  "not verified")
            elif answer.get("leaf") != want:
                # A spent note's leaf is the tombstone, and a tombstone path
                # opens perfectly well — to the wrong leaf.  Checking the path
                # without checking what it opens to would call a spent note
                # live, which is the one answer this client must never give.
                checked.reason = "the proof opens to a leaf that is not this note"
            elif not verify_witness(want, answer["proof"],
                                    self.trusted.witness_root):
                checked.reason = "the proof does not open to the trusted root"
            else:
                checked.proved_at = self.trusted.height
                checked.reason = "ok"
            out.append(checked)
        return out

    # ── being shown everything ───────────────────────────────────────────────

    def scan(self, wallet, limit: int | None = None) -> dict:
        """Scan up to the trusted tip, and check that nothing was left out.

        Verifying every output you were handed is not the same as having been
        handed every output, and until now nothing here could tell the
        difference: a node that quietly dropped one output made a payment
        disappear, and every check still passed.

        Two numbers in the header close it.  Positions are issued in order and
        never reused, so between the header this client last scanned to and the
        header it trusts now there are exactly `utxo_count` − `utxo_count`
        outputs, no more and no fewer.  Counting them is the whole check; the
        contiguity test below is what makes the count mean anything, because
        otherwise a node could pad a short answer with repeats.
        """
        if self.trusted.is_empty() or self.trusted.header is None:
            raise LightError("follow the chain before scanning it")
        tip = self.trusted
        since = self.scanned_to + 1 if self.scanned_to else 0
        want_out = tip.utxo_count - self.scanned_counts[0]
        want_nf = tip.nf_count - self.scanned_counts[1]

        outs, nfs, pages = [], [], 0
        while True:
            answer = self.client.outputs(since=since, to=tip.height,
                                         limit=limit)
            outs.extend(answer["outputs"])
            nfs.extend(answer["nullifiers"])
            pages += 1
            nxt = answer.get("next_from")
            if nxt is None or int(nxt) > tip.height:
                break
            since = int(nxt)

        ok, why = _spans(outs, self.scanned_counts[0], tip.utxo_count, "output")
        if not ok:
            raise LightError(why)
        ok, why = _spans(nfs, self.scanned_counts[1], tip.nf_count, "nullifier")
        if not ok:
            raise LightError(why)

        found = wallet.scan(tuple(map(tuple, outs)))
        spent = wallet.reconcile([row[1] for row in nfs], height=tip.height)
        self.scanned_to = tip.height
        self.scanned_counts = (tip.utxo_count, tip.nf_count)
        wallet.scanned_to = max(wallet.scanned_to, tip.height)
        return {"height": tip.height, "pages": pages, "found": found,
                "spent": spent, "outputs": len(outs), "nullifiers": len(nfs),
                "expected": (want_out, want_nf), "complete": True}

    def verified_balance(self, wallet):
        """(proved, unproved) — never one number, because that would hide the
        distinction this client exists to make."""
        checks = self.check_notes(wallet)
        proved = sum(c.value for c in checks if c.proved)
        unproved = sum(c.value for c in checks if not c.proved)
        return proved, unproved, checks

    # ── persistence ──────────────────────────────────────────────────────────

    def dump(self) -> dict:
        t = self.trusted
        return {"version": 1, "chain_id": self.chain_id, "height": t.height,
                "tip": t.tip, "witness_root": t.witness_root,
                "history_root": t.history_root,
                "utxo_count": t.utxo_count, "nf_count": t.nf_count,
                "scanned_to": self.scanned_to,
                "scanned_counts": list(self.scanned_counts)}

    def save(self, path):
        import json
        import os
        tmp = f"{path}.tmp"
        with open(tmp, "w") as fh:
            json.dump(self.dump(), fh, indent=2)
        os.replace(tmp, path)
        return path

    @classmethod
    def load(cls, path, doc, client) -> "LightClient":
        """Resume.  The saved state is four fields and no history."""
        import json
        import os
        out = cls(doc, client)
        if not os.path.exists(path):
            return out
        with open(path) as fh:
            raw = json.load(fh)
        if raw.get("chain_id") != doc.chain_id:
            raise LightError("that saved state is for another chain")
        out.trusted = Trusted(
            height=int(raw["height"]), tip=raw["tip"],
            witness_root=raw.get("witness_root", ""),
            history_root=raw.get("history_root", ""),
            utxo_count=int(raw.get("utxo_count", 0)),
            nf_count=int(raw.get("nf_count", 0)))
        out.scanned_to = int(raw.get("scanned_to", 0))
        out.scanned_counts = tuple(raw.get("scanned_counts", (0, 0)))
        return out

    def __repr__(self):
        t = self.trusted
        return (f"LightClient(h={t.height}, tip={t.tip[:14]}…)"
                if not t.is_empty() else "LightClient(following nothing yet)")


def _spans(rows, first: int, last: int, what: str):
    """Every position from `first` to `last`, once each, in order.

    Contiguity is not decoration.  Without it a node could answer a request for
    n rows with n copies of one row and the count would still add up.
    """
    want = last - first
    if len(rows) != want:
        return False, (f"the node served {len(rows)} {what}s for a range the "
                       f"headers say holds {want}")
    for i, row in enumerate(rows):
        pos = row[-1]
        if int(pos) != first + i:
            return False, (f"{what} positions are not contiguous: expected "
                           f"{first + i}, got {pos}")
    return True, "ok"
