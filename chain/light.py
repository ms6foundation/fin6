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
    adjudicating client, and it is not built.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import h_bytes
from .hardening.history import HardenedBlock, NetworkHistory
from .hardening.pool import EraSpec
from .register import GridRegister
from .seal import leaf_value, verify_ancestry, verify_witness
from .tiered import registers_root


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


# ═══════════════════════════════════════════════════════════════════════════════
# The adjudicating client
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Branch:
    """One node's claim about history, after the client has checked it."""
    source: str
    tip: str = ""
    height: int = 0
    cumulative: int = 0
    blocks: int = 0
    stamps: int = 0
    ok: bool = False
    reason: str = "not examined"

    def __repr__(self):
        return (f"Branch({self.source}, h={self.height}, "
                f"weight={self.cumulative:,}, "
                f"{'ok' if self.ok else self.reason})")


class Adjudicator:
    """Convened when two nodes disagree, and not before.

    A following client trusts the validator register — which works right up to
    the moment the register is the thing being lied about.  Two nodes hand back
    two tips, each with a certificate from a different seat set, and signatures
    cannot settle it because both sets sign honestly by their own lights.

    Only work can, and the arithmetic here is unusually clean.  A branch that
    reuses a turn already spent on its own history is invalid outright and
    turns are consumed per branch, so an attacker cannot re-cast what the
    honest chain burned; it can only spend its own, which puts a ceiling on how
    deep it can ever reach:

        max fork depth = attacker's unspent turns / width

    That is a bound, not a probability, and it is computable — which is what
    lets `settled_depth` answer "how many blocks until this payment cannot be
    unsaid" with a number rather than a convention.

    This client verifies rather than tallies.  It rebuilds each branch in its
    own `NetworkHistory` and re-runs every check: that the committee is the one
    the draw produces, that each stamp solves its puzzle and opens to the era
    root, that no turn is spent twice on a branch, and that the weight claimed
    is the weight of the stamps present.  A node's `cumulative` field is never
    read as evidence; it is only compared against what the client computed, and
    a disagreement is reported rather than resolved.
    """

    def __init__(self, doc, *, era_spec: EraSpec | None = None):
        self.doc = doc
        self.params = doc.hardening_params()
        self.spec = era_spec or self.derive_spec(doc)

    @staticmethod
    def derive_spec(doc) -> EraSpec:
        """Rebuild era 0 from the genesis document.

        Deriving it means holding the master seed, which in this dev model
        every node does — the README's "distribution is the security parameter"
        caveat, in the one place a reader will trip over it.  A deployment
        publishes the era root in the genesis document and derives nothing; the
        client code below does not care which, because all it uses is the spec.
        """
        from .hardening.pool import Era
        hp = doc.hardening_params()
        return Era(0, h_bytes("era-seed", doc.digest()),
                   hp.tree_height, hp.turns).spec

    # ── one branch ───────────────────────────────────────────────────────────

    def examine(self, client, name: str | None = None) -> Branch:
        """Fetch a node's hardened chain and check every block of it."""
        source = name or f"{client.host}:{client.port}"
        branch = Branch(source=source)
        try:
            answer = client.weight(since=1)
        except Exception as exc:
            branch.reason = f"could not be asked: {exc}"
            return branch
        era = answer.get("era") or {}
        if era.get("root") != self.spec.root.hex():
            branch.reason = "that node is hardening under another era"
            return branch

        history = NetworkHistory(self.spec, self.params)
        for row in answer.get("blocks", []):
            hb = HardenedBlock(
                block_hash=row["block_hash"], height=int(row["height"]),
                prev_hash=row["prev"], era_id=int(row["era_id"]),
                drawn=tuple(int(t) for t in row["drawn"]),
                stamps=tuple(row["stamps"]),
                weight=int(row["weight"]), cumulative=int(row["cumulative"]),
                spent_root=int(row["spent_root"]))
            ok, why = history.accept(hb)
            if not ok:
                branch.reason = f"height {hb.height}: {why}"
                branch.blocks = len(history.blocks)
                return branch
            branch.stamps += len(hb.stamps)
        if not history.blocks:
            branch.reason = "that node has hardened nothing"
            return branch
        branch.ok = True
        branch.reason = "ok"
        branch.tip = history.tip_hash
        branch.height = history.height
        branch.cumulative = history.cumulative_weight
        branch.blocks = len(history.blocks)
        return branch

    # ── two of them ──────────────────────────────────────────────────────────

    def weigh(self, sources: dict) -> dict:
        """{name: client} -> what the work says.

        Returns every branch it examined, whether they agree, and which one
        wins if they do not.  It does not adopt anything: choosing is the
        caller's, and a client that silently switched chains on the strength of
        a fork-choice rule would be doing the one thing this whole module
        exists to avoid.
        """
        branches = [self.examine(c, name=n) for n, c in sorted(sources.items())]
        good = [b for b in branches if b.ok]
        if not good:
            return {"decision": "no branch could be verified",
                    "branches": branches, "agree": False, "winner": None}
        tips = {b.tip for b in good}
        if len(tips) == 1:
            return {"decision": "the sources agree", "branches": branches,
                    "agree": True, "winner": good[0].tip,
                    "cumulative": max(b.cumulative for b in good)}
        best = max(good, key=lambda b: (b.cumulative, b.height, b.tip))
        rivals = [b for b in good if b.tip != best.tip]
        margin = best.cumulative - max(b.cumulative for b in rivals)
        return {
            "decision": f"{best.source} carries the most work",
            "branches": branches, "agree": False, "winner": best.tip,
            "winner_source": best.source, "cumulative": best.cumulative,
            "margin": margin,
            "margin_blocks": margin // max(1, self.params.stamp_weight
                                           * self.params.threshold),
        }

    # ── how deep is settled ──────────────────────────────────────────────────

    def settled_depth(self, attacker_share: float = 1 / 3) -> int:
        """How deep a rewrite could reach, for an attacker holding this share.

        The number a wallet should show instead of a spinner.  It is a bound,
        not a probability: below this depth a payment can still be unsaid, and
        above it there are not enough unspent turns in the pool to reach it.
        """
        return self.params.max_fork_depth(attacker_share)

    def is_settled(self, confirmations: int,
                   attacker_share: float = 1 / 3) -> bool:
        return confirmations > self.settled_depth(attacker_share)

    def __repr__(self):
        return (f"Adjudicator(era {self.spec.era_id}, "
                f"{self.params.turns:,} turns, width {self.params.width})")
