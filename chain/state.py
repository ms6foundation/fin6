"""Ledger state: the UTXO accumulator, the nullifier accumulator, and the
rules for moving state forward.

Both accumulators are ms6 seal trees over deterministic leaves (see chain/seal.py
for why they are not ms6.Commitment objects).
"""
from __future__ import annotations

from dataclasses import dataclass

from .crypto import h_hex
from .locality import tx_partition
from .params import ChainParams
from .seal import HeaderHistory, SealAccumulator
from .transaction import Transaction, verify_transaction

# ═══════════════════════════════════════════════════════════════════════════════
# ChainState
# ═══════════════════════════════════════════════════════════════════════════════


class LedgerInconsistent(Exception):
    """The ledger's two records of a spend disagree.

    Not a validation failure — a validation failure is somebody else's block
    being wrong, and this is *this* state being wrong. It cannot be recovered
    from locally, because there is no way to tell which of the two records is
    the true one; the fix is a resync from a node that agrees with the network
    (review B5, `ChainState.cross_check`).
    """

@dataclass
class ApplyResult:
    ok: bool
    reason: str = "ok"
    fees: int = 0


@dataclass(frozen=True)
class UtxoDelta:
    """What one grid's ceremony does to the ledger.

    A local grid cannot compute utxo_root: it does not know what the other grids
    spent this epoch, so it has no idea what the global set will look like.  All
    it can honestly commit to is a delta against the last finalised state.  The
    roots are computed once, at the supreme tier, by applying every surviving
    delta in canonical order.
    """
    spent: tuple = ()          # input note commitments consumed
    created: tuple = ()        # output note commitments
    nullifiers: tuple = ()
    fees: int = 0

    @classmethod
    def from_txs(cls, txs) -> "UtxoDelta":
        spent, created, nfs, fees = [], [], [], 0
        for tx in txs:
            spent.extend(tx.input_cms)
            created.extend(tx.output_cms)
            nfs.extend(tx.nullifiers)
            fees += tx.fee
        return cls(tuple(spent), tuple(created), tuple(nfs), fees)

    def digest(self) -> str:
        return h_hex("utxo-delta", list(self.spent), list(self.created),
                     list(self.nullifiers), self.fees)

    def is_empty(self) -> bool:
        return not (self.spent or self.created or self.nullifiers)

    def __repr__(self):
        return (f"UtxoDelta(-{len(self.spent)} +{len(self.created)}, "
                f"{len(self.nullifiers)} nf, fees={self.fees})")


def merge_deltas(deltas):
    """Fold sibling deltas into one, dropping any that collide.

    Partitioning should make collisions impossible — a note can only be spendable
    in the grid that owns its nullifier — but partition compliance is a rule a
    Byzantine leader can break, so the merge tier still checks.  The partition is
    the design; this is the enforcement.

    Returns (merged, [(index, reason)]).  Order is the caller's canonical order,
    so every node drops the same ones.
    """
    spent, created, nfs, fees = [], [], [], 0
    seen_spent, seen_created, seen_nf = set(), set(), set()
    dropped = []
    for i, d in enumerate(deltas):
        clash = (set(d.spent) & seen_spent) or (set(d.nullifiers) & seen_nf) \
            or (set(d.created) & seen_created)
        if clash:
            dropped.append((i, f"collides on {sorted(clash)[0][:14]}…"))
            continue
        if len(set(d.spent)) != len(d.spent) or len(set(d.nullifiers)) != len(d.nullifiers):
            dropped.append((i, "delta conflicts with itself"))
            continue
        spent.extend(d.spent); created.extend(d.created); nfs.extend(d.nullifiers)
        fees += d.fees
        seen_spent.update(d.spent); seen_created.update(d.created); seen_nf.update(d.nullifiers)
    return UtxoDelta(tuple(spent), tuple(created), tuple(nfs), fees), dropped


class ChainState:
    """The full validating state of one node.

    Fees are burned: a transaction's fee leaves circulation rather than being
    paid to the leader.  Paying it out would need an extra output note minted
    inside the block, which the sum row would have to account for; left as a
    deliberate simplification.
    """

    def __init__(self, params: ChainParams, chain_id: str | None = None):
        self.params = params
        self.chain_id = chain_id or params.chain_id
        self.utxo = SealAccumulator("utxo", d=params.seal_d)
        self.nullifiers = SealAccumulator("nf", d=params.seal_d)
        self.history = HeaderHistory()
        self.height = -1
        self.tip = "genesis"
        self.burned_fees = 0

    def cross_check(self) -> tuple:
        """The two records of one fact, compared.  (ok, reason)

        Review B5 asked whether the nullifier set needs to exist. Its
        double-spend job is already done by the UTXO set: this chain's spend
        graph is public, so a replay names the same commitment and
        `cm not in self.utxo` refuses it before a nullifier is looked at. That
        is the confidential-transactions model, not the Zcash one, and under it
        the nullifier is a second record of something the first record already
        knows.

        The decision — measured and written up in docs/nullifier_decision.md —
        is to keep it and make the redundancy earn its keep, because a second
        *independent* record of every spend is worth more than the 0.3% of a
        proof it costs. This is what earns it: a spend tombstones a leaf in one
        structure and appends to the other, so

            utxo.spent_count == nullifiers.size

        at every height, for ever. Two integers. If they ever disagree, a note
        was spent without publishing a nullifier or a nullifier appeared for a
        note nobody spent — either way the ledger has lost track of a spend,
        which is the one thing it exists to keep track of.
        """
        spent, published = self.utxo.spent_count, self.nullifiers.size
        if spent != published:
            return False, (f"{spent} notes are spent and {published} "
                           f"nullifiers are published: the ledger's two "
                           f"records of a spend disagree")
        return True, "ok"

    def record_block(self, height: int, block_hash: str):
        """Move the tip, and put the block into the spine.

        The spine is what makes a client's ancestry check one path instead of a
        walk, and it has to be part of the state every node keeps rather than an
        index some nodes happen to build — the root of it is in the header.
        """
        if len(self.history) != height - 1:
            raise ValueError(f"spine holds {len(self.history)} blocks; cannot "
                             f"record height {height}")
        self.history.append(block_hash)
        self.height = height
        self.tip = block_hash

    # ── issuance (genesis only) ──────────────────────────────────────────────

    def issue(self, cm: str):
        """Put a note into circulation outside any transaction.

        Only legitimate at genesis, and what stands behind it depends on the
        document.  An *issued* supply is trusted outright: nothing proves the
        value is in range or that anyone authorised it.  A *minted* one is not
        — the commitments come with a proof that they sum to the declared
        total and each lies in range, and the founders' ratifications are what
        authorise the total (chain/mint.py).  This method is the same either
        way; the difference is whether a reader had to take the supply on
        trust.
        """
        if self.height >= 0:
            raise ValueError("issuance is only allowed in the genesis state")
        self.utxo.add(cm)

    # ── transactions ─────────────────────────────────────────────────────────

    def check_transaction(self, tx: Transaction, *, verify_proof: bool = True,
                          seen_nf: set | None = None,
                          seen_cm: set | None = None,
                          backend: str | None = None):
        """Validate one transaction against this state.

        seen_nf / seen_cm let a caller thread the within-block view through, so
        two transactions in the same block cannot spend the same note.
        """
        if verify_proof:
            ok, why = verify_transaction(tx, self.params, chain_id=self.chain_id,
                                         backend=backend)
            if not ok:
                return False, why
        else:
            ok, why = True, "ok"

        for tin in tx.inputs:
            if tin.cm not in self.utxo:
                return False, f"input {tin.cm[:14]}… is not an unspent note"
            if seen_cm is not None and tin.cm in seen_cm:
                return False, f"input {tin.cm[:14]}… spent twice in one block"
        for nf in tx.nullifiers:
            if nf in self.nullifiers:
                return False, f"double spend: {nf[:14]}… already published"
            if seen_nf is not None and nf in seen_nf:
                return False, f"double spend: {nf[:14]}… twice in one block"
        for cm in tx.output_cms:
            if self.utxo.ever_contained(cm):
                return False, f"output {cm[:14]}… already exists"
        return True, "ok"

    def apply_transaction(self, tx: Transaction):
        """Mutate state.  Caller must have checked first."""
        for tin in tx.inputs:
            self.utxo.spend(tin.cm)
        for nf in tx.nullifiers:
            self.nullifiers.add(nf)
        for cm in tx.output_cms:
            self.utxo.add(cm)
        self.burned_fees += tx.fee

    # ── blocks ───────────────────────────────────────────────────────────────

    def check_block(self, block, *, already_verified=None):
        """Speculatively apply `block` to a clone and compare the roots.

        already_verified(tx) -> bool lets a node skip re-checking a proof it
        already checked at mempool admission, so a proof costs one verification
        per node per transaction rather than one per node per block.  It must
        key on the proof as well as the transaction id, since the id binds the
        body but not the proof bytes.
        """
        h = block.header
        if h.chain_id != self.chain_id:
            return False, f"wrong chain {h.chain_id!r}"
        if h.height != self.height + 1:
            return False, f"height {h.height} does not follow {self.height}"
        if h.prev_hash != self.tip:
            return False, f"prev_hash {h.prev_hash[:14]}… does not follow the tip"
        if h.tx_root != block.compute_tx_root():
            return False, "tx_root does not match the transaction list"
        if len(set(tx.txid for tx in block.transactions)) != len(block.transactions):
            return False, "duplicate transaction in block"

        shadow = self.copy()
        seen_nf, seen_cm = set(), set()
        for tx in block.transactions:
            verify_proof = not (already_verified and already_verified(tx))
            ok, why = shadow.check_transaction(tx, verify_proof=verify_proof,
                                               seen_nf=seen_nf, seen_cm=seen_cm)
            if not ok:
                return False, f"{tx.txid[:14]}…: {why}"
            seen_nf.update(tx.nullifiers)
            seen_cm.update(tx.input_cms)
            shadow.apply_transaction(tx)

        if shadow.utxo.root != h.utxo_root:
            return False, "utxo_root does not match the applied block"
        if shadow.nullifiers.root != h.nf_root:
            return False, "nf_root does not match the applied block"
        return True, "ok"

    def apply_block(self, block):
        for tx in block.transactions:
            self.apply_transaction(tx)
        ok, why = self.cross_check()
        if not ok:
            raise LedgerInconsistent(why)
        self.height = block.header.height
        self.tip = block.header.hash()
        return ApplyResult(True, "ok", sum(tx.fee for tx in block.transactions))

    # ── tiered path: per-grid deltas ─────────────────────────────────────────

    def check_ceremony_txs(self, txs, partition: int, n_partitions: int, *,
                           already_verified=None, backend: str | None = None):
        """Validate one grid's transaction set against the last finalised state.

        No shadow application here: a delta is measured against the last network
        block, not against its own partial effects, so within-set conflicts are
        caught by the seen_* sets instead.

        Returns (ok, reason, delta).
        """
        seen_nf, seen_cm, seen_out = set(), set(), set()
        for tx in txs:
            part = tx_partition(tx, n_partitions)
            if part is None:
                return False, (f"{tx.txid[:14]}…: inputs span partitions; no "
                               f"grid may include it"), None
            if part != partition:
                return False, (f"{tx.txid[:14]}…: belongs to partition {part}, "
                               f"not {partition}"), None
            verify_proof = not (already_verified and already_verified(tx))
            ok, why = self.check_transaction(tx, verify_proof=verify_proof,
                                             seen_nf=seen_nf, seen_cm=seen_cm,
                                             backend=backend)
            if not ok:
                return False, f"{tx.txid[:14]}…: {why}", None
            for cm in tx.output_cms:
                if cm in seen_out:
                    return False, f"{tx.txid[:14]}…: duplicate output", None
            seen_nf.update(tx.nullifiers)
            seen_cm.update(tx.input_cms)
            seen_out.update(tx.output_cms)
        return True, "ok", UtxoDelta.from_txs(txs)

    def apply_delta(self, delta: UtxoDelta):
        for cm in delta.spent:
            self.utxo.spend(cm)
        for nf in delta.nullifiers:
            self.nullifiers.add(nf)
        for cm in delta.created:
            self.utxo.add(cm)
        self.burned_fees += delta.fees
        ok, why = self.cross_check()
        if not ok:
            # Two integers, checked on the path that moves them.  A ledger
            # whose own two records of a spend disagree cannot be reasoned
            # about, and carrying on would mean computing roots nobody else
            # will reproduce — the same fail-stop discipline as a protocol
            # version this build cannot run.
            raise LedgerInconsistent(why)

    def can_apply_delta(self, delta: UtxoDelta):
        for cm in delta.spent:
            if cm not in self.utxo:
                return False, f"{cm[:14]}… is not an unspent note"
        for nf in delta.nullifiers:
            if nf in self.nullifiers:
                return False, f"nullifier {nf[:14]}… already published"
        for cm in delta.created:
            if self.utxo.ever_contained(cm):
                return False, f"output {cm[:14]}… already exists"
        return True, "ok"

    # ── persistence ──────────────────────────────────────────────────────────

    def dump(self):
        """Everything a store needs to reproduce this state exactly."""
        utxo_values, utxo_dead = self.utxo.dump()
        nf_values, _ = self.nullifiers.dump()
        return {"chain_id": self.chain_id, "height": self.height,
                "tip": self.tip, "burned_fees": self.burned_fees,
                "utxo": utxo_values, "utxo_dead": utxo_dead,
                "nullifiers": nf_values, "history": self.history.dump()}

    @classmethod
    def load(cls, params: ChainParams, dump) -> "ChainState":
        out = cls.__new__(cls)
        out.params = params
        out.chain_id = dump["chain_id"]
        out.utxo = SealAccumulator.load("utxo", dump["utxo"],
                                        dump.get("utxo_dead", ()),
                                        d=params.seal_d)
        out.nullifiers = SealAccumulator.load("nf", dump["nullifiers"],
                                              d=params.seal_d)
        out.history = HeaderHistory(dump.get("history", ()))
        out.height = dump["height"]
        out.tip = dump["tip"]
        out.burned_fees = dump["burned_fees"]
        return out

    # ── copying ──────────────────────────────────────────────────────────────

    def copy(self) -> "ChainState":
        out = ChainState.__new__(ChainState)
        out.params = self.params
        out.chain_id = self.chain_id
        out.utxo = self.utxo.clone()
        out.nullifiers = self.nullifiers.clone()
        out.history = self.history.clone()
        out.height = self.height
        out.tip = self.tip
        out.burned_fees = self.burned_fees
        return out

    def __repr__(self):
        return (f"ChainState(h={self.height}, utxo={len(self.utxo)}, "
                f"nf={len(self.nullifiers)}, tip={self.tip[:12]}…)")
