"""A validating node: mempool, state, block production, attestation.

A node never trusts a leader.  It re-derives every root itself, re-checks every
proof it has not already checked, and only then signs an attestation.  The
ceremony's job is only to move those attestations around efficiently.
"""
from __future__ import annotations

from .block import (Attestation, Block, BlockHeader, CeremonyMeta, FaultReport,
                    SignedProposal)
from .crypto import Signer, h_hex
from .params import ChainParams
from .seal import seal_root
from .state import ChainState
from .transaction import Transaction, verify_transaction


def tx_fingerprint(tx: Transaction) -> str:
    """Identity of a transaction *including* its proof bytes.

    tx.txid binds the body only, so two submissions can share an id with
    different proofs; the verification cache must key on this instead.
    """
    return h_hex("tx-fingerprint", tx.txid, tx.proof_bytes(),
                 list(int(a) for a in tx.v))


class Node:
    def __init__(self, node_id: str, signer: Signer, params: ChainParams,
                 state: ChainState):
        self.id = node_id
        self.signer = signer
        self.params = params
        self.state = state
        self.mempool: dict = {}
        self._verified: dict = {}          # txid -> fingerprint
        # Reservations held by mempool transactions.  Without these two, a node
        # would happily hold two transactions spending the same note: block
        # building skips the conflict, so the chain stays safe, but the node
        # wastes a slot and gossips a transaction that can never be included.
        self._reserved_nf: dict = {}       # nullifier   -> txid
        self._reserved_cm: dict = {}       # input note  -> txid
        self.log: list = []

    # ── identity ─────────────────────────────────────────────────────────────

    @property
    def public_hex(self) -> str:
        return self.signer.public_hex

    @property
    def chain_id(self) -> str:
        return self.state.chain_id

    # ── mempool ──────────────────────────────────────────────────────────────

    def submit(self, tx: Transaction, backend: str | None = None):
        """Admit a transaction: full proof check plus state check."""
        ok, why = verify_transaction(tx, self.params, chain_id=self.chain_id,
                                     backend=backend)
        if not ok:
            return False, why
        ok, why = self.state.check_transaction(tx, verify_proof=False)
        if not ok:
            return False, why
        if tx.txid in self.mempool:
            return False, "already in the mempool"
        for nf in tx.nullifiers:
            holder = self._reserved_nf.get(nf)
            if holder is not None:
                return False, (f"conflicts with {holder[:14]}…: nullifier "
                               f"{nf[:14]}… is already claimed in the mempool")
        for cm in tx.input_cms:
            holder = self._reserved_cm.get(cm)
            if holder is not None:
                return False, (f"conflicts with {holder[:14]}…: note "
                               f"{cm[:14]}… is already being spent")
        self.mempool[tx.txid] = tx
        self._verified[tx.txid] = tx_fingerprint(tx)
        for nf in tx.nullifiers:
            self._reserved_nf[nf] = tx.txid
        for cm in tx.input_cms:
            self._reserved_cm[cm] = tx.txid
        return True, "ok"

    def _evict(self, txid):
        tx = self.mempool.pop(txid, None)
        if tx is None:
            return
        for nf in tx.nullifiers:
            self._reserved_nf.pop(nf, None)
        for cm in tx.input_cms:
            self._reserved_cm.pop(cm, None)

    def already_verified(self, tx: Transaction) -> bool:
        return self._verified.get(tx.txid) == tx_fingerprint(tx)

    # ── block production ─────────────────────────────────────────────────────

    def build_block(self, meta: CeremonyMeta, limit: int | None = None) -> Block:
        """Assemble the next block from the mempool.

        Transactions that conflict with an earlier pick are skipped rather than
        failing the block.
        """
        shadow = self.state.copy()
        chosen, seen_nf, seen_cm = [], set(), set()
        for tx in list(self.mempool.values()):
            if limit is not None and len(chosen) >= limit:
                break
            ok, _ = shadow.check_transaction(tx, verify_proof=False,
                                             seen_nf=seen_nf, seen_cm=seen_cm)
            if not ok:
                continue
            chosen.append(tx)
            seen_nf.update(tx.nullifiers)
            seen_cm.update(tx.input_cms)
            shadow.apply_transaction(tx)

        header = BlockHeader(
            height=self.state.height + 1,
            prev_hash=self.state.tip,
            chain_id=self.chain_id,
            utxo_root=shadow.utxo.root,
            nf_root=shadow.nullifiers.root,
            tx_root=seal_root("tx", [tx.txid for tx in chosen]),
            ceremony=meta)
        return Block(header=header, transactions=tuple(chosen))

    # ── validation ───────────────────────────────────────────────────────────

    def validate_block(self, block: Block):
        ok, why = self.state.check_block(block,
                                         already_verified=self.already_verified)
        if ok:
            for tx in block.transactions:
                self._verified.setdefault(tx.txid, tx_fingerprint(tx))
        return ok, why

    # ── signed statements ────────────────────────────────────────────────────

    def propose(self, block, epoch: int, grid_seed: str) -> SignedProposal:
        # block.height, not block.header.height: the tiered headers key on epoch
        # and expose height as a block-level property, so this is the spelling
        # every block type answers to.
        msg = SignedProposal.message(self.chain_id, block.height,
                                     block.hash(), epoch, grid_seed)
        return SignedProposal(block=block, leader_id=self.id,
                              public_hex=self.public_hex, epoch=epoch,
                              grid_seed=grid_seed, signature=self.signer.sign(msg))

    def attest(self, block_hash: str, height: int, epoch: int,
               grid_seed: str) -> Attestation:
        msg = Attestation.message(self.chain_id, height, block_hash, epoch,
                                  grid_seed)
        return Attestation(node_id=self.id, public_hex=self.public_hex,
                           chain_id=self.chain_id, height=height,
                           block_hash=block_hash, epoch=epoch,
                           grid_seed=grid_seed,
                           signature=self.signer.sign(msg))

    def report(self, kind: str, height: int, epoch: int, detail: str,
               evidence=()) -> FaultReport:
        evidence = tuple(evidence)
        msg = FaultReport.message(self.id, kind, height, epoch, detail,
                                  [sp.block_hash for sp in evidence])
        return FaultReport(reporter=self.id, public_hex=self.public_hex,
                           kind=kind, height=height, epoch=epoch, detail=detail,
                           evidence=evidence, signature=self.signer.sign(msg))

    # ── chain advance ────────────────────────────────────────────────────────

    def apply(self, block: Block):
        result = self.state.apply_block(block)
        for tx in block.transactions:
            self._evict(tx.txid)
        # Anything left in the mempool that the new state invalidates is dropped
        # — most often a transaction that lost a race to spend the same note.
        for txid, tx in list(self.mempool.items()):
            ok, _ = self.state.check_transaction(tx, verify_proof=False)
            if not ok:
                self._evict(txid)
        return result

    def __repr__(self):
        return (f"Node({self.id}, h={self.state.height}, "
                f"mempool={len(self.mempool)})")
