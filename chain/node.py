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
from .store import codec
from .transaction import Transaction, authenticate, verify_proof


def proof_fingerprint(tx: Transaction, backend: str | None = None) -> str:
    """Identity of a (body, backend, proof *content*) triple.

    Distinct from `tx_fingerprint` on purpose, and the difference matters here.
    `tx_fingerprint` keys on `proof_bytes()`, which is a *length* summed over
    every backend attached — so it cannot tell two same-sized proofs apart, and
    it does not say which backend was checked.  That is tolerable for the
    positive cache, whose question is "is this statement already known to
    hold", and useless for the negative one, whose question is "have I already
    burned 25 ms on exactly these proof bytes".

    Keyed on the content, and on the backend, because a transaction refused
    under one backend's proof may carry a good proof under another.
    """
    proof = tx.proofs.get(backend or "")
    if proof is None and backend is None:
        blob = codec.encode([[n, tx.proofs[n]] for n in sorted(tx.proofs)])
    else:
        blob = codec.encode(proof)
    return h_hex("proof-fingerprint", tx.txid, backend or "*",
                 list(int(a) for a in tx.v), blob)


def tx_fingerprint(tx: Transaction) -> str:
    """Identity of a transaction *including* its proof bytes.

    tx.txid binds the body only, so two submissions can share an id with
    different proofs; the verification cache must key on this instead.
    """
    return h_hex("tx-fingerprint", tx.txid, tx.proof_bytes(),
                 list(int(a) for a in tx.v))


#: The shape of a transaction this chain admits at all.  Not a consensus rule
#: — a block full of legal-but-enormous transactions is still legal — but a
#: bound on what one submission can make a node do before anything is checked.
MAX_INPUTS = 16
MAX_OUTPUTS = 16

#: How many refused proofs a node remembers.  A submission whose proof fails
#: costs 25 ms and, before part nine, was not written down anywhere — so the
#: same bad proof could be resubmitted for ever at no cost to the sender.  The
#: cache is bounded because it is fed by strangers; when it is full the oldest
#: entries go, which loses the cheap `no` for those and nothing else.
MAX_REFUSED_PROOFS = 4096

#: How many failed proofs against one body make it suspect.  Note what this
#: is NOT: a threshold at which the body is refused.  Refusing it would hand
#: an attacker a censorship primitive — watch a transaction go past in gossip,
#: splice three bad proofs onto its body, and the real transaction is refused
#: by every node it reaches, having done nothing wrong.  A body's strikes only
#: ever *demote* it in the work budget, so an honest proof for a struck body
#: still gets verified, just behind everything that has not been abused.
PROOF_STRIKES = 3


def _bounded_put(store: dict, key, value):
    """Insert, evicting oldest first.  These caches are fed by strangers."""
    if key not in store and len(store) >= MAX_REFUSED_PROOFS:
        for stale in list(store)[:len(store) - MAX_REFUSED_PROOFS + 1]:
            store.pop(stale, None)
    store[key] = value


class Node:
    def __init__(self, node_id: str, signer: Signer, params: ChainParams,
                 state: ChainState, store=None):
        self.id = node_id
        self.signer = signer
        self.params = params
        self.state = state
        # A node with a store survives a restart; one without is a simulation.
        # The mempool deliberately stays in memory either way — it is rebuilt
        # by gossip within an epoch, and a restored mempool is a way to
        # re-admit transactions the chain has since invalidated.
        self.store = store
        self.mempool: dict = {}
        self._verified: dict = {}          # txid -> fingerprint
        self.admitted = 0
        self.refused = 0
        self.bad_proofs = 0        # the proof itself failed: 25 ms was spent
        self.unauthenticated = 0   # the body failed: 0.12 ms was spent
        self.stale_proofs = 0      # refused from the cache: nothing was spent
        # Proofs that have already failed, by fingerprint.  Insertion-ordered
        # so the bound evicts the oldest; a dict rather than a set for that
        # reason alone.
        self._refused_proofs: dict = {}
        # txid -> how many proofs for that body have failed.  The free outer
        # gate; see `authenticate`.
        self._strikes: dict = {}
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

    def admissible(self, tx: Transaction):
        """Everything refusable without touching the proof.  (ok, reason)

        This is the cheap `no` part eight asked for.  A proof costs about 26 ms
        to check and a set lookup costs microseconds, so every reason a
        transaction could be refused anyway is applied first — and the
        expensive check only ever runs on something that would otherwise be
        worth including.  It does not make flooding free to resist; it makes it
        three orders of magnitude cheaper, which is the difference between a
        node that falls over and a node that gets slower.

        Nothing here is a *new* rule.  Each of these checks already existed;
        they were simply behind the proof.
        """
        if tx.chain_id != self.chain_id:
            return False, f"transaction is for chain {str(tx.chain_id)[:20]}…"
        if tx.txid in self.mempool:
            return False, "already in the mempool"
        if tx.fee < 0:
            return False, "negative fee"
        if not tx.inputs or not tx.output_cms:
            return False, "a transaction spends something and creates something"
        if len(tx.inputs) > MAX_INPUTS or len(tx.output_cms) > MAX_OUTPUTS:
            return False, (f"{len(tx.inputs)} inputs and "
                           f"{len(tx.output_cms)} outputs is outside the "
                           f"shape this chain admits")
        ok, why = self.state.check_transaction(tx, verify_proof=False)
        if not ok:
            return False, why
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
        return True, "ok"

    def authenticate(self, tx: Transaction, backend: str | None = None):
        """The two cheap rungs, and nothing else.  (ok, reason, auth)

        `admissible` first, because a set lookup is 2.1 µs and being refusable
        at all beats being authentic.  Then `authenticate`, which is 0.12 ms
        and establishes who is asking: the owner rows are pinned to the
        declared commitments and every spend signature verifies, so a
        transaction that reaches the end of this method was built by a party
        holding spend authority over notes `admissible` has just confirmed are
        live and unspent.

        A caller that wants to meter the expensive rung — see
        `chain/net/budget.py` — calls this, decides, and then calls
        `verify_and_admit`.  `submit` is the two of them back to back.
        """
        ok, why = self.admissible(tx)
        if not ok:
            self.refused += 1
            return False, why, None
        backend_name = backend or self.params.default_backend
        # The negative cache, in two levels, because its own key is not free:
        # `proof_fingerprint` encodes the proof canonically, which costs about
        # 1.2 ms on a 60 KB proof — ten times what the whole cheap half costs.
        # Paying that on every honest submission to catch a replay would be a
        # denial of service with better manners.
        #
        # So the outer gate is a strike count per transaction body: one dict
        # lookup on a string `admissible` has already computed, and free.  A
        # body nobody has failed a proof for goes straight through.  A body
        # with strikes against it is worth fingerprinting, and a body with
        # PROOF_STRIKES against it is refused without looking at the proof at
        # all.
        #
        # What this buys, precisely: a repeated bad proof is refused 20x
        # cheaper, and any one body costs the node at most PROOF_STRIKES
        # verifications however many proofs are mutated onto it.  What it does
        # not buy: anything against an attacker who mutates proof bytes, since
        # steps 1-4 cannot see them and every mutation is a fresh fingerprint.
        # Bounding that is the budget's job (`chain/net/budget.py`), not the
        # cache's — and it has to be, because the alternative of refusing a
        # body outright is a censorship primitive.  See `PROOF_STRIKES`.
        # A body with no strikes has never had a proof fail, so there is
        # nothing to compare against and nothing to pay for.
        if self._strikes.get(tx.txid) and \
                proof_fingerprint(tx, backend_name) in self._refused_proofs:
            self.refused += 1
            self.stale_proofs += 1
            return False, "this proof has already been refused", None
        ok, why, auth = authenticate(tx, self.params, chain_id=self.chain_id)
        if not ok:
            self.refused += 1
            self.unauthenticated += 1
            return False, why, None
        return True, "ok", auth

    def verify_and_admit(self, tx: Transaction, auth, backend: str | None = None):
        """The expensive rung, and the mempool.  (ok, reason)

        Only ever called with an `auth` from `self.authenticate` on this same
        transaction.  A failure here is remembered by fingerprint, which is the
        right key and `tx.txid` is not: a body can legitimately be re-proved,
        and a txid-keyed refusal would reject the honest retry along with the
        mutations.
        """
        backend_name = backend or self.params.default_backend
        ok, why = verify_proof(tx, self.params, auth, backend=backend)
        if not ok:
            self.refused += 1
            self.bad_proofs += 1
            self._remember_refusal(tx, backend_name)
            return False, why
        self.mempool[tx.txid] = tx
        self.admitted += 1
        self._verified[tx.txid] = tx_fingerprint(tx)
        for nf in tx.nullifiers:
            self._reserved_nf[nf] = tx.txid
        for cm in tx.input_cms:
            self._reserved_cm[cm] = tx.txid
        return True, "ok"

    def submit(self, tx: Transaction, backend: str | None = None):
        """Admit a transaction: cheap checks, authentication, then the proof.

        Unmetered, and therefore for the simulation, the tests and any caller
        that is not on the path to a deadline.  A networked node submits
        through the budget in `chain/net/budget.py` instead, so that a
        stranger's 25 ms cannot land on the thread that has to attest.
        """
        ok, why, auth = self.authenticate(tx, backend)
        if not ok:
            return False, why
        return self.verify_and_admit(tx, auth, backend)

    def strikes_against(self, tx: Transaction) -> int:
        """How many proofs for this body have already failed.

        The budget's demotion signal.  Free to ask.
        """
        return self._strikes.get(tx.txid, 0)

    def suspect(self, tx: Transaction) -> bool:
        return self.strikes_against(tx) >= PROOF_STRIKES

    def _remember_refusal(self, tx: Transaction, backend_name: str):
        """Write down a proof that failed, at both levels of the cache."""
        self._strikes[tx.txid] = self._strikes.get(tx.txid, 0) + 1
        _bounded_put(self._strikes, tx.txid, self._strikes[tx.txid])
        _bounded_put(self._refused_proofs,
                     proof_fingerprint(tx, backend_name), True)

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
