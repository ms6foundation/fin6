"""What can be proved about a block without knowing anything else.

Review B1: `Seat.catch_lazy` produces signed evidence that an attester did not
check — an attestation over a block that does not validate — and nothing
happens. `GridRegister.apply` takes a `faulted` set; the network path passed
none. So the whole standing system, the forty-ceremony apprenticeship and the
forgiveness counters, was machinery for punishing behaviour the network could
not record.

The reason it stopped there is real and it is this: **acting on a fault means
every node agreeing about it**, and a node applying block h+1 next month cannot
re-run a validity check that needed the ledger state at height h. Equivocation
escaped that because its evidence proves itself — two signed proposals, one
height, one leader, and any party with the bytes can see it.

This module is the same property for laziness. It splits invalidity in two:

**Self-evident.** The block's own bytes contradict each other, or contradict
the chain parameters. A transaction whose body does not authenticate, a
`tx_root` that is not the root of the transactions underneath it, a delta that
is not the delta those transactions imply, a transaction in the wrong
partition, a digest that does not match the thing it commits to. Checking any
of these needs the block and nothing else — not the UTXO set, not the tip, not
a register. A verifier a year later gets the same answer as the seat that was
there.

**Contextual.** An input already spent, a block that does not follow the tip,
an epoch that has moved on. Objective at the time, and not re-derivable from
the block afterwards.

Only the first kind can convict anybody, which is exactly the boundary
`FaultReport` already draws between `equivocation` and `invalid_block`. An
attester that signed a block with a self-evident flaw either did not look or
looked and lied, and the evidence for that is the block itself.
"""
from __future__ import annotations

from .locality import tx_partition
from .state import UtxoDelta
from .transaction import authenticate

#: A fault report carries the block it convicts, because a verifier has to
#: re-run the check. That is a real cost paid at a rare moment — but a block
#: full of transactions is megabytes of proof, so a report is only filed when
#: the evidence fits. Above this, laziness stays visible in the log and
#: unpunished, and the fix is a succinct fraud proof naming the one
#: contradiction rather than carrying the whole block: a design, not a field.
MAX_EVIDENCE_BYTES = 512 * 1024


def self_evident_flaw(block, params, *, chain_id: str | None = None,
                      check_proofs: bool = True) -> str | None:
    """The reason this block is invalid on its own bytes, or None.

    Takes a ceremony block or a network block — a seat attests to whichever
    its tier produces, and at one tier that is a network block wrapping one
    ceremony. A pure function of (block, params) either way. Never raises: a
    malformed block is a flawed block, and a checker that throws on the
    evidence it was handed is a checker an attacker can silence.
    """
    if hasattr(block, "groups"):
        return _network_flaw(block, params, chain_id=chain_id,
                             check_proofs=check_proofs)
    return _ceremony_flaw(block, params, chain_id=chain_id,
                          check_proofs=check_proofs)


def _network_flaw(block, params, *, chain_id, check_proofs) -> str | None:
    """What a network block says about itself, and its nested ceremonies.

    Only the commitments over things the block carries: `group_root`,
    `foundings_root`, and every ceremony underneath. The rest of a network
    header — the UTXO root, the history root, the counts, the register roots —
    is a statement about the *ledger*, which is contextual by construction and
    is not something a report can prove a year later.
    """
    try:
        h = block.header
        if chain_id is not None and h.chain_id != chain_id:
            return f"block is for chain {str(h.chain_id)[:20]}…"
        if h.group_root != block.compute_group_root():
            return "group_root does not match the tier-1 blocks carried"
        if h.foundings_root != block.compute_foundings_root():
            return "foundings_root does not match the foundings carried"
        if h.merges_root != block.compute_merges_root():
            return "merges_root does not match the merges carried"
        for sup in block.groups:
            if sup.header.child_root != sup.compute_child_root():
                return (f"{sup.header.group_id}: child_root does not match "
                        f"the ceremony blocks carried")
        for child in block.ceremony_blocks():
            flaw = _ceremony_flaw(child, params, chain_id=chain_id,
                                  check_proofs=check_proofs)
            if flaw is not None:
                return f"{child.header.grid_id}: {flaw}"
        return None
    except Exception as exc:
        return f"malformed block: {exc.__class__.__name__}: {exc}"


def _ceremony_flaw(block, params, *, chain_id, check_proofs) -> str | None:
    try:
        h = block.header
        if chain_id is not None and h.chain_id != chain_id:
            return f"block is for chain {str(h.chain_id)[:20]}…"
        if h.n_partitions < 1:
            return f"header claims {h.n_partitions} partitions"
        if not 0 <= h.partition < h.n_partitions:
            return (f"partition {h.partition} is outside "
                    f"0–{h.n_partitions - 1}")

        # The header's own commitments, against what the block carries.
        if h.tx_root != block.compute_tx_root():
            return "tx_root is not the root of these transactions"
        if h.prev_cert_digest != block.compute_prev_cert_digest():
            return "prev_cert digest does not match the certificate carried"
        if h.faults_digest != block.compute_faults_digest():
            return "faults digest does not match the reports carried"
        if block.roll is not None and h.roll_digest != block.roll.digest():
            return "roll digest does not match the roll carried"

        # The delta has to be the one these transactions imply, and the digest
        # the one that delta has.  Two separate lies, both checkable here.
        implied = UtxoDelta.from_txs(block.transactions)
        if block.delta.digest() != implied.digest():
            return "the delta is not the one these transactions make"
        if h.delta_digest != block.delta.digest():
            return "delta digest does not match the delta carried"

        # Each transaction, on its own terms.
        seen_cm, seen_nf, seen_out = set(), set(), set()
        for i, tx in enumerate(block.transactions):
            if tx.chain_id != h.chain_id:
                return f"transaction {i} is for another chain"
            part = tx_partition(tx, h.n_partitions)
            if part is None:
                return f"transaction {i} spans partitions, so no grid may hold it"
            if part != h.partition:
                return (f"transaction {i} belongs to partition {part}, this "
                        f"block is partition {h.partition}")
            if set(tx.input_cms) & seen_cm:
                return f"transaction {i} spends a note already spent in this block"
            if set(tx.nullifiers) & seen_nf:
                return f"transaction {i} repeats a nullifier in this block"
            if set(tx.output_cms) & seen_out:
                return f"transaction {i} creates a note already created here"
            seen_cm.update(tx.input_cms)
            seen_nf.update(tx.nullifiers)
            seen_out.update(tx.output_cms)

            ok, why, auth = authenticate(tx, params, chain_id=h.chain_id)
            if not ok:
                return f"transaction {i} does not authenticate: {why}"
            if check_proofs:
                from .transaction import verify_proof
                ok, why = verify_proof(tx, params, auth)
                if not ok:
                    return f"transaction {i}: {why}"
        return None
    except Exception as exc:                    # a malformed block is flawed
        return f"malformed block: {exc.__class__.__name__}: {exc}"


def evidence_size(block) -> int:
    """How many bytes a report about this block would have to carry."""
    from .store import codec
    try:
        return len(codec.encode(block))
    except Exception:
        return MAX_EVIDENCE_BYTES + 1


def reportable(block) -> bool:
    return evidence_size(block) <= MAX_EVIDENCE_BYTES
