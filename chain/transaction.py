"""Transactions — build, prove, verify.

A transaction spends k notes and creates m notes.  What goes on chain is:

    input cms + nullifiers + spend signatures, output cms, the public fee,
    the MQ output vector v, and one gamma-batched 5-pass SSH proof.

Values, blinders, output owners and the notes' rho seeds never appear.

What the single proof establishes, all at once:

  * every slot's hidden coordinates really do commit to the declared cm
    (the note rows of v ARE that note's commitment vector)
  * sum(input values) - sum(output values) = fee            (sum row)
  * every note in the transaction carries the same asset     (asset rows)
  * every output value lies in [0, 2^B)                      (recomp + bit rows)
  * each published nullifier is the public form evaluated at the very note
    being spent                                              (nullifier rows)
  * each published spending key matches the owner slot of the note it spends
    (owner rows), so the attached signature authorises this spend
  * the whole thing is bound to this transaction body        (bind row, and the
    binding scalar is a revealed coordinate so it enters the proof's
    Fiat-Shamir statement — a proof cannot be lifted onto another body)

PRIVACY SCOPE.  Amounts, output owners, and note randomness are hidden.  Which
notes are being spent is NOT: the input note's commitment vector is carried in
v, so the spend graph is public.  This is the Mimblewimble / confidential-
transactions model, not the Zcash one.  Hiding the spend graph needs a
membership proof *inside* the MQ statement, which needs an algebraically
expressible accumulator; the seal tree is hash-based, so that is out of reach
of today's primitives.  Tracked as an open item.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from mq.ms6 import P
from mq.vs6 import verify_hidden as vs6_verify_hidden

from .crypto import h_bytes, h_field, h_hex, owner_field, verify_sig
from .proofs import get_backend
from .notes import Note, note_id, note_vector, nullifier_id
from .params import ChainParams
from .txsystem import tx_system

TX_VERSION = 1


class TxError(Exception):
    """Raised when a transaction cannot be built (a local, caller-side fault)."""


# ═══════════════════════════════════════════════════════════════════════════════
# Wire objects
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TxInput:
    cm: str             # commitment of the note being spent
    nullifier: str      # spend marker, derived inside the proof
    owner_pub: str      # spending public key
    signature: str      # signature by owner_pub over the binding scalar


@dataclass(frozen=True)
class Transaction:
    version: int
    chain_id: str
    fee: int
    inputs: tuple
    output_cms: tuple
    v: tuple
    binding: int
    proofs: dict = field(repr=False)      # backend name -> proof
    #: One sealed opening per output, in `output_cms` order — `epk || ct`,
    #: readable only by the address it was sent to.  Empty for a transaction
    #: built without recipient addresses, which is how every in-process demo
    #: works and is why receiving needed a design of its own.
    output_notes: tuple = field(default=(), repr=False)
    #: One detection tag per output, in the same order.  Three bytes each, and
    #: bound into the binding scalar like the openings beside them — a tag an
    #: attacker could rewrite would let it redirect somebody's *scan*, which is
    #: not theft but is a way to make a payment invisible to its recipient.
    output_tags: tuple = field(default=(), repr=False)

    @property
    def txid(self) -> str:
        return "tx:" + h_hex("txid", self.binding)

    @property
    def nullifiers(self) -> tuple:
        return tuple(i.nullifier for i in self.inputs)

    @property
    def input_cms(self) -> tuple:
        return tuple(i.cm for i in self.inputs)

    def has_proof(self, backend: str) -> bool:
        return backend in self.proofs

    def proof_bytes(self, backend: str | None = None) -> int:
        names = [backend] if backend else sorted(self.proofs)
        return sum(get_backend(n).size(self.proofs[n]) for n in names)

    def __repr__(self):
        return (f"Transaction({self.txid[:14]}…, {len(self.inputs)}in/"
                f"{len(self.output_cms)}out, fee={self.fee})")


def binding_scalar(chain_id: str, version: int, fee: int, input_cms,
                   output_cms, owner_pubs, output_notes=(),
                   output_tags=()) -> int:
    """The scalar every part of a transaction is bound to.

    Computed from the body alone — never from v — so there is no circularity:
    a spender knows all cms before building the proof, because each note's
    commitment depends only on that note.

    The sealed openings are in here too, so the proof covers them: a relay that
    swaps a ciphertext for another breaks the proof rather than quietly leaving
    a recipient unable to find money that is provably theirs.
    """
    return h_field("tx-bind", chain_id, version, fee,
                   list(input_cms), list(output_cms), list(owner_pubs),
                   [bytes(x).hex() for x in output_notes],
                   [bytes(x).hex() for x in output_tags])


def sig_message(binding: int) -> bytes:
    return h_bytes("tx-sig", binding)


# ═══════════════════════════════════════════════════════════════════════════════
# Build
# ═══════════════════════════════════════════════════════════════════════════════

def build_transaction(spends, outputs, fee: int, params: ChainParams,
                      chain_id: str | None = None,
                      backends=None, sealed=(), tags=()) -> Transaction:
    """Build and prove a transaction.

    spends   : [(Note, Signer)] — the notes to consume and the keys that own them
    outputs  : [Note]           — the notes to create
    fee      : public, in the same asset
    sealed   : one sealed opening per output, or ().  Produced by
               `wallet.sealing.seal_output` and passed in already made, because
               sealing needs a recipient *address* and the ledger has no
               business knowing what an address is.  What the ledger does do is
               bind them: the openings and tags go into the binding scalar, so
               an attacker who swaps two of them breaks the proof rather than
               redirecting a payment.
    tags     : one detection tag per output, or ().  Same reasoning.
    backends : which proof systems to prove the statement in.  Only the spender
               holds the witness, so only the spender can prove; a higher tier
               can re-verify but never re-prove.  Proving in more than one system
               is what gives the tiers independent checks over one statement.
    """
    chain_id = chain_id or params.chain_id
    if not spends:
        raise TxError("a transaction needs at least one input")
    if not outputs:
        raise TxError("a transaction needs at least one output")
    if fee < 0:
        raise TxError(f"negative fee {fee}")

    in_notes = [n for n, _ in spends]
    signers = [s for _, s in spends]

    # Conservation and asset agreement, checked before proving so the caller
    # gets a clear error instead of an unprovable statement.
    total_in = sum(n.value for n in in_notes)
    total_out = sum(n.value for n in outputs)
    if total_in - total_out != fee:
        raise TxError(f"values do not conserve: in={total_in} out={total_out} "
                      f"fee={fee} (difference {total_in - total_out - fee})")
    assets = {n.asset for n in in_notes} | {n.asset for n in outputs}
    if len(assets) != 1:
        raise TxError("all notes in a transaction must carry the same asset")
    for n in outputs:
        if not 0 <= n.value < params.max_value:
            raise TxError(f"output value {n.value} outside "
                          f"[0, 2^{params.range_bits})")
    for n, s in spends:
        if n.owner != owner_field(s.public_hex):
            raise TxError("signing key does not own the note it is spending")

    in_cms = [note_id(note_vector(n, params)) for n in in_notes]
    if len(set(in_cms)) != len(in_cms):
        raise TxError("the same note appears twice among the inputs")
    out_cms = [note_id(note_vector(n, params)) for n in outputs]
    owner_pubs = [s.public_hex for s in signers]

    sealed, tags = tuple(sealed), tuple(tags)
    if sealed and len(sealed) != len(outputs):
        raise TxError(f"{len(sealed)} sealed openings for {len(outputs)} "
                      f"outputs")
    if tags and len(tags) != len(outputs):
        raise TxError(f"{len(tags)} detection tags for {len(outputs)} outputs")

    beta = binding_scalar(chain_id, TX_VERSION, fee, in_cms, out_cms,
                          owner_pubs, sealed, tags)

    ts = tx_system(params, len(in_notes), len(outputs))
    x_base = []
    for n in in_notes + outputs:
        x_base.extend(n.coords())
    x_base.append(beta)

    X = ts.lift(x_base)
    v = ts.F(X)
    known = {ts.bind_pos: beta}
    z = [X[i] for i in range(ts.N) if i != ts.bind_pos]

    names = list(backends or params.proof_backends)
    proofs = {}
    for name in names:
        backend = get_backend(name)
        rounds = (params.zk_rounds if name == "ssh5"
                  else backend.rounds_for(params.security_bits))
        proofs[name] = backend.prove(ts, v, known, z, rounds=rounds)

    msg = sig_message(beta)
    tx_inputs = tuple(
        TxInput(cm=cm,
                nullifier=nullifier_id(v[ts.nf_rows[j]]),
                owner_pub=signers[j].public_hex,
                signature=signers[j].sign(msg))
        for j, cm in enumerate(in_cms))

    return Transaction(version=TX_VERSION, chain_id=chain_id, fee=fee,
                       inputs=tx_inputs, output_cms=tuple(out_cms),
                       output_notes=sealed, output_tags=tags,
                       v=tuple(int(a) for a in v), binding=beta, proofs=proofs)


# ═══════════════════════════════════════════════════════════════════════════════
# Verify
# ═══════════════════════════════════════════════════════════════════════════════
#
# Checking a transaction has two halves that differ by two hundred times in
# cost, and part nine is the argument for being able to act in the gap between
# them.  Measured on one input and two outputs:
#
#     authenticate    0.12 ms    the body binds, the note rows reproduce the
#                                declared commitments, values conserve, each
#                                nullifier is derived from the note being spent,
#                                each spending key matches its owner slot, and
#                                every spend signature verifies
#     verify_proof   25.40 ms    the MQ zero-knowledge proof (mpcith)
#
# `verify_transaction` still runs both, in the same order, and is what every
# consensus path calls.  The two halves are exported for the one caller that
# needs the seam: a node deciding whether to spend 25 ms on a stranger wants to
# know *who is asking* first, and the cheap half is what tells it — the owner
# rows and their signatures name a party holding spend authority over notes the
# ledger says are unspent.  See `chain/net/budget.py`.


@dataclass(frozen=True)
class Authenticated:
    """The cheap half's work, kept so the expensive half need not redo it."""
    ts: object          # the tx system for this (k, m) shape
    v: tuple            # the declared MQ output vector, reduced mod P
    beta: int           # the binding scalar, recomputed from the body


def authenticate(tx: Transaction, params: ChainParams, *,
                 chain_id: str | None = None):
    """Everything about a transaction that does not need its proof.

    Returns (ok, reason, auth) — `auth` is an `Authenticated` on success and
    None otherwise.  Never raises.

    This is steps 1-4 of the old single function, unchanged and in the same
    order.  What it establishes is worth stating plainly, because it is the
    only identity a submission has: the owner rows of `v` are pinned to the
    declared commitments, each spend signature verifies against the owner key
    in its input, and the whole thing is welded to this body by the binding
    scalar.  A caller that has also confirmed the inputs are unspent therefore
    knows the submitter holds spend authority over specific live notes.

    What it does NOT establish: that `v` is a satisfying assignment.  Nothing
    here touches the proof bytes, so a transaction with a mutated or garbage
    proof passes this and fails the next step.  That asymmetry is the whole
    reason the negative cache in `chain/node.py` exists.
    """
    chain_id = chain_id or params.chain_id
    try:
        if tx.version != TX_VERSION:
            return False, f"unknown transaction version {tx.version}", None
        if tx.chain_id != chain_id:
            return False, f"wrong chain: {tx.chain_id!r} != {chain_id!r}", None
        if tx.fee < 0:
            return False, f"negative fee {tx.fee}", None
        k, m = len(tx.inputs), len(tx.output_cms)
        if k < 1 or m < 1:
            return False, "transaction must have at least one input and output", None
        if len(set(tx.input_cms)) != k:
            return False, "duplicate input note", None
        if len(set(tx.nullifiers)) != k:
            return False, "duplicate nullifier", None
        if tx.output_notes and len(tx.output_notes) != m:
            return False, (f"{len(tx.output_notes)} sealed openings for {m} "
                           f"outputs"), None
        if tx.output_tags and len(tx.output_tags) != m:
            return False, f"{len(tx.output_tags)} detection tags for {m} outputs", None
        if len(set(tx.output_cms)) != m:
            return False, "duplicate output note", None

        ts = tx_system(params, k, m)
        v = [int(a) % P for a in tx.v]
        if len(v) != ts.m:
            return False, f"v has {len(v)} rows, system has {ts.m}", None

        # 1. binding scalar recomputed from the body
        beta = binding_scalar(chain_id, tx.version, tx.fee, tx.input_cms,
                              tx.output_cms, [i.owner_pub for i in tx.inputs],
                              tx.output_notes, tx.output_tags)
        if beta != tx.binding % P:
            return False, "binding scalar does not match the transaction body", None
        if v[ts.bind_row] != beta:
            return False, "bind row does not carry the binding scalar", None

        # 2. every slot's note rows must reproduce the declared commitment
        declared = list(tx.input_cms) + list(tx.output_cms)
        for s in range(ts.n_slots):
            if note_id(ts.note_vector_of(v, s)) != declared[s]:
                where = "input" if s < k else "output"
                return False, (f"{where} {s if s < k else s - k}: note rows do "
                               f"not match the declared commitment"), None

        # 3. ledger semantics carried in the clear by v
        if v[ts.sum_row] != tx.fee % P:
            return False, "values do not conserve (sum row != fee)", None
        for r in ts.asset_rows:
            if v[r] != 0:
                return False, "notes do not all carry the same asset", None
        for r in ts.range_rows:
            if v[r] != 0:
                return False, "output range decomposition inconsistent", None
        for r in ts.bit_rows:
            if v[r] != 0:
                return False, "range bit not in {0, 1}", None

        # 4. nullifiers and spend authorisation
        msg = sig_message(beta)
        for j, tin in enumerate(tx.inputs):
            if nullifier_id(v[ts.nf_rows[j]]) != tin.nullifier:
                return False, f"input {j}: nullifier not derived from the note", None
            if v[ts.owner_rows[j]] != owner_field(tin.owner_pub):
                return False, f"input {j}: spending key is not the note's owner", None
            if not verify_sig(tin.owner_pub, msg, tin.signature):
                return False, f"input {j}: bad spend signature", None

        return True, "ok", Authenticated(ts=ts, v=tuple(v), beta=beta)
    except Exception as exc:                       # malformed input, never fatal
        return False, f"malformed transaction: {exc.__class__.__name__}: {exc}", None


def verify_proof(tx: Transaction, params: ChainParams, auth: Authenticated, *,
                 verifier=None, backend: str | None = None):
    """The expensive half: the MQ proof, against an already-authenticated body.

    `auth` must come from `authenticate` on this same transaction — it carries
    the recomputed binding scalar, so the proof is checked against the body the
    cheap half verified rather than against anything the transaction claims a
    second time.  Returns (ok, reason).  Never raises.
    """
    backend_name = backend or params.default_backend
    try:
        proof = tx.proofs.get(backend_name)
        if proof is None:
            return False, (f"no {backend_name} proof attached "
                           f"(has {sorted(tx.proofs)})")
        ts, v, beta = auth.ts, list(auth.v), auth.beta
        if verifier is not None:
            ok = verifier(ts, v, {ts.bind_pos: beta}, proof)
        else:
            ok = get_backend(backend_name).verify(ts, v, {ts.bind_pos: beta},
                                                  proof)
        if not ok:
            return False, f"MQ proof failed ({backend_name})"
        return True, "ok"
    except Exception as exc:                       # malformed proof, never fatal
        return False, f"malformed proof: {exc.__class__.__name__}: {exc}"


def verify_transaction(tx: Transaction, params: ChainParams, *,
                       utxo_has=None, nf_has=None, chain_id: str | None = None,
                       verifier=None, backend: str | None = None):
    """Check a transaction.  Returns (ok, reason).  Never raises.

    utxo_has(cm) -> bool   membership of each input in the live UTXO set
    nf_has(nf)   -> bool   whether a nullifier has already been published
    backend                which proof system to check (default: the tier-
                           independent one named by params.default_backend)
    verifier               override the checking function itself; pass the vs6
                           copy to exercise the prover-independent verifier

    The composition of `authenticate` and `verify_proof`, then the ledger
    checks.  Unchanged in behaviour and in order of refusal; the halves are
    separate so a node under load can pay for them separately.
    """
    ok, why, auth = authenticate(tx, params, chain_id=chain_id)
    if not ok:
        return False, why
    ok, why = verify_proof(tx, params, auth, verifier=verifier, backend=backend)
    if not ok:
        return False, why
    try:
        # 6. ledger state, when the caller supplied it
        if utxo_has is not None:
            for tin in tx.inputs:
                if not utxo_has(tin.cm):
                    return False, f"input {tin.cm[:14]}… is not an unspent note"
        if nf_has is not None:
            for nf in tx.nullifiers:
                if nf_has(nf):
                    return False, f"double spend: nullifier {nf[:14]}… already used"
        return True, "ok"
    except Exception as exc:                       # malformed input, never fatal
        return False, f"malformed transaction: {exc.__class__.__name__}: {exc}"


def verify_transaction_vs6(tx, params, **kw):
    """Same check, run through the independent vs6 verifier copy (5-pass only)."""
    return verify_transaction(tx, params, verifier=vs6_verify_hidden,
                              backend="ssh5", **kw)


def verify_transaction_everywhere(tx, params, **kw):
    """Check every proof the transaction carries.  Returns (ok, {name: reason}).

    This is what protocol diversity buys: a soundness bug in one system has to
    be matched by a bug in the others before a forged transaction survives.
    """
    results = {}
    for name in sorted(tx.proofs):
        results[name] = verify_transaction(tx, params, backend=name, **kw)
    return all(ok for ok, _ in results.values()), {n: why for n, (_, why) in results.items()}
