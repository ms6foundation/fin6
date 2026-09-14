"""The genesis mint — where the first money comes from, checkably.

Until now the supply was *issued*: the genesis document listed the values, and
`verify()` checked that they added up to the declared total. Two problems, from
opposite directions, and the review calls them A5.

**Nobody outside could check it.** Adding up values only works for a party
holding the openings. Everyone else took the total on trust — on a chain whose
entire argument is that a reader can check things, the one number that says how
much money exists was an announcement.

**And everybody inside could read it.** Since genesis had to be reproducible
across processes, the note randomness was derived from the document digest, so
every opening was derivable by anyone holding the document. That was the right
fix for seven nodes computing seven different genesis states, and it made the
initial holdings permanently public.

A mint fixes both with the machinery that already exists. It is a transaction
shape with **no inputs**: the sum row reads `-sum(outputs) = v`, so a verifier
holding the declared total learns that the outputs add up to it and learns
nothing else, and the range rows say each one is a real amount rather than a
negative that cancels. The openings travel sealed to their holders, exactly as
the openings of any other payment do.

What authorises money appearing from nowhere is not a signature over a note —
there is no note to sign yet. It is the document: the mint's commitments are
inside the bytes the chain id is the hash of, and the founders ratify that.

The proof and the sealed openings live in a *published artifact* rather than in
the document, for the same reason era 0's leaves do: they are hundreds of
kilobytes, and the document commits to their digest, so the two cannot disagree
without one of them failing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from mq.ms6 import P

from .crypto import h_field, h_hex
from .notes import note_id
from .params import ChainParams
from .proofs import get_backend
from .store import codec
from .txsystem import tx_system

MINT_VERSION = 1


class MintError(Exception):
    pass


def mint_binding(context: str, total: int, output_cms, sealed=(),
                 tags=()) -> int:
    """What the proof is welded to: this document, this total, these outputs.

    `context` is the genesis document *without its mint block* — see
    `GenesisDocument.mint_context`. It cannot be the chain id, because the
    chain id is the hash of a body that contains the mint: the two commit to
    each other, so one of them has to be taken a step earlier.

    The sealed openings are in it for the reason the transaction binding has
    them: a relay that swaps a ciphertext breaks the proof rather than quietly
    leaving a holder unable to find money that is provably theirs.
    """
    return h_field("mint-bind", context, MINT_VERSION, total,
                   list(output_cms), [bytes(x).hex() for x in sealed],
                   list(tags))


@dataclass(frozen=True)
class GenesisMint:
    """The artifact. Public, large, and checkable by anyone."""
    context: str
    total: int
    output_cms: tuple
    v: tuple
    binding: int
    proofs: dict = field(default_factory=dict, repr=False)
    sealed: tuple = field(default=(), repr=False)
    tags: tuple = ()
    version: int = MINT_VERSION

    def body(self) -> dict:
        """Everything, canonically — the artifact is the proof as much as it is
        the commitments, so nothing here is left out of the digest."""
        return {
            "version": self.version, "context": self.context,
            "total": self.total, "output_cms": list(self.output_cms),
            "v": [int(x) for x in self.v], "binding": int(self.binding),
            "proofs": {k: self.proofs[k] for k in sorted(self.proofs)},
            "sealed": [bytes(x) for x in self.sealed],
            "tags": list(self.tags),
        }

    def digest(self) -> str:
        """What the genesis document commits to.

        Over the proofs as well as the commitments: the commitments *are* the
        genesis UTXO set, and the proof is the only reason to believe they add
        up to anything in particular, so a document must not be pairable with
        some other proof of the same total.
        """
        return h_hex("mint", codec.encode(self.body()))

    def encode(self) -> bytes:
        return codec.encode(self.body())

    @classmethod
    def decode(cls, blob: bytes) -> "GenesisMint":
        raw = codec.decode(blob)
        return cls(context=raw["context"], total=int(raw["total"]),
                   output_cms=tuple(raw["output_cms"]),
                   v=tuple(int(x) for x in raw["v"]),
                   binding=int(raw["binding"]),
                   proofs=dict(raw["proofs"]),
                   sealed=tuple(bytes(x) for x in raw["sealed"]),
                   tags=tuple(raw.get("tags", ())),
                   version=int(raw.get("version", MINT_VERSION)))


def build_mint(notes, params: ChainParams, context: str, *,
               sealed=(), tags=(), backends=None) -> GenesisMint:
    """Prove that these hidden values add up to their declared total."""
    if not notes:
        raise MintError("a mint needs at least one output")
    assets = {n.asset for n in notes}
    if len(assets) != 1:
        raise MintError("every note in one mint carries the same asset")
    for n in notes:
        if not 0 <= n.value < params.max_value:
            raise MintError(f"output value {n.value} outside "
                            f"[0, 2^{params.range_bits})")
    total = sum(n.value for n in notes)
    out_cms = [note_id(_vector(n, params)) for n in notes]
    if len(set(out_cms)) != len(out_cms):
        raise MintError("two genesis notes have the same commitment")

    sealed, tags = tuple(sealed), tuple(tags)
    if sealed and len(sealed) != len(notes):
        raise MintError(f"{len(sealed)} sealed openings for {len(notes)} "
                        f"outputs")
    if tags and len(tags) != len(notes):
        raise MintError(f"{len(tags)} detection tags for {len(notes)} outputs")

    beta = mint_binding(context, total, out_cms, sealed, tags)
    ts = tx_system(params, 0, len(notes))
    x_base = []
    for n in notes:
        x_base.extend(n.coords())
    x_base.append(beta)
    X = ts.lift(x_base)
    v = ts.F(X)
    known = {ts.bind_pos: beta}
    z = [X[i] for i in range(ts.N) if i != ts.bind_pos]

    proofs = {}
    for name in list(backends or params.proof_backends):
        backend = get_backend(name)
        rounds = (params.zk_rounds if name == "ssh5"
                  else backend.rounds_for(params.security_bits))
        proofs[name] = backend.prove(ts, v, known, z, rounds=rounds)

    return GenesisMint(context=context, total=total,
                       output_cms=tuple(out_cms), v=tuple(int(a) for a in v),
                       binding=beta, proofs=proofs, sealed=sealed, tags=tags)


def verify_mint(mint: GenesisMint, params: ChainParams, context: str, *,
                backend: str | None = None) -> tuple:
    """(ok, reason).  Never raises.

    The same order as a transaction's: everything that does not need the proof
    first, then the proof. What it establishes is the sentence the chain could
    not say before — *these commitments are the whole of the money, and it is
    this much.*
    """
    try:
        if mint.version != MINT_VERSION:
            return False, f"unknown mint version {mint.version}"
        if mint.context != context:
            return False, f"mint is for another document ({str(mint.context)[:20]}…)"
        if mint.total < 0:
            return False, f"negative total {mint.total}"
        m = len(mint.output_cms)
        if m < 1:
            return False, "a mint has at least one output"
        if len(set(mint.output_cms)) != m:
            return False, "duplicate genesis note"
        if mint.sealed and len(mint.sealed) != m:
            return False, f"{len(mint.sealed)} sealed openings for {m} outputs"
        if mint.tags and len(mint.tags) != m:
            return False, f"{len(mint.tags)} detection tags for {m} outputs"

        ts = tx_system(params, 0, m)
        v = [int(a) % P for a in mint.v]
        if len(v) != ts.m:
            return False, f"v has {len(v)} rows, system has {ts.m}"

        beta = mint_binding(context, mint.total, mint.output_cms, mint.sealed,
                            mint.tags)
        if beta != mint.binding % P:
            return False, "binding scalar does not match the mint body"
        if v[ts.bind_row] != beta:
            return False, "bind row does not carry the binding scalar"

        for s in range(ts.n_slots):
            if note_id(ts.note_vector_of(v, s)) != mint.output_cms[s]:
                return False, (f"output {s}: note rows do not match the "
                               f"declared commitment")

        # With no inputs the sum row is -sum(outputs), so this is the whole
        # claim: the hidden values add up to the declared total and to nothing
        # else.  A mint that printed more than it admits fails here.
        if v[ts.sum_row] != (P - mint.total % P) % P:
            return False, "the outputs do not add up to the declared total"
        for r in ts.asset_rows:
            if v[r] != 0:
                return False, "notes do not all carry the same asset"
        for r in ts.range_rows:
            if v[r] != 0:
                return False, "output range decomposition inconsistent"
        for r in ts.bit_rows:
            if v[r] != 0:
                return False, "range bit not in {0, 1}"

        name = backend or params.default_backend
        proof = mint.proofs.get(name)
        if proof is None:
            return False, (f"no {name} proof attached "
                           f"(has {sorted(mint.proofs)})")
        if not get_backend(name).verify(ts, v, {ts.bind_pos: beta}, proof):
            return False, f"MQ proof failed ({name})"
        return True, "ok"
    except Exception as exc:
        return False, f"malformed mint: {exc.__class__.__name__}: {exc}"


def _vector(note, params):
    from .notes import note_vector
    return note_vector(note, params)
