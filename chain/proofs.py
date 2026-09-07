"""Proof backends — one per tier.

All three prove the same statement: knowledge of a witness z with
F(embed(known, z)) = v over a transaction's TxSystem, under the same MQ hardness
assumption.  What differs is the machinery, and therefore the implementation
surface a soundness bug could hide in.  A transaction that reaches the supreme
tier has been accepted by all three.

    mpcith   MPC-in-the-head          mq/ms6/mpcith.py   smallest proof
    ssh5     gamma-batched 5-pass SSH mq/ms6/core.py
    ssh3     gamma-batched 3-pass SSH mq/ms6/ssh3.py     simplest analysis

Every backend lives in mq/, not here: ms6 proves and verifies, vs6 verifies only
and imports nothing from ms6.  `verify_independent` runs a proof through the vs6
copy, so the chain can exercise the prover-independent verifier the mq packages
are split to provide.
"""
from __future__ import annotations

from mq.ms6 import (prove_hidden, prove_hidden3, prove_mpcith, serialize_proof,
                    serialize_proof3, serialize_proof_mpcith, verify_hidden,
                    verify_hidden3, verify_mpcith)
from mq.ms6.mpcith import DEFAULT_PARTIES, repetitions_for
from mq.ms6.ssh3 import DEFAULT_ROUNDS_3PASS
from mq.vs6 import verify_hidden as vs6_verify_hidden
from mq.vs6 import verify_hidden3 as vs6_verify_hidden3
from mq.vs6 import verify_mpcith as vs6_verify_mpcith

DEFAULT_SECURITY_BITS = 80


class ProofError(Exception):
    pass


class ProofBackend:
    """One proof system.  Backends are stateless and interchangeable."""

    name = "abstract"
    passes = 0
    available = False

    def rounds_for(self, security_bits: int = DEFAULT_SECURITY_BITS) -> int:
        raise NotImplementedError

    def prove(self, sys, v, known, z, rounds=None):
        raise NotImplementedError

    def verify(self, sys, v, known, proof) -> bool:
        raise NotImplementedError

    def verify_independent(self, sys, v, known, proof) -> bool:
        """The same check through vs6, which cannot produce proofs at all."""
        raise NotImplementedError

    def serialize(self, proof) -> bytes:
        raise NotImplementedError

    def size(self, proof) -> int:
        return len(self.serialize(proof))

    def __repr__(self):
        return f"<{self.name}>"


class SSH5Backend(ProofBackend):
    name = "ssh5"
    passes = 5
    available = True

    def rounds_for(self, security_bits=DEFAULT_SECURITY_BITS) -> int:
        # per-round error 1/2 + 1/(2P); a 255-bit field leaves grinding nothing
        return security_bits

    def prove(self, sys, v, known, z, rounds=None):
        return prove_hidden(sys, v, known, z, rounds=rounds or self.rounds_for())

    def verify(self, sys, v, known, proof) -> bool:
        return verify_hidden(sys, v, known, proof)

    def verify_independent(self, sys, v, known, proof) -> bool:
        return vs6_verify_hidden(sys, v, known, proof)

    def serialize(self, proof) -> bytes:
        return serialize_proof(proof)


class SSH3Backend(ProofBackend):
    name = "ssh3"
    passes = 3
    available = True

    def rounds_for(self, security_bits=DEFAULT_SECURITY_BITS) -> int:
        # per-round error 2/3, so 2^-80 needs 137 rounds
        return (DEFAULT_ROUNDS_3PASS if security_bits == DEFAULT_SECURITY_BITS
                else __import__("math").ceil(security_bits / __import__("math").log2(1.5)))

    def prove(self, sys, v, known, z, rounds=None):
        return prove_hidden3(sys, v, known, z, rounds=rounds or self.rounds_for())

    def verify(self, sys, v, known, proof) -> bool:
        return verify_hidden3(sys, v, known, proof)

    def verify_independent(self, sys, v, known, proof) -> bool:
        return vs6_verify_hidden3(sys, v, known, proof)

    def serialize(self, proof) -> bytes:
        return serialize_proof3(proof)


class MPCitHBackend(ProofBackend):
    """The smallest of the three, and the one with the most machinery.

    N virtual parties hold additive shares of the witness; the prover opens all
    but one.  Soundness per repetition is ~1/N + 2/P, so tau = ceil(lambda/log2 N)
    — more parties means fewer repetitions and a smaller proof, at more work per
    repetition.
    """

    name = "mpcith"
    passes = 0
    available = True

    def __init__(self, parties: int = DEFAULT_PARTIES):
        self.parties = parties

    def rounds_for(self, security_bits=DEFAULT_SECURITY_BITS) -> int:
        return repetitions_for(security_bits, self.parties)

    def prove(self, sys, v, known, z, rounds=None):
        return prove_mpcith(sys, v, known, z, n_parties=self.parties,
                            reps=rounds or self.rounds_for())

    def verify(self, sys, v, known, proof) -> bool:
        return verify_mpcith(sys, v, known, proof)

    def verify_independent(self, sys, v, known, proof) -> bool:
        return vs6_verify_mpcith(sys, v, known, proof)

    def serialize(self, proof) -> bytes:
        return serialize_proof_mpcith(proof)

    def __repr__(self):
        return f"<mpcith N={self.parties}>"


BACKENDS = {b.name: b for b in (SSH5Backend(), SSH3Backend(), MPCitHBackend())}


def get_backend(name: str) -> ProofBackend:
    try:
        return BACKENDS[name]
    except KeyError:
        raise ProofError(f"unknown proof backend {name!r}; "
                         f"have {sorted(BACKENDS)}") from None


def available_backends():
    return sorted(n for n, b in BACKENDS.items() if b.available)
