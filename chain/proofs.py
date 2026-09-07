"""Proof backends — one per tier.

All three prove the same statement: knowledge of a witness z with
F(embed(known, z)) = v over a transaction's TxSystem, under the same MQ
hardness assumption.  What differs is the machinery, and therefore the
implementation surface a soundness bug could hide in.  A transaction that
reaches the supreme tier has been accepted by more than one of them.

    ssh5     gamma-batched 5-pass SSH.  mq/ms6/core.py, unchanged.
    ssh3     gamma-batched 3-pass SSH.  Implemented here on the same batched
             form, because mq/ms6 dropped its 3-pass path when it moved to
             5-pass and only rounds_for_security() survives from it.
    mpcith   MPC-in-the-head.  Designed in mq/mq.md (stages 1-2 built there,
             stage 3 specified but never written) and NOT implemented here.

The 3-pass protocol, batched
----------------------------
The batched form gives one quadratic q(z) = <z,Az> + b.z + c with target t, and
a bilinear polar G(a,b) = q(a+b) - q(a) - q(b) + q(0).  Since

    q(r0 + r1) = q(r0) + q(r1) + G(r0, r1) - c

the identity the verifier checks on challenge 1 is

    G(t0, r1) + e0  =  t - q(r1) + c - G(t1, r1) - e1                     (*)

with r1 = z - r0, t1 = r0 - t0, e1 = q(r0) - e0.  Per round the prover sends
three commitments and answers one of three challenges; a cheat can prepare at
most two, so the soundness error is 2/3 per round and 2^-80 needs
rounds_for_security(80) = 137 rounds — which is exactly the helper mq/ms6 kept.

Challenge 0's whole response is derivable from the round seed, so it costs
SEED_BYTES rather than 2h+1 field elements, mirroring the 5-pass's seeded branch.
"""
from __future__ import annotations

import hashlib
import secrets as _secrets

from mq.ms6 import P, prove_hidden, serialize_proof, verify_hidden
from mq.ms6.core import (FIELD_BYTES, FS_TAG, SEED_BYTES, RestrictedMap, _com,
                         _fe_bytes, _fs_gamma, _round_rand, _statement, _vec_bytes,
                         _vsub, rounds_for_security)

DEFAULT_SECURITY_BITS = 80


class ProofError(Exception):
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Backend interface
# ═══════════════════════════════════════════════════════════════════════════════

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

    def serialize(self, proof) -> bytes:
        raise NotImplementedError

    def size(self, proof) -> int:
        return len(self.serialize(proof))

    def __repr__(self):
        return f"<{self.name} {self.passes}-pass>"


# ═══════════════════════════════════════════════════════════════════════════════
# 5-pass — the one mq/ms6 ships
# ═══════════════════════════════════════════════════════════════════════════════

class SSH5Backend(ProofBackend):
    name = "ssh5"
    passes = 5
    available = True

    def rounds_for(self, security_bits=DEFAULT_SECURITY_BITS) -> int:
        # per-round error 1/2 + 1/(2P); a 255-bit field leaves grinding nothing
        return security_bits

    def prove(self, sys, v, known, z, rounds=None):
        return prove_hidden(sys, v, known, z,
                            rounds=rounds or self.rounds_for())

    def verify(self, sys, v, known, proof) -> bool:
        return verify_hidden(sys, v, known, proof)

    def serialize(self, proof) -> bytes:
        return serialize_proof(proof)


# ═══════════════════════════════════════════════════════════════════════════════
# 3-pass — implemented here
# ═══════════════════════════════════════════════════════════════════════════════

def _fs_trits(stmt: bytes, commits, rounds: int):
    """Fiat-Shamir challenges in {0,1,2}, one per round, over the transcript."""
    h = hashlib.shake_256(FS_TAG.encode() + b"ssh3-ch" + stmt)
    for c0, c1, c2 in commits:
        h.update(c0 + c1 + c2)
    raw = h.digest(8 * rounds)
    return [int.from_bytes(raw[8 * i:8 * (i + 1)], "big") % 3
            for i in range(rounds)]


class SSH3Backend(ProofBackend):
    name = "ssh3"
    passes = 3
    available = True

    def rounds_for(self, security_bits=DEFAULT_SECURITY_BITS) -> int:
        return rounds_for_security(security_bits)      # (2/3)^r <= 2^-lambda

    def prove(self, sys, v, known, z, rounds=None):
        rounds = rounds or self.rounds_for()
        R = RestrictedMap(sys, known)
        if len(z) != R.h:
            raise ProofError(f"witness has {len(z)} coords, {R.h} are hidden")
        stmt = _statement(v, known)
        BF = R.batched(_fs_gamma(stmt, sys.m), v)

        state, commits = [], []
        for _ in range(rounds):
            seed = _secrets.token_bytes(SEED_BYTES)
            r0, t0, e0 = _round_rand(seed, R.h)
            r1 = _vsub(z, r0)
            t1 = _vsub(r0, t0)
            e1 = (BF.q(r0) - e0) % P
            n0, n1, n2 = (_secrets.token_bytes(32) for _ in range(3))
            c0 = _com(n0, r1, [(BF.polar(t0, r1) + e0) % P])
            c1 = _com(n1, t0, [e0 % P])
            c2 = _com(n2, t1, [e1])
            commits.append((c0, c1, c2))
            state.append((seed, r1, t0, t1, e0, e1, n0, n1, n2))

        chs = _fs_trits(stmt, commits, rounds)
        responses = []
        for ch, (seed, r1, t0, t1, e0, e1, n0, n1, n2) in zip(chs, state):
            if ch == 0:
                responses.append((seed, n1, n2))       # seed regenerates r0,t0,e0
            elif ch == 1:
                responses.append((r1, t1, e1, n0, n2))
            else:
                responses.append((r1, t0, e0 % P, n0, n1))
        return {"passes": 3, "batched": True, "seeded": True, "rounds": rounds,
                "commits": commits, "responses": responses}

    def verify(self, sys, v, known, proof) -> bool:
        if proof.get("passes") != 3 or not proof.get("batched"):
            return False
        try:
            R = RestrictedMap(sys, known)
            rounds = proof["rounds"]
            commits, responses = proof["commits"], proof["responses"]
            if not (len(commits) == len(responses) == rounds) or rounds < 1:
                return False
            stmt = _statement(v, known)
            BF = R.batched(_fs_gamma(stmt, sys.m), v)
            chs = _fs_trits(stmt, commits, rounds)

            for ch, (c0, c1, c2), resp in zip(chs, commits, responses):
                if ch == 0:
                    seed, n1, n2 = resp
                    if not isinstance(seed, (bytes, bytearray)):
                        return False
                    if len(seed) != SEED_BYTES:
                        return False
                    r0, t0, e0 = _round_rand(bytes(seed), R.h)
                    t1 = _vsub(r0, t0)
                    e1 = (BF.q(r0) - e0) % P
                    if _com(n1, t0, [e0 % P]) != c1:
                        return False
                    if _com(n2, t1, [e1]) != c2:
                        return False

                elif ch == 1:
                    r1, t1, e1, n0, n2 = resp
                    if len(r1) != R.h or len(t1) != R.h:
                        return False
                    # identity (*): the value hidden in c0, recomputed
                    y = (BF.t - BF.q(r1) + BF.c
                         - BF.polar(t1, r1) - e1) % P
                    if _com(n0, r1, [y]) != c0:
                        return False
                    if _com(n2, t1, [e1 % P]) != c2:
                        return False

                else:
                    r1, t0, e0, n0, n1 = resp
                    if len(r1) != R.h or len(t0) != R.h:
                        return False
                    if _com(n0, r1, [(BF.polar(t0, r1) + e0) % P]) != c0:
                        return False
                    if _com(n1, t0, [e0 % P]) != c1:
                        return False
            return True
        except Exception:
            return False

    def serialize(self, proof) -> bytes:
        out = [proof["rounds"].to_bytes(4, "big")]
        for c0, c1, c2 in proof["commits"]:
            out.append(c0 + c1 + c2)
        for resp in proof["responses"]:
            if len(resp) == 3:                              # challenge 0
                seed, n1, n2 = resp
                out.append(b"\x00" + bytes(seed) + n1 + n2)
            elif len(resp) == 5:                            # challenge 1 or 2
                a, b, e, x, y = resp
                out.append(b"\x01" + _vec_bytes(a) + _vec_bytes(b)
                           + _fe_bytes(e % P) + x + y)
            else:
                raise ProofError("malformed response")
        return b"".join(out)


# ═══════════════════════════════════════════════════════════════════════════════
# MPC-in-the-head — designed in mq/mq.md, not implemented
# ═══════════════════════════════════════════════════════════════════════════════

class MPCitHBackend(ProofBackend):
    """Placeholder for the smallest of the three.

    mq/mq.md specifies this in full: coefficient extraction into an explicit
    quadratic form, gamma-batching into one inner product, a sacrifice check
    over N additive shares, then seed trees, view commitments and a three-phase
    Fiat-Shamir transcript.  Stages 1 and 2 were built in an ms6acc_mpcith.py
    that is not in this repository; stage 3 was designed but never written.

    Estimated at ~50 KB per proof for h around 50 with N=256, tau=10 — roughly
    a quarter the size of the 5-pass proof it would replace at the local tier.
    """

    name = "mpcith"
    passes = 0
    available = False

    def rounds_for(self, security_bits=DEFAULT_SECURITY_BITS) -> int:
        return 10                                    # tau, at N = 256

    def _unavailable(self):
        raise NotImplementedError(
            "the MPC-in-the-head backend is specified in mq/mq.md but not "
            "implemented; run with a policy that maps the local tier to 'ssh5' "
            "(see ProofPolicy.runnable())")

    def prove(self, sys, v, known, z, rounds=None):
        self._unavailable()

    def verify(self, sys, v, known, proof) -> bool:
        self._unavailable()

    def serialize(self, proof) -> bytes:
        self._unavailable()


# ═══════════════════════════════════════════════════════════════════════════════
# Registry
# ═══════════════════════════════════════════════════════════════════════════════

BACKENDS = {b.name: b for b in (SSH5Backend(), SSH3Backend(), MPCitHBackend())}


def get_backend(name: str) -> ProofBackend:
    try:
        return BACKENDS[name]
    except KeyError:
        raise ProofError(f"unknown proof backend {name!r}; "
                         f"have {sorted(BACKENDS)}") from None


def available_backends():
    return sorted(n for n, b in BACKENDS.items() if b.available)
