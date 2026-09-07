"""SSH 3-pass MQ identification, gamma-batched, Fiat-Shamir'd.

core.py moved to the 5-pass protocol and dropped its 3-pass path, leaving only
`rounds_for_security` behind to compute the round count the 2/3 soundness error
needs.  This restores the protocol on the same batched form, so both variants
prove the identical statement and a verifier can hold either.

The batched form gives one quadratic q(z) = <z,Az> + b.z + c with target t and a
bilinear polar G(a,b) = q(a+b) - q(a) - q(b) + q(0).  Since

    q(r0 + r1) = q(r0) + q(r1) + G(r0, r1) - c

the identity checked on challenge 1 is

    G(t0, r1) + e0  =  t - q(r1) + c - G(t1, r1) - e1                     (*)

with r1 = z - r0, t1 = r0 - t0, e1 = q(r0) - e0.

Per round the prover sends three commitments and answers one of three
challenges; a cheat can prepare at most two of the three, so the soundness error
is 2/3 per round and 2^-80 needs rounds_for_security(80) = 137 rounds.

Challenge 0's whole response is derivable from the round seed, so it costs
SEED_BYTES rather than 2h+1 field elements — the same trick the 5-pass uses.
"""
from __future__ import annotations

import hashlib
import secrets as _secrets

from .core import (FIELD_BYTES, FS_TAG, P, SEED_BYTES, RestrictedMap, _com,
                   _fe_bytes, _fs_gamma, _round_rand, _statement, _vec_bytes,
                   _vsub, rounds_for_security)

DEFAULT_ROUNDS_3PASS = rounds_for_security(80)          # 137


def fs_trits(stmt: bytes, commits, rounds: int):
    """Fiat-Shamir challenges in {0,1,2}, one per round, over the transcript."""
    h = hashlib.shake_256(FS_TAG.encode() + b"ssh3-ch" + stmt)
    for c0, c1, c2 in commits:
        h.update(c0 + c1 + c2)
    raw = h.digest(8 * rounds)
    return [int.from_bytes(raw[8 * i:8 * (i + 1)], "big") % 3
            for i in range(rounds)]


def prove_hidden3(sys, v, known, z, rounds: int = DEFAULT_ROUNDS_3PASS):
    """Gamma-batched 3-pass SSH proof of knowledge of z with F(embed(known,z)) = v."""
    R = RestrictedMap(sys, known)
    if len(z) != R.h:
        raise ValueError(f"witness has {len(z)} coords, {R.h} are hidden")
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
        commits.append((_com(n0, r1, [(BF.polar(t0, r1) + e0) % P]),
                        _com(n1, t0, [e0 % P]),
                        _com(n2, t1, [e1])))
        state.append((seed, r1, t0, t1, e0, e1, n0, n1, n2))

    chs = fs_trits(stmt, commits, rounds)
    responses = []
    for ch, (seed, r1, t0, t1, e0, e1, n0, n1, n2) in zip(chs, state):
        if ch == 0:
            responses.append((seed, n1, n2))        # seed regenerates r0,t0,e0
        elif ch == 1:
            responses.append((r1, t1, e1, n0, n2))
        else:
            responses.append((r1, t0, e0 % P, n0, n1))
    return {"passes": 3, "batched": True, "seeded": True, "rounds": rounds,
            "commits": commits, "responses": responses}


def verify_hidden3(sys, v, known, proof) -> bool:
    """Verify a gamma-batched 3-pass proof.  Never raises."""
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

        for ch, (c0, c1, c2), resp in zip(fs_trits(stmt, commits, rounds),
                                          commits, responses):
            if ch == 0:
                seed, n1, n2 = resp
                if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_BYTES:
                    return False
                r0, t0, e0 = _round_rand(bytes(seed), R.h)
                if _com(n1, t0, [e0 % P]) != c1:
                    return False
                if _com(n2, _vsub(r0, t0), [(BF.q(r0) - e0) % P]) != c2:
                    return False
            elif ch == 1:
                r1, t1, e1, n0, n2 = resp
                if len(r1) != R.h or len(t1) != R.h:
                    return False
                y = (BF.t - BF.q(r1) + BF.c - BF.polar(t1, r1) - e1) % P   # (*)
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


def serialize_proof3(proof) -> bytes:
    out = [proof["rounds"].to_bytes(4, "big")]
    for c0, c1, c2 in proof["commits"]:
        out.append(c0 + c1 + c2)
    for resp in proof["responses"]:
        if len(resp) == 3:
            seed, n1, n2 = resp
            out.append(b"\x00" + bytes(seed) + n1 + n2)
        else:
            a, b, e, x, y = resp
            out.append(b"\x01" + _vec_bytes(a) + _vec_bytes(b)
                       + _fe_bytes(e % P) + x + y)
    return b"".join(out)
