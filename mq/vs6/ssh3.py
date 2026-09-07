"""SSH 3-pass MQ verification - verifier half, copied verbatim from the
prover-side module.

Nothing here imports the prover package.  chain/tests/test_mq_backends.py
asserts the retained functions are character-identical to their originals, which
is the bit-for-bit regression the package docstrings ask for.
"""
from __future__ import annotations

from .core import (FS_TAG, P, RestrictedMap, SEED_BYTES, _com, _fe_bytes, _fs_gamma, _round_rand, _statement, _vec_bytes, _vsub)


import hashlib

def fs_trits(stmt: bytes, commits, rounds: int):
    """Fiat-Shamir challenges in {0,1,2}, one per round, over the transcript."""
    h = hashlib.shake_256(FS_TAG.encode() + b"ssh3-ch" + stmt)
    for c0, c1, c2 in commits:
        h.update(c0 + c1 + c2)
    raw = h.digest(8 * rounds)
    return [int.from_bytes(raw[8 * i:8 * (i + 1)], "big") % 3
            for i in range(rounds)]

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
