"""MPC-in-the-head verification - verifier half, copied verbatim from the
prover-side module.

Nothing here imports the prover package, and nothing here can produce a proof:
the prover and the in-the-clear sacrifice check are dropped, so this module never
touches `secrets`.  chain/tests/test_mq_backends.py asserts the retained
functions are character-identical to their originals.
"""
from __future__ import annotations

from .core import (FIELD_BYTES, P, RestrictedMap, SEED_BYTES, _com, _fe_bytes, _fs_gamma, _fs_scalars, _statement, _vec_bytes)


import hashlib

DEFAULT_PARTIES = 16

SALT_BYTES = 32

def repetitions_for(security_bits: int = 80,
                    n_parties: int = DEFAULT_PARTIES) -> int:
    """tau = ceil(lambda / log2 N)."""
    bits = max(1, (n_parties - 1).bit_length())
    return -(-security_bits // bits)

def matvec_transpose(qf, Aflat, alpha):
    """A^T alpha, for A stored as core.py's flat upper triangle.

    (A v)[i] = sum_{j>=i} A_ij v_j, so <alpha, A v> = <v, A^T alpha> with
    (A^T alpha)[j] = sum_{i<=j} A_ij alpha_i.  Computing it once replaces one
    matvec per party with one dot product per party.
    """
    h, off = qf.h, qf.row_off
    out = [0] * h
    for i in range(h):
        ai = alpha[i]
        if not ai:
            continue
        base = off[i]
        row = Aflat[base:base + (h - i)]
        for k, coef in enumerate(row):
            if coef:
                out[i + k] += coef * ai
    return [x % P for x in out]

def party_broadcast_alpha(eps, z_share, a_share):
    return [(eps * zi + ai) % P for zi, ai in zip(z_share, a_share)]

def party_broadcast_sigma(BF, eps, u, z_share, c_share, is_first):
    d = 1 if is_first else 0
    acc = 0
    for bi, zi in zip(BF.b, z_share):
        acc += bi * zi
    dot = 0
    for ui, zi in zip(u, z_share):
        dot += ui * zi
    return (eps * (BF.t * d - acc - BF.c * d) - dot + c_share) % P

def _prg(seed: bytes, label: bytes) -> bytes:
    return hashlib.shake_256(b"mpcith-tree" + label + seed).digest(SEED_BYTES)

def _expand_subtree(seed: bytes, size: int):
    level = [seed]
    while len(level) < size:
        nxt = []
        for s in level:
            nxt.append(_prg(s, b"L"))
            nxt.append(_prg(s, b"R"))
        level = nxt
    return level[:size]

def tree_leaves(root: bytes, n_parties: int):
    return _expand_subtree(root, n_parties)

def tree_path(root: bytes, n_parties: int, hidden: int):
    """The sibling seeds that let a verifier rebuild every leaf but `hidden`."""
    depth = (n_parties - 1).bit_length()
    node, path = root, []
    for d in range(depth):
        left, right = _prg(node, b"L"), _prg(node, b"R")
        goes_right = (hidden >> (depth - d - 1)) & 1
        path.append(left if goes_right else right)
        node = right if goes_right else left
    return tuple(path)

def tree_rebuild(path, n_parties: int, hidden: int):
    """Every leaf seed except `hidden`, which stays None."""
    depth = (n_parties - 1).bit_length()
    if len(path) != depth:
        raise ValueError("seed path has the wrong depth")
    leaves = [None] * n_parties
    for d, sibling in enumerate(path):
        span = 1 << (depth - d - 1)
        sib_index = (hidden >> (depth - d - 1)) ^ 1
        start = sib_index * span
        for k, s in enumerate(_expand_subtree(sibling, span)):
            if start + k < n_parties:
                leaves[start + k] = s
    return leaves

def _party_field(seed: bytes, label: bytes, count: int):
    if count <= 0:
        return []
    k = FIELD_BYTES + 16
    raw = hashlib.shake_256(b"mpcith-share" + label + seed).digest(k * count)
    return [int.from_bytes(raw[k * i:k * (i + 1)], "big") % P
            for i in range(count)]

def _party_shares(seed: bytes, h: int, last: bool):
    """(z_share, a_share, c_share) for one party, from its seed.

    The last party's z and hint shares are corrections carried in the proof, so
    only its mask comes from the seed.
    """
    a_share = _party_field(seed, b"a", h)
    if last:
        return None, a_share, None
    vals = _party_field(seed, b"zc", h + 1)
    return vals[:h], a_share, vals[h]

def _commit(salt: bytes, rep: int, index: int, seed: bytes, extra=None):
    nonce = hashlib.shake_256(
        b"mpcith-nonce" + salt + rep.to_bytes(2, "big")
        + index.to_bytes(2, "big")).digest(32)
    return _com(nonce, extra or [], seed=seed)

def _hash_commitments(stmt: bytes, salt: bytes, coms) -> bytes:
    h = hashlib.shake_256(b"mpcith-com" + stmt + salt)
    for rep in coms:
        for c in rep:
            h.update(c)
    return h.digest(32)

def _hash_broadcasts(h_com: bytes, alphas, sigmas) -> bytes:
    h = hashlib.shake_256(b"mpcith-bc" + h_com)
    for rep_a, rep_s in zip(alphas, sigmas):
        for vec in rep_a:
            h.update(_vec_bytes(vec))
        for s in rep_s:
            h.update(_fe_bytes(s % P))
    return h.digest(32)

def _hidden_indices(h_bc: bytes, reps: int, n_parties: int):
    raw = hashlib.shake_256(b"mpcith-party" + h_bc).digest(8 * reps)
    return [int.from_bytes(raw[8 * i:8 * (i + 1)], "big") % n_parties
            for i in range(reps)]

def verify_mpcith(sys, v, known, proof) -> bool:
    """Verify an MPC-in-the-head proof.  Never raises."""
    if not isinstance(proof, dict) or proof.get("scheme") != "mpcith":
        return False
    try:
        n_parties = proof["parties"]
        reps = proof["reps"]
        salt = proof["salt"]
        hidden = list(proof["hidden"])
        if n_parties < 2 or (n_parties & (n_parties - 1)) or reps < 1:
            return False
        if not (len(hidden) == reps == len(proof["paths"])
                == len(proof["com_hidden"]) == len(proof["deltas"])
                == len(proof["alpha_hidden"]) == len(proof["sigma_hidden"])):
            return False
        if any(not 0 <= i < n_parties for i in hidden):
            return False

        R = RestrictedMap(sys, known)
        h = R.h
        stmt = _statement(v, known)
        BF = R.batched(_fs_gamma(stmt, sys.m), v)
        last = n_parties - 1

        # rebuild every party but the unopened one, and its commitment
        rebuilt, coms = [], []
        for rep in range(reps):
            i_star = hidden[rep]
            seeds = tree_rebuild(proof["paths"][rep], n_parties, i_star)
            delta = proof["deltas"][rep]
            if (delta is None) != (i_star == last):
                return False          # corrections must be withheld iff last is hidden
            if delta is not None:
                dz, dc = delta
                if len(dz) != h:
                    return False

            z_sh, a_sh, c_sh, rep_coms = [], [], [], []
            for i in range(n_parties):
                if i == i_star:
                    z_sh.append(None); a_sh.append(None); c_sh.append(None)
                    rep_coms.append(proof["com_hidden"][rep])
                    continue
                seed = seeds[i]
                if seed is None:
                    return False
                zi, ai, ci = _party_shares(seed, h, last=(i == last))
                if i == last:
                    zi, ci = [x % P for x in delta[0]], delta[1] % P
                    rep_coms.append(_commit(salt, rep, i, seed,
                                            list(zi) + [ci]))
                else:
                    rep_coms.append(_commit(salt, rep, i, seed))
                z_sh.append(zi); a_sh.append(ai); c_sh.append(ci)
            rebuilt.append((z_sh, a_sh, c_sh))
            coms.append(rep_coms)

        h_com = _hash_commitments(stmt, salt, coms)
        eps_all = _fs_scalars(b"mpcith-eps", h_com, reps)

        alphas, sigmas = [], []
        for rep in range(reps):
            i_star = hidden[rep]
            z_sh, a_sh, c_sh = rebuilt[rep]
            eps = eps_all[rep]

            rep_alpha = []
            for i in range(n_parties):
                if i == i_star:
                    vec = [x % P for x in proof["alpha_hidden"][rep]]
                    if len(vec) != h:
                        return False
                    rep_alpha.append(vec)
                else:
                    rep_alpha.append(party_broadcast_alpha(eps, z_sh[i], a_sh[i]))
            alpha = [sum(a_i[k] for a_i in rep_alpha) % P for k in range(h)]
            u = matvec_transpose(BF.qf, BF.A, alpha)

            rep_sigma = []
            for i in range(n_parties):
                if i == i_star:
                    rep_sigma.append(proof["sigma_hidden"][rep] % P)
                else:
                    rep_sigma.append(
                        party_broadcast_sigma(BF, eps, u, z_sh[i], c_sh[i], i == 0))

            if sum(rep_sigma) % P != 0:
                return False               # the sacrifice check
            alphas.append(rep_alpha)
            sigmas.append(rep_sigma)

        h_bc = _hash_broadcasts(h_com, alphas, sigmas)
        if _hidden_indices(h_bc, reps, n_parties) != hidden:
            return False                   # the party challenge must be the real one
        return True
    except Exception:
        return False

def serialize_proof_mpcith(proof) -> bytes:
    out = [proof["reps"].to_bytes(4, "big"), proof["parties"].to_bytes(4, "big"),
           proof["salt"]]
    for rep in range(proof["reps"]):
        out.append(proof["hidden"][rep].to_bytes(4, "big"))
        for s in proof["paths"][rep]:
            out.append(s)
        out.append(proof["com_hidden"][rep])
        delta = proof["deltas"][rep]
        if delta is not None:
            out.append(_vec_bytes(delta[0]))
            out.append(_fe_bytes(delta[1] % P))
        out.append(_vec_bytes(proof["alpha_hidden"][rep]))
        out.append(_fe_bytes(proof["sigma_hidden"][rep] % P))
    return b"".join(out)
