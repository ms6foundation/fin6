"""MPC-in-the-head proof for the gamma-batched MQ statement.

This is the construction mq.md specifies (the MQOM/Banquet line) and never
shipped: stages 1 and 2 lived in an ms6acc_mpcith.py that is not in this tree,
and stage 3 was designed but not written.  All three are here.

WHAT IS PROVED.  The same statement the 3- and 5-pass protocols prove: knowledge
of z with F(embed(known, z)) = v.  gamma-batching folds the m rows into one
quadratic  q(z) = <z,Az> + b.z + c  with target t, which core.py's DirectBatched
already accumulates straight from the sparse rows — so stage 1 is a view over it
plus one transpose, not a re-derivation.

THE PROTOCOL, per repetition.  N virtual parties hold additive shares [z].  The
prover also shares a random mask a and, once gamma is fixed, the hint
c_hint = <a, w> where w = Az.  Then for a challenge eps:

    [alpha]_i = eps*[z]_i + [a]_i                    -> broadcast, reconstruct alpha
    [sigma]_i = eps*(t*d_i - b.[z]_i - c*d_i) - <u, [z]_i> + [c_hint]_i

with u = A^T alpha and d_i = 1 for party 0 only.  Summing:

    sum sigma = eps*(t - b.z - c - <z,Az>) = eps*(t - q(z))

so the broadcasts sum to zero exactly when the claim holds, and a prover whose z
fails it survives only the one bad eps out of P.  Everything is linear in a
party's own shares given the public alpha; no Beaver triples.

TWO DEVIATIONS FROM mq.md, both deliberate.

  1. <alpha, [w]_i> is computed as <A^T alpha, [z]_i>.  mq.md has each party form
     [w]_i = A_gamma [z]_i, which is a matvec per party per repetition -- tau*N*h^2,
     the term it estimates at ~6M multiplications.  One transpose gives the same
     value for every party, so the cost falls to tau*(h^2 + N*h).  At N=256, h=48
     that is 40x less arithmetic and it is exact, not an approximation.

  2. No Delta_a.  mq.md corrects both z and a at the last party.  z must be
     corrected because it is fixed, and the hint because it is determined -- but a
     is an unconstrained random mask, so letting every party draw its share from
     its own seed leaves a still uniform and saves h field elements per repetition.

SOUNDNESS.  Per repetition ~1/N + 2/P: guessing the unopened party, or hitting
the one bad gamma or eps.  tau = ceil(lambda / log2 N), per mq.md.  That figure
counts a cheater grinding only the party challenge; a deployment wanting the
tighter KKW-style bound over all three Fiat-Shamir phases should raise tau.
"""
from __future__ import annotations

import hashlib
import secrets as _secrets

from .core import (FIELD_BYTES, P, SEED_BYTES, RestrictedMap, _com, _fe_bytes,
                   _fs_gamma, _fs_scalars, _statement, _vec_bytes)

DEFAULT_PARTIES = 16
SALT_BYTES = 32


def repetitions_for(security_bits: int = 80,
                    n_parties: int = DEFAULT_PARTIES) -> int:
    """tau = ceil(lambda / log2 N)."""
    bits = max(1, (n_parties - 1).bit_length())
    return -(-security_bits // bits)


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1 — the explicit quadratic, and the transpose the protocol needs
# ═══════════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2 — the sacrifice check, in the clear
# ═══════════════════════════════════════════════════════════════════════════════

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


def sacrifice_check_in_the_clear(BF, z, n_parties: int, eps: int, rng=None):
    """mq.md's stage 2: run the check with every view public.

    Returns (sum_sigma, alpha).  Honest runs sum to zero; a z that fails the
    claim survives only for one eps in P.
    """
    rnd = rng or _secrets
    h = len(z)
    z_shares = [[rnd.randbelow(P) for _ in range(h)] for _ in range(n_parties - 1)]
    z_shares.append([(z[k] - sum(s[k] for s in z_shares)) % P for k in range(h)])
    a_shares = [[rnd.randbelow(P) for _ in range(h)] for _ in range(n_parties)]
    a = [sum(s[k] for s in a_shares) % P for k in range(h)]

    w = BF.qf.matvec(BF.A, z)
    hint = sum(ai * wi for ai, wi in zip(a, w)) % P
    c_shares = [rnd.randbelow(P) for _ in range(n_parties - 1)]
    c_shares.append((hint - sum(c_shares)) % P)

    alphas = [party_broadcast_alpha(eps, z_shares[i], a_shares[i])
              for i in range(n_parties)]
    alpha = [sum(a_i[k] for a_i in alphas) % P for k in range(h)]
    u = matvec_transpose(BF.qf, BF.A, alpha)
    total = sum(party_broadcast_sigma(BF, eps, u, z_shares[i], c_shares[i], i == 0)
                for i in range(n_parties)) % P
    return total, alpha


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 3 — seed trees, view commitments, three-phase Fiat-Shamir
# ═══════════════════════════════════════════════════════════════════════════════

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


def prove_mpcith(sys, v, known, z, n_parties: int = DEFAULT_PARTIES,
                 reps: int | None = None, security_bits: int = 80):
    """MPC-in-the-head proof of knowledge of z with F(embed(known, z)) = v."""
    if n_parties < 2 or (n_parties & (n_parties - 1)):
        raise ValueError("n_parties must be a power of two, at least 2")
    reps = reps or repetitions_for(security_bits, n_parties)

    R = RestrictedMap(sys, known)
    if len(z) != R.h:
        raise ValueError(f"witness has {len(z)} coords, {R.h} are hidden")
    h = R.h
    stmt = _statement(v, known)
    BF = R.batched(_fs_gamma(stmt, sys.m), v)
    w = BF.qf.matvec(BF.A, z)

    salt = _secrets.token_bytes(SALT_BYTES)
    roots, seeds_all, coms, deltas = [], [], [], []
    shares = []                                   # per rep: (z_shares, a_shares, c_shares)

    for rep in range(reps):
        root = _secrets.token_bytes(SEED_BYTES)
        seeds = tree_leaves(root, n_parties)
        z_sh, a_sh, c_sh = [], [], []
        for i in range(n_parties):
            zi, ai, ci = _party_shares(seeds[i], h, last=(i == n_parties - 1))
            z_sh.append(zi)
            a_sh.append(ai)
            c_sh.append(ci)

        dz = [(z[k] - sum(s[k] for s in z_sh[:-1])) % P for k in range(h)]
        z_sh[-1] = dz
        a = [sum(s[k] for s in a_sh) % P for k in range(h)]
        hint = sum(ai * wi for ai, wi in zip(a, w)) % P
        dc = (hint - sum(c_sh[:-1])) % P
        c_sh[-1] = dc

        rep_coms = [_commit(salt, rep, i, seeds[i]) for i in range(n_parties - 1)]
        rep_coms.append(_commit(salt, rep, n_parties - 1, seeds[-1], dz + [dc]))

        roots.append(root)
        seeds_all.append(seeds)
        coms.append(rep_coms)
        deltas.append((dz, dc))
        shares.append((z_sh, a_sh, c_sh))

    # ── phase 1: commitments fix eps ─────────────────────────────────────────
    h_com = _hash_commitments(stmt, salt, coms)
    eps_all = _fs_scalars(b"mpcith-eps", h_com, reps)

    # ── phase 2: broadcasts fix the unopened party ───────────────────────────
    alphas, sigmas = [], []
    for rep in range(reps):
        z_sh, a_sh, c_sh = shares[rep]
        eps = eps_all[rep]
        rep_alpha = [party_broadcast_alpha(eps, z_sh[i], a_sh[i])
                     for i in range(n_parties)]
        alpha = [sum(a_i[k] for a_i in rep_alpha) % P for k in range(h)]
        u = matvec_transpose(BF.qf, BF.A, alpha)
        rep_sigma = [party_broadcast_sigma(BF, eps, u, z_sh[i], c_sh[i], i == 0)
                     for i in range(n_parties)]
        alphas.append(rep_alpha)
        sigmas.append(rep_sigma)

    h_bc = _hash_broadcasts(h_com, alphas, sigmas)
    hidden = _hidden_indices(h_bc, reps, n_parties)

    # ── phase 3: open every party but one ────────────────────────────────────
    proof = {
        "scheme": "mpcith", "parties": n_parties, "reps": reps, "salt": salt,
        "hidden": hidden,
        "paths": [tree_path(roots[r], n_parties, hidden[r]) for r in range(reps)],
        "com_hidden": [coms[r][hidden[r]] for r in range(reps)],
        # the last party's corrections, withheld when it is the unopened one
        "deltas": [None if hidden[r] == n_parties - 1 else deltas[r]
                   for r in range(reps)],
        "alpha_hidden": [alphas[r][hidden[r]] for r in range(reps)],
        "sigma_hidden": [sigmas[r][hidden[r]] for r in range(reps)],
    }
    return proof


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
