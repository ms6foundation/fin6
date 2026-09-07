"""vs6/core.py — verifier side of the MQ-hardened ms6mq commitment.

This module intentionally has ZERO import dependency on ms6/core.py.  All
shared logic (MQSystem, RestrictedMap, verify_hidden, hash_to_field,
_mq_batch_digest, _mq_leaf, seal-tree helpers) is duplicated here so that a
pure verifier can be deployed, audited, and installed without dragging in any
prover-only code paths (salt generation, SystemRandom, prove_hidden, etc.).

If either copy of a shared function changes, the other must be updated to
match — there is no automated enforcement; a bit-for-bit regression test
across the two modules is the recommended follow-up.

Public entry point
------------------
vs6(c, claims, ps_list, x_list, sys, params, workers=1, expect=None) → True

`ps_list[b]` is either:
    - str                    — untouched batch (leaf copied straight from ms6)
    - {"salts":…, "proof":…, "v":…}  — touched batch (SSH proof)

vs6 verifies each touched batch's SSH proof and reconstructs the seal-tree
root independently, then checks it equals `c`.
"""
import hashlib

from . import utils6 as u

# ── MQ field prime (defined first; DEFAULT_MOD derives from it) ──────────────
P            = 2 ** 255 - 19            # Curve25519 prime  (255-bit)
FIELD_BYTES  = 32

ut = u.Utils()

# ── outer-scheme defaults ─────────────────────────────────────────────────────
DEFAULT_CHUNK_SIZE      = 100
DEFAULT_BATCH_SIZE      = 1000
DEFAULT_WORKERS         = 1
DEFAULT_SEAL_BATCH_SIZE = 1000
# Seal fold and batch fold both operate in F_P — must match ms6/core.py.
DEFAULT_MOD             = P

# ── MQ constants (must stay identical to ms6/core.py) ─────────────────────────
ITEM_TAG     = "ms6mq-item"
SYS_TAG      = "ms6mq-sys"
COM_TAG      = "ms6mq-com"
FS_TAG       = "ms6mq-fs"
BATCH_TAG    = "ms6mq-batch"
SEAL_TAG     = "ms6-seal"

DEFAULT_BLINDERS = 8
DEFAULT_ROUNDS   = 80
DEFAULT_FOLDS    = 8
GEOMETRIC_CAP_DIVISOR = 4
SEED_BYTES = 16   # must match ms6/core.py

# Must match ms6/core.py PARAM_KEYS (with "blinders" replacing "rand_edge_size").
PARAM_KEYS = ("d", "chunk_size", "batch_size", "mod", "seal_batch_size", "blinders")


# ═══════════════════════════════════════════════════════════════════════════════
# Field helpers (duplicated from ms6/core.py per zero-prover-dep rule)
# ═══════════════════════════════════════════════════════════════════════════════

def _fe_bytes(a):
    return int(a).to_bytes(FIELD_BYTES, "big")


def _vec_bytes(vec):
    return b"".join(_fe_bytes(a) for a in vec)


def _vadd(a, b):
    return [(u_ + w) % P for u_, w in zip(a, b)]


def _vsub(a, b):
    return [(u_ - w) % P for u_, w in zip(a, b)]


def hash_to_field(global_index, salt, value):
    """Random-oracle map matching ms6/core.py's copy."""
    seed = f"{ITEM_TAG}:{global_index}:{salt}:{value}".encode()
    return int.from_bytes(hashlib.shake_256(seed).digest(48), "big") % P


# ═══════════════════════════════════════════════════════════════════════════════
# MQ system (duplicated from ms6/core.py)
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from gmpy2 import mpz as _mpz
    _HAVE_GMP = True
except ImportError:
    _mpz = int
    _HAVE_GMP = False


class MQSystem:
    """Duplicated from ms6/core.py per zero-prover-dependency rule."""

    def __init__(self, n, fold_degree=2, m_rand=None, n_folds=DEFAULT_FOLDS,
                 fold_weights="random", fold_bases=None, seed=SYS_TAG,
                 insecure_ok=False):
        if n < 2 or fold_degree < 2:
            raise ValueError("need n >= 2 and fold_degree >= 2")
        self.n = n
        self.K = K = fold_degree
        self.seed = seed
        self.m_rand = (n - 1) if m_rand is None else m_rand

        if self.m_rand < n - 1 and not insecure_ok:
            raise ValueError(
                f"m_rand={self.m_rand} < n-1={n-1}: the dense random rows are "
                "what puts the system in the generic MQ regime; folds are a "
                "supplement only (pass insecure_ok=True for experiments)")

        if fold_weights == "geometric":
            if fold_bases is None:
                fold_bases = [10, 3, 7, 11, 13, 17, 19, 23][:n_folds]
            self.bases = [b % P for b in fold_bases]
            if len(set(self.bases)) != len(self.bases):
                raise ValueError("fold_bases must be distinct")
            dim = K * (n - 1) + 1
            cap = max(1, dim // GEOMETRIC_CAP_DIVISOR)
            if len(self.bases) > cap and not insecure_ok:
                raise ValueError(
                    f"{len(self.bases)} geometric folds: the geometric family "
                    f"spans a bucket space of dim {dim} and becomes peelable "
                    f"near it; at most {cap} (= dim/{GEOMETRIC_CAP_DIVISOR}) "
                    "are allowed (pass insecure_ok=True for experiments)")
            self.W = [[pow(b, n - 1 - p, P) for p in range(n)]
                      for b in self.bases]
        elif fold_weights == "random":
            self.bases = None
            self.W = []
            for f in range(n_folds):
                h = hashlib.shake_256(
                    f"{seed}:foldw:{n}:{K}:{f}".encode())
                raw = h.digest(48 * n)
                self.W.append([
                    int.from_bytes(raw[48 * p:48 * (p + 1)], "big") % P or 1
                    for p in range(n)
                ])
        else:
            raise ValueError("fold_weights must be 'geometric' or 'random'")
        self.fold_weights = fold_weights
        self.n_folds = len(self.W)

        self.aux_per_fold = 0 if K == 2 else n * (K - 1)
        self.n_aux = self.n_folds * self.aux_per_fold
        self.N = n + self.n_aux
        self.n_cons = self.n_aux
        self.m = self.m_rand + self.n_cons + self.n_folds

        self.idx = {}
        L = self.N
        k = 0
        for s in range(2 * L - 1):
            for i in range(max(0, s - L + 1), s // 2 + 1):
                self.idx[(i, s - i)] = k
                k += 1
        self.nmono = k

        self.Q, self.Lin = [], []
        self.Qs, self.Lins, self.kind = [], [], []
        nbase = n * (n + 1) // 2
        for l in range(self.m_rand):
            h = hashlib.shake_256(f"{seed}:{n}:{K}:{self.m_rand}:{l}".encode())
            raw = h.digest(48 * nbase)
            q = [0] * self.nmono
            t = 0
            for i in range(n):
                for j in range(i, n):
                    q[self.idx[(i, j)]] = (
                        int.from_bytes(raw[48 * t:48 * (t + 1)], "big") % P)
                    t += 1
            self._add_row(q, [0] * self.N)
        self.fold_rows = []
        for f, w in enumerate(self.W):
            if K == 2:
                q = [0] * self.nmono
                for i in range(n):
                    for j in range(i, n):
                        q[self.idx[(i, j)]] = w[i] * w[j] % P
                self.fold_rows.append(len(self.Q))
                self._add_row(q, [0] * self.N, kind=("fold", f))
                continue
            a = lambda p, c, f=f: self._aux_index(f, p, c)
            for p in range(n):
                for c in range(2, K + 1):
                    q, lin = [0] * self.nmono, [0] * self.N
                    lin[a(p, c)] = 1
                    if p >= 1:
                        lin[a(p - 1, c)] = P - 1
                    if c - 1 >= 2:
                        q[self.idx[self._key(a(p, c - 1), p)]] = (P - w[p]) % P
                    else:
                        for qq in range(p + 1):
                            key = self.idx[self._key(qq, p)]
                            q[key] = (q[key] - w[qq] * w[p]) % P
                    self._add_row(q, lin)
            lin = [0] * self.N
            lin[a(n - 1, K)] = 1
            self.fold_rows.append(len(self.Q))
            self._add_row([0] * self.nmono, lin)
        assert len(self.Q) == self.m

    @staticmethod
    def _key(i, j):
        return (i, j) if i <= j else (j, i)

    def _aux_index(self, f, p, c):
        return self.n + f * self.aux_per_fold + p * (self.K - 1) + (c - 2)

    def _add_row(self, q, lin, kind=None):
        if _HAVE_GMP:
            q   = [_mpz(v) for v in q]
            lin = [_mpz(v) for v in lin]
        self.Q.append(q)
        self.Lin.append(lin)
        self.Qs.append([(k, c) for k, c in enumerate(q) if c])
        self.Lins.append([(k, c) for k, c in enumerate(lin) if c])
        self.kind.append(kind)

    @staticmethod
    def fast_h2(w, x, n=None):
        """h_2(w∘x) = (e₁² + p₂)/2 mod P in O(n) using Newton's identity."""
        e1 = p2 = 0
        for wi, xi in zip(w, x):
            y   = wi * xi % P
            e1 += y
            p2 += y * y
        return (e1 % P * (e1 % P) + p2) % P * ((P + 1) // 2) % P

    @staticmethod
    def monomials(X):
        return [mk for bucket in ut.eval_level_mod_fast(2, [int(a) % P for a in X], P)
                for mk in bucket]

    def fold(self, x, f):
        nz = [i for i in range(len(x)) if x[i]]
        if not nz:
            return 0
        pmax = max(nz)
        inv10 = pow(10, P - 2, P)
        w = self.W[f]
        xs = [x[p] * w[p] % P * pow(inv10, pmax - p, P) % P
              for p in range(len(x))]
        return int(ut.vsum_level_fold_fast(self.K, xs, P))

    def lift(self, x):
        x = [int(a) % P for a in x]
        assert len(x) == self.n
        if self.n_aux == 0:
            return list(x)
        aux = [0] * self.n_aux
        for f, w in enumerate(self.W):
            dp = [1] + [0] * self.K
            for p in range(self.n):
                yp = w[p] * x[p] % P
                for c in range(1, self.K + 1):
                    dp[c] = (dp[c] + dp[c - 1] * yp) % P
                if self.K > 2:
                    for c in range(2, self.K + 1):
                        aux[self._aux_index(f, p, c) - self.n] = dp[c]
        return x + aux

    def F(self, X):
        """Evaluate F; K=2 fold rows use fast_h2 O(n), rest use sparse dot product."""
        assert len(X) == self.N
        X    = [int(a) % P for a in X]
        mono = None
        out  = []
        for qs, lins, kind in zip(self.Qs, self.Lins, self.kind):
            if kind is not None and kind[0] == "fold":
                out.append(self.fast_h2(self.W[kind[1]], X[:self.n]))
                continue
            if mono is None and qs:
                mono = self.monomials(X)
            acc = 0
            for k, c in qs:
                acc += c * mono[k]
            for k, c in lins:
                acc += c * X[k]
            out.append(int(acc % P))
        return out


class RestrictedMap:
    def __init__(self, sys, known):
        self.sys    = sys
        self.known  = dict(known)
        self.hidden = [i for i in range(sys.N) if i not in self.known]
        self.h      = len(self.hidden)
        if self.h == 0:
            raise ValueError("nothing hidden")
        self.F0 = self.F([0] * self.h)

    def embed(self, z):
        x = [0] * self.sys.N
        for i, a in self.known.items():
            x[i] = a
        for i, a in zip(self.hidden, z):
            x[i] = a
        return x

    def F(self, z):
        return self.sys.F(self.embed(z))

    def G(self, a, b):
        fab = self.F(_vadd(a, b))
        fa  = self.F(a)
        fb  = self.F(b)
        return [(u_ - w - t + f0) % P
                for u_, w, t, f0 in zip(fab, fa, fb, self.F0)]

    def batched(self, gamma, v):
        """Fold the m rows into ONE quadratic q(z) = <z,Az> + b.z + c with
        target t = <gamma, v>.  Uses DirectBatched (O(h²) memory, no per-row
        A_l materialisation) — mandatory for LedgerSystem with range bits."""
        db = DirectBatched.from_restricted(self, gamma, v)
        return _Batched(db, db.A, db.b, db.c, db.t)


class DirectBatched:
    """The gamma-batched quadratic  q(z) = <z,Az> + b.z + c,  accumulated
    STRAIGHT from the sparse rows of the system.

    Duplicated verbatim from ms6/core.py per the zero-prover-dependency rule:
    vs6 must import nothing from ms6."""

    __slots__ = ("h", "A", "b", "c", "t", "row_off", "ntri")

    def __init__(self, h, A, b, c, t, row_off):
        self.h, self.A, self.b, self.c, self.t = h, A, b, c, t
        self.row_off, self.ntri = row_off, h * (h + 1) // 2

    @classmethod
    def from_restricted(cls, R, gamma, v):
        sys, h = R.sys, R.h
        pos = {p: kk for kk, p in enumerate(R.hidden)}
        known = R.known
        row_off = [i * h - i * (i - 1) // 2 for i in range(h)]
        inv = getattr(sys, "_inv_idx", None)
        if inv is None:
            inv = [None] * sys.nmono
            for (i, j), kk in sys.idx.items():
                inv[kk] = (i, j)
            sys._inv_idx = inv
        A = [0] * (h * (h + 1) // 2)
        b = [0] * h
        c = t = 0
        for g, terms, lterms, vl in zip(gamma, sys.Qs, sys.Lins, v):
            t += g * vl
            if not g:
                continue
            for kk, coef in terms:
                i, j = inv[kk]
                coef = g * int(coef)
                pi, pj = pos.get(i), pos.get(j)
                if pi is not None and pj is not None:
                    a_, b_ = (pi, pj) if pi <= pj else (pj, pi)
                    A[row_off[a_] + (b_ - a_)] += coef
                elif pi is not None:
                    b[pi] += coef * known[j]
                elif pj is not None:
                    b[pj] += coef * known[i]
                else:
                    c += coef * known[i] * known[j]
            for i, coef in lterms:
                coef = g * int(coef)
                pi = pos.get(i)
                if pi is not None:
                    b[pi] += coef
                else:
                    c += coef * known[i]
        return cls(h, [x % P for x in A], [x % P for x in b], c % P, t % P, row_off)

    def matvec(self, Aflat, z):
        h, off = self.h, self.row_off
        out = []
        for i in range(h):
            base = off[i]
            acc = 0
            for a, zj in zip(Aflat[base:base + (h - i)], z[i:]):
                if a:
                    acc += a * zj
            out.append(acc % P)
        return out


class _Batched:
    """Single batched quadratic form q(z) = <z,Az> + b.z + c and its polar."""
    __slots__ = ("qf", "A", "b", "c", "t")

    def __init__(self, qf, A, b, c, t):
        self.qf, self.A, self.b, self.c, self.t = qf, A, b, c, t

    def q(self, z):
        w = self.qf.matvec(self.A, z)
        acc = 0
        for zi, wi in zip(z, w):
            acc += zi * wi
        for bi, zi in zip(self.b, z):
            acc += bi * zi
        return (acc + self.c) % P

    def polar(self, a, b):
        mv = self.qf.matvec
        acc = 0
        for x, y in zip(a, mv(self.A, b)):
            acc += x * y
        for x, y in zip(b, mv(self.A, a)):
            acc += x * y
        return acc % P


# ═══════════════════════════════════════════════════════════════════════════════
# SSH 5-pass verification — gamma-batched (duplicated from ms6/core.py)
# ═══════════════════════════════════════════════════════════════════════════════

def _com(nonce, *vecs, seed=None):
    h = hashlib.shake_256(COM_TAG.encode() + nonce)
    if seed is not None:
        h.update(b"s" + seed)
    for v in vecs:
        h.update(len(v).to_bytes(4, "big"))
        h.update(_vec_bytes(v))
    return h.digest(32)


def _fs_scalars(tag, transcript, count):
    k = FIELD_BYTES + 16
    raw = hashlib.shake_256(FS_TAG.encode() + tag + transcript).digest(k * count)
    return [int.from_bytes(raw[k * i:k * (i + 1)], "big") % P for i in range(count)]


def _fs_gamma(stmt, m):
    return _fs_scalars(b"gamma", stmt, m)


def _fs_alpha(statement, commits, rounds):
    """Fiat-Shamir challenge 1: alpha_i uniform in F_P from the commitments."""
    h = hashlib.shake_256()
    for c0, c1 in commits:
        h.update(c0 + c1)
    return _fs_scalars(b"alpha", statement + h.digest(32), rounds)


def _fs_bits(statement, commits, alphas, mids, rounds):
    """Fiat-Shamir challenge 2: Ch_i in {0,1} from the whole transcript."""
    h = hashlib.shake_256(FS_TAG.encode() + b"ch" + statement)
    for c0, c1 in commits:
        h.update(c0 + c1)
    h.update(_vec_bytes(alphas))
    for t1, e1 in mids:
        h.update(_vec_bytes(t1) + _fe_bytes(e1))   # e1 is a scalar
    raw = h.digest((rounds + 7) // 8)
    return [(raw[i // 8] >> (i % 8)) & 1 for i in range(rounds)]


def _statement(v, known):
    h = hashlib.shake_256(b"stmt")
    h.update(_vec_bytes(v))
    for i in sorted(known):
        h.update(i.to_bytes(4, "big") + _fe_bytes(known[i]))
    return h.digest(32)


def _round_rand(seed, h):
    """Expand a SEED_BYTES-byte round seed → (r0, t0, e0_scalar) via SHAKE128."""
    k = FIELD_BYTES + 16
    raw = hashlib.shake_128(b"rr" + seed).digest(k * (2 * h + 1))
    vals = [int.from_bytes(raw[k * i:k * (i + 1)], "big") % P for i in range(2 * h + 1)]
    return vals[:h], vals[h:2 * h], vals[2 * h]


def verify_hidden(sys, v, known, proof):
    """Verify a gamma-batched 5-pass SSH proof produced by prove_hidden."""
    if proof.get("passes") != 5 or not proof.get("batched"):
        return False
    R       = RestrictedMap(sys, known)
    rounds  = proof["rounds"]
    commits, mids, responses = proof["commits"], proof["mids"], proof["responses"]
    if not (len(commits) == len(mids) == len(responses) == rounds):
        return False
    stmt   = _statement(v, known)
    BF     = R.batched(_fs_gamma(stmt, sys.m), v)
    alphas = _fs_alpha(stmt, commits, rounds)
    bits   = _fs_bits(stmt, commits, alphas, mids, rounds)
    for ch, a, (c0, c1), (t1, e1), (r, nonce) in zip(bits, alphas, commits, mids, responses):
        if len(t1) != R.h:
            return False
        if ch == 0:
            if not isinstance(r, (bytes, bytearray)) or len(r) != SEED_BYTES:
                return False
            r0, t0, e0 = _round_rand(bytes(r), R.h)
            if _com(nonce, [], [], [], seed=bytes(r)) != c0:
                return False
            if _vsub([a * ri % P for ri in r0], t0) != list(t1) or (a * BF.q(r0) - e0) % P != e1 % P:
                return False
        else:
            if len(r) != R.h:
                return False
            y = (a * (BF.t - BF.q(r) + BF.c) - BF.polar(t1, r) - e1) % P
            if _com(nonce, r, [y]) != c1:
                return False
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# MQ batch helpers (duplicated from ms6/core.py)
# ═══════════════════════════════════════════════════════════════════════════════

def _mq_batch_digest(v):
    return int.from_bytes(
        hashlib.shake_256(BATCH_TAG.encode() + _vec_bytes(v)).digest(32), "big")


def _mq_leaf(v):
    return _seal_hash(_mq_batch_digest(v))


def _grid_seal(xi, chunk_size, d, mod):
    """Map one field element through the digit-prime grid and fold it.

    Must stay identical to ms6/core.py's copy (zero-prover-dep rule).
    Returns an integer in [0, P).
    """
    x_rows     = _seal_fold_rows(chunk_size)
    target_len = x_rows * chunk_size
    chunk_fn   = chunks(x_rows, chunk_size)
    _dp        = [u.DIGIT_PRIMES[v] % mod for v in range(10)]
    xi_str     = ut.sparse_expand(str(xi), target_len, mod)
    combined   = [1] * chunk_size
    for row_str in chunk_fn(xi_str):
        for j, ch in enumerate(row_str):
            p = _dp[int(ch)] if ch.isdigit() else 1
            combined[j] = combined[j] * p % mod
    return int(ut.vsum_level_fold_fast(d, combined, mod)) % P


# ═══════════════════════════════════════════════════════════════════════════════
# Params
# ═══════════════════════════════════════════════════════════════════════════════

def _brief(v):
    if isinstance(v, int) and v.bit_length() > 64:
        return f"<{v.bit_length()}-bit int ...{str(v)[-6:]}>"
    return repr(v)


class ParamMismatch(ValueError):
    """params did not match the caller's expect= pins."""


def _validate_params(params, expect=None):
    missing = [k for k in PARAM_KEYS if k not in params]
    if missing:
        raise KeyError(f"params missing required key(s): {', '.join(missing)}")
    for k in ("d", "chunk_size", "batch_size", "seal_batch_size", "blinders"):
        v = params[k]
        if not isinstance(v, int) or v < 1:
            raise ParamMismatch(f"params[{k!r}] must be a positive int, got {v!r}")
    if not isinstance(params["mod"], int) or params["mod"] < 2:
        raise ParamMismatch(f"params['mod'] must be an int >= 2, got {params['mod']!r}")
    if expect:
        unknown = [k for k in expect if k not in PARAM_KEYS]
        if unknown:
            raise ParamMismatch(f"expect has unknown key(s): {', '.join(sorted(unknown))}")
        bad = {k: (expect[k], params[k]) for k in expect if params[k] != expect[k]}
        if bad:
            detail = "; ".join(f"{k}: expected {_brief(e)}, got {_brief(g)}"
                               for k, (e, g) in sorted(bad.items()))
            raise ParamMismatch(f"params do not match expect -- {detail}")


def unpack_params(params, expect=None):
    """params → (d, chunk_size, batch_size, mod, seal_batch_size, blinders)."""
    _validate_params(params, expect)
    return tuple(params[k] for k in PARAM_KEYS)


# ═══════════════════════════════════════════════════════════════════════════════
# Seal-tree helpers (duplicated from ms6/core.py per zero-prover-dep rule)
# ═══════════════════════════════════════════════════════════════════════════════

FLUSH = 4096


def _seal_hash(val):
    """Must stay identical to ms6/core.py's copy."""
    return ut.domain_hash(f"{SEAL_TAG}:{val}".encode())


def _seal_fold_rows(chunk_size):
    return -(-u.DOMAIN_HASH_DIGITS // chunk_size)


def chunk_of(val, x, chunk_size):
    chunks_list = list(ut.backward_chunk(val, chunk_size))
    chunks_list[0] = f"{chunks_list[0]:{u.PAD}>{chunk_size}}"
    return [u.PAD * chunk_size] * (x - len(chunks_list)) + chunks_list


def chunks(x, chunk_size):
    def internal(val):
        return chunk_of(val, x, chunk_size)
    return internal


def _seal_from_counts(cnt, chunk_size, d, mod):
    H = [[ut.cell_product_mod(cnt[i][j], 1, mod) for j in range(chunk_size)]
         for i in range(len(cnt))]
    H = [ut.vsum_level_fold_fast(d, H1, mod) for H1 in H]
    return ut.vsum_level(H, b=chunk_size)


def _seal_batch_flat(vals, chunk_size, x, d, mod):
    accH     = u.Acc(x, chunk_size)
    chunk_fn = chunks(x, chunk_size)
    for t, val in enumerate(vals):
        accH.add(chunk_fn(val))
        if (t & (FLUSH - 1)) == FLUSH - 1:
            accH.flush()
    accH.flush()
    return _seal_from_counts(accH.cnt, chunk_size, d, mod)


def _seal_batch(vals, chunk_size, x, d, mod=DEFAULT_MOD,
                seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
    vals = list(vals)
    if len(vals) > seal_batch_size:
        vals = [
            _seal_hash(_seal_batch(vals[start:start + seal_batch_size],
                                   chunk_size, x, d, mod, seal_batch_size))
            for start in range(0, len(vals), seal_batch_size)
        ]
        return _seal_batch(vals, chunk_size, x, d, mod, seal_batch_size)
    return _seal_batch_flat(vals, chunk_size, x, d, mod)


def _get_batch_ids(indices, batch_size=DEFAULT_BATCH_SIZE):
    return [index // batch_size for index in indices]


def _vs6_from_copath(h_by_batch, touched, copath, n_batches, chunk_size, x,
                     d, mod, sbs):
    """Reconstruct root c from touched h values and compact copath."""
    active_vals = dict(h_by_batch)
    active_set  = set(touched)
    n_current   = n_batches

    for k, siblings_by_group in enumerate(copath):
        is_last   = (k == len(copath) - 1)
        next_vals = {}
        for g, sibs in siblings_by_group.items():
            g_start  = g * sbs
            g_end    = min((g + 1) * sbs, n_current)
            sib_iter = iter(sibs)
            group    = []
            for j in range(g_start, g_end):
                group.append(active_vals[j] if j in active_set
                             else next(sib_iter))
            raw = _seal_batch_flat(group, chunk_size, x, d, mod)
            next_vals[g] = raw if is_last else _seal_hash(raw)
        active_vals = next_vals
        active_set  = set(next_vals)
        n_current   = -(-n_current // sbs)

    assert len(active_vals) == 1
    return next(iter(active_vals.values()))


# ═══════════════════════════════════════════════════════════════════════════════
# MQ batch verifier
# ═══════════════════════════════════════════════════════════════════════════════

def _vs6_mq_batch(b, claims_b, ps_b, sys, batch_size, d, chunk_size, mod):
    """Verify one touched batch and return its seal-tree leaf.

    claims_b  : dict {global_index → claimed_value}
    ps_b      : {"salts": {gi: salt},        — all items in touched chunks
                 "vals":  {gi: val},          — non-claimed items in touched chunks
                 "proof": ssh_proof,
                 "v":     v_b}

    Reconstructs known[chunk_idx] = joint column-product fold of all items in
    chunk_idx, then verifies the SSH proof against those known coordinates.
    """
    start       = b * batch_size
    salts       = ps_b["salts"]       # {gi: salt | None-if-tombstone}
    extra_vals  = ps_b.get("vals", {})  # {gi: val} for non-claimed items

    x_rows     = _seal_fold_rows(chunk_size)
    target_len = x_rows * chunk_size
    chunk_fn   = chunks(x_rows, chunk_size)
    _dp        = [u.DIGIT_PRIMES[v] % mod for v in range(10)]

    # Determine which x_mq slots are touched.
    local_claimed = {gi - start for gi in claims_b}
    chunk_idxs    = {local_j // chunk_size for local_j in local_claimed}

    # For each touched chunk: reconstruct x_mq[chunk_idx] via joint fold.
    known = {}
    for ci in chunk_idxs:
        combined = [1] * chunk_size
        for local_j in range(ci * chunk_size, (ci + 1) * chunk_size):
            gi = start + local_j
            if gi in claims_b:
                salt = salts.get(gi)
                xi   = hash_to_field(gi, salt, claims_b[gi])
            elif gi in salts:
                salt = salts[gi]
                xi   = 0 if salt is None else hash_to_field(gi, salt, extra_vals[gi])
            else:
                break  # chunk is shorter than chunk_size (end of batch)
            xi_str = ut.sparse_expand(str(xi), target_len, mod)
            for row_str in chunk_fn(xi_str):
                for j, ch in enumerate(row_str):
                    p = _dp[int(ch)] if ch.isdigit() else 1
                    combined[j] = combined[j] * p % mod
        known[ci] = int(ut.vsum_level_fold_fast(d, combined, mod)) % P

    v_b = ps_b["v"]
    if not verify_hidden(sys, v_b, known, ps_b["proof"]):
        raise AssertionError(f"SSH proof failed for batch {b}")

    return _mq_leaf(v_b)


# ═══════════════════════════════════════════════════════════════════════════════
# vs6 — public verifier
# ═══════════════════════════════════════════════════════════════════════════════

def vs6(c, claims, ps_list, x_list, sys, params,
        workers=DEFAULT_WORKERS, expect=None):
    """Verify an MQ-hardened opening and return True if valid.

    Parameters
    ----------
    c        : root commitment from ms6()
    claims   : {global_index: claimed_value}
    ps_list  : return value of ps6() — list or compact dict
    x_list   : per-batch seal-fold rows from ms6()  [all equal]
    sys      : MQSystem from ms6()
    params   : parameter dict from ms6()
    workers  : number of parallel workers (>1 parallelises across batches)
    expect   : optional dict pinning known-good param values

    Raises AssertionError if the proof is invalid.
    Raises ParamMismatch if params do not match expect.
    Returns True on success.
    """
    d, chunk_size, batch_size, mod, sbs, blinders = unpack_params(params, expect)

    # ── Compact-proof path ─────────────────────────────────────────────────────
    if isinstance(ps_list, dict) and ps_list.get("format") == "compact_v1":
        n_batches = ps_list["n_batches"]
        x_seal    = ps_list["x"]
        proofs    = ps_list["proofs"]    # {b: {"salts":…, "proof":…, "v":…}}
        copath    = ps_list["copath"]
        assert n_batches == len(x_list)

        touched = set(_get_batch_ids(list(claims), batch_size))
        per_batch = {}
        for gi, val in claims.items():
            b = gi // batch_size
            per_batch.setdefault(b, {})[gi] = val

        h_by_batch = {}
        if workers and workers > 1 and len(touched) > 1:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=workers) as ex:
                futures = {
                    b: ex.submit(_vs6_mq_batch, b, per_batch[b], proofs[b],
                                 sys, batch_size, d, chunk_size, mod)
                    for b in touched
                }
                for b, fut in futures.items():
                    h_by_batch[b] = fut.result()
        else:
            for b in touched:
                h_by_batch[b] = _vs6_mq_batch(b, per_batch[b], proofs[b],
                                               sys, batch_size, d, chunk_size, mod)

        h = _vs6_from_copath(h_by_batch, touched, copath, n_batches,
                             chunk_size, x_seal, d, mod, sbs)
        assert h == c
        return True

    # ── Flat-proof path ────────────────────────────────────────────────────────
    assert len(ps_list) == len(x_list)

    per_batch = {}
    for gi, val in claims.items():
        b = gi // batch_size
        per_batch.setdefault(b, {})[gi] = val

    touched = set(_get_batch_ids(list(claims), batch_size))
    h_list  = list(ps_list)    # copy; untouched entries remain as-is

    if workers and workers > 1 and len(touched) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = {
                b: ex.submit(_vs6_mq_batch, b, per_batch[b], ps_list[b],
                             sys, batch_size, d, chunk_size, mod)
                for b in touched
            }
            for b, fut in futures.items():
                h_list[b] = fut.result()
    else:
        for b in touched:
            h_list[b] = _vs6_mq_batch(b, per_batch[b], ps_list[b],
                                       sys, batch_size, d, chunk_size, mod)

    x = max(x_list)
    h = _seal_batch(h_list, chunk_size, x, d, mod, sbs)
    assert h == c
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# LinkedSystem and verify_linked (duplicated from ms6/core.py per zero-prover rule)
# ═══════════════════════════════════════════════════════════════════════════════

class LinkedSystem:
    """Joint quadratic map encoding the linkage relation as MQ rows.

    Duplicated verbatim from ms6/core.py per the zero-prover-dependency rule.
    relation="mul": X=(a|b|c),     linkage: c_p - a_p·b_p = 0
    relation="pow": X=(a|c|aux),   linkage: c_p - a_p^k   = 0
    """

    def __init__(self, n, relation="mul", k=2, m_rand=None,
                 n_folds=DEFAULT_FOLDS, seed=SYS_TAG, insecure_ok=False):
        if relation not in ("mul", "pow"):
            raise ValueError("relation must be 'mul' or 'pow'")
        if relation == "pow" and k < 2:
            raise ValueError("pow relation needs k >= 2")
        self.n, self.relation, self.k, self.seed = n, relation, k, seed
        self.blocks = ["a", "b", "c"] if relation == "mul" else ["a", "c"]
        self.nb     = len(self.blocks)
        self.m_rand = (n - 1) if m_rand is None else m_rand
        if self.m_rand < n - 1 and not insecure_ok:
            raise ValueError(
                f"m_rand={self.m_rand} < n-1={n-1}: the dense random rows are "
                "what put the joint system in the generic MQ regime; linkage "
                "rows are sparse and do not hide (pass insecure_ok=True for "
                "experiments)")
        self.aux_per_pos = 0 if (relation == "mul" or k == 2) else (k - 2)
        self.n_aux = n * self.aux_per_pos
        self.N     = self.nb * n + self.n_aux
        self.idx, kk = {}, 0
        L = self.N
        for s in range(2 * L - 1):
            for i in range(max(0, s - L + 1), s // 2 + 1):
                self.idx[(i, s - i)] = kk
                kk += 1
        self.nmono = kk
        self.W = {}
        for blk in self.blocks:
            ws = []
            for f in range(n_folds):
                h = hashlib.shake_256(f"{seed}:linkw:{n}:{blk}:{f}".encode())
                raw = h.digest(48 * n)
                ws.append([
                    int.from_bytes(raw[48 * p:48 * (p + 1)], "big") % P or 1
                    for p in range(n)
                ])
            self.W[blk] = ws
        self.n_folds = n_folds
        self.Q, self.Lin = [], []
        self._build()
        self.m = len(self.Q)

    def off(self, blk):
        return self.blocks.index(blk) * self.n

    def aux_index(self, p, j):
        return self.nb * self.n + p * self.aux_per_pos + (j - 2)

    @staticmethod
    def _key(i, j):
        return (i, j) if i <= j else (j, i)

    def _add(self, q, lin):
        self.Q.append(q)
        self.Lin.append(lin)

    def _build(self):
        n = self.n
        for blk in self.blocks:
            o = self.off(blk)
            for l in range(self.m_rand):
                h = hashlib.shake_256(
                    f"{self.seed}:linkQ:{n}:{blk}:{l}".encode())
                raw = h.digest(48 * (n * (n + 1) // 2))
                q, t = [0] * self.nmono, 0
                for i in range(n):
                    for j in range(i, n):
                        q[self.idx[(o + i, o + j)]] = (
                            int.from_bytes(raw[48 * t:48 * (t + 1)], "big") % P)
                        t += 1
                self._add(q, [0] * self.N)
        self.link_rows = []
        oa, oc = self.off("a"), self.off("c")
        if self.relation == "mul":
            ob = self.off("b")
            for p in range(n):
                q, lin = [0] * self.nmono, [0] * self.N
                q[self.idx[self._key(oa + p, ob + p)]] = P - 1
                lin[oc + p] = 1
                self.link_rows.append(len(self.Q))
                self._add(q, lin)
        else:
            for p in range(n):
                if self.k == 2:
                    q, lin = [0] * self.nmono, [0] * self.N
                    q[self.idx[self._key(oa + p, oa + p)]] = P - 1
                    lin[oc + p] = 1
                    self.link_rows.append(len(self.Q))
                    self._add(q, lin)
                else:
                    for j in range(2, self.k + 1):
                        q, lin = [0] * self.nmono, [0] * self.N
                        prev = oa + p if j == 2 else self.aux_index(p, j - 1)
                        q[self.idx[self._key(oa + p, prev)]] = P - 1
                        if j == self.k:
                            lin[oc + p] = 1
                        else:
                            lin[self.aux_index(p, j)] = 1
                        self.link_rows.append(len(self.Q))
                        self._add(q, lin)
        self.fold_rows = {}
        for blk in self.blocks:
            o = self.off(blk)
            rows = []
            for w in self.W[blk]:
                q = [0] * self.nmono
                for i in range(n):
                    for j in range(i, n):
                        q[self.idx[(o + i, o + j)]] = w[i] * w[j] % P
                rows.append(len(self.Q))
                self._add(q, [0] * self.N)
            self.fold_rows[blk] = rows

    def F(self, X):
        assert len(X) == self.N
        X    = [int(v) % P for v in X]
        mono = [mk for bucket in ut.eval_level_mod_fast(2, X, P) for mk in bucket]
        out  = []
        for q, lin in zip(self.Q, self.Lin):
            acc = 0
            for c, mk in zip(q, mono):
                if c:
                    acc += c * mk
            for c, xk in zip(lin, X):
                if c:
                    acc += c * xk
            out.append(int(acc % P))
        return out


def verify_linked(sys, v, claims, witness):
    """Verify a linked opening (verifier side, no prover imports).

    claims  : {position → claimed_value}  (positions in block 'a')
    witness : {"salts": {p: salt}, "proof": ssh_proof}
    Raises AssertionError on failure; returns True on success.
    """
    known = {}
    for p, val in claims.items():
        if p not in witness["salts"]:
            raise AssertionError(f"no salt for position {p}")
        known[sys.off("a") + p] = hash_to_field(p, witness["salts"][p], val)
    if not verify_hidden(sys, v, known, witness["proof"]):
        raise AssertionError("linked witness check failed")
    return True
