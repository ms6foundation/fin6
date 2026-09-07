"""ms6mq/ms6/core.py — commit / open side of the MQ-hardened batched commitment.

Hardness basis: the Multivariate Quadratic (MQ) problem over F_P (P = 2²⁵⁵−19).
Each batch's commitment is v = F(x) where F : F_P^n → F_P^m is assembled from the
two fold primitives (eval_level_mod_fast / vsum_level_fast).

Opening a set S of positions reveals (value, per-item salt) for those positions;
the remaining coordinates z = x_H (H = [n] \ S, always containing k ≥ blinders
hidden coordinates) are proved in zero knowledge via the Sakumoto–Shirai–Hiwatari
3-pass MQ identification protocol, Fiat–Shamir'd against the statement (v, x_S).
The polar form G′(a,b) = F′(a+b)−F′(a)−F′(b)+F′(0) is computed as a combination
of fold evaluations (eval_level_mod_fast / vsum_level_fast via RestrictedMap.G).

The outer commitment (folding per-batch hashes into a root c) is unchanged: the
same _seal_batch / _SealTree machinery as before, operating on
h_b = _seal_hash(_mq_batch_digest(v_b)) leaves.

Public API
----------
ms6(vals, d, ...)            → (c, h_list, x_list, mq_sec, v_list, sys, params)
ps6(iset, h_list, mq_sec,
     v_list, sys, params)    → ps_list
                               ps_list[b] = h_b (str)  for untouched batches
                               ps_list[b] = {"salts":{gi:salt},"proof":…,"v":v_b}
vs6(c, claims, ps_list,
     x_list, sys, params)    → True   (lives in vs6/core.py)

Commitment                   updatable commitment class (same outer API as before)

Zero-prover-dependency rule: vs6/core.py must not import from this module.
Shared code (MQSystem / RestrictedMap / verify_hidden) is duplicated there.
"""
from random import SystemRandom
import hashlib
import math
import secrets as _secrets

from . import utils6 as u
from . import pow6  # kept for any remaining seal-fold helpers that use it


try:
    from gmpy2 import mpz as _mpz
    _HAVE_GMP = True
except ImportError:                    # pragma: no cover
    _mpz = int
    _HAVE_GMP = False

gen = SystemRandom()
ut = u.Utils()

FLUSH = 4096

# ── MQ field prime (defined first; DEFAULT_MOD derives from it) ──────────────
P            = 2 ** 255 - 19            # Curve25519 prime  (255-bit)
FIELD_BYTES  = 32

# ── outer-scheme defaults ──────────────────────────────────────────────────────
DEFAULT_CHUNK_SIZE      = 100
DEFAULT_BATCH_SIZE      = 1000
DEFAULT_WORKERS         = 1
DEFAULT_SEAL_BATCH_SIZE = 1000
# Both the seal fold and the _mq_batch column-product fold operate in F_P.
# Using P (~255 bits) instead of the old RSA-2048 composite gives ~8× cheaper
# modular arithmetic.  Binding comes from MQ hardness over F_P, so the seal
# fold needs only collision resistance in F_P (2^127.5-bit birthday bound),
# not unknown-order hardness.
DEFAULT_MOD             = P

# ── MQ-scheme constants ───────────────────────────────────────────────────────
ITEM_TAG     = "ms6mq-item"
SYS_TAG      = "ms6mq-sys"
COM_TAG      = "ms6mq-com"
FS_TAG       = "ms6mq-fs"
BATCH_TAG    = "ms6mq-batch"

DEFAULT_X_N      = 10
DEFAULT_BLINDERS = 8    # hidden-coord floor; raise for production (see README)
DEFAULT_ROUNDS   = 80   # (1/2)^80  < 2^-80 soundness for 5-pass protocol
DEFAULT_FOLDS    = 8   # default number of fold rows per MQSystem

# Geometric-weight folds live in a bucket space of dim = K*(n-1)+1.  Using more
# than dim//GEOMETRIC_CAP_DIVISOR bases leaks partial information even before
# the Vandermonde threshold; the tighter cap keeps the fold subsystem opaque.
GEOMETRIC_CAP_DIVISOR = 4

# Domain-separation tag for the seal fold (must match vs6/core.py exactly).
SEAL_TAG = "ms6-seal"

SEED_BYTES = 16   # bytes per per-round seed (Ch=0 response)

# ── param keys ────────────────────────────────────────────────────────────────
PARAM_KEYS = ("d", "chunk_size", "batch_size", "mod", "seal_batch_size", "blinders")


# ═══════════════════════════════════════════════════════════════════════════════
# Field helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _fe_bytes(a):
    return int(a).to_bytes(FIELD_BYTES, "big")


def _vec_bytes(vec):
    return b"".join(_fe_bytes(a) for a in vec)


def _rand_vec(length):
    return [_secrets.randbelow(P) for _ in range(length)]


def _vadd(a, b):
    return [(u_ + w) % P for u_, w in zip(a, b)]


def _vsub(a, b):
    return [(u_ - w) % P for u_, w in zip(a, b)]


def hash_to_field(global_index, salt, value):
    """Random-oracle map (index, per-item salt, value) → F_P.
    The salt stays secret until the item is opened, making the commitment
    hiding for low-entropy values."""
    seed = f"{ITEM_TAG}:{global_index}:{salt}:{value}".encode()
    return int.from_bytes(hashlib.shake_256(seed).digest(48), "big") % P


# ═══════════════════════════════════════════════════════════════════════════════
# MQ system  F : F_P^n → F_P^m
# ═══════════════════════════════════════════════════════════════════════════════

def rounds_for_security(lam):
    """Rounds needed so that (2/3)^rounds ≤ 2^-lam."""
    return math.ceil(lam / math.log2(1.5))


class MQSystem:
    """Public quadratic map F : F_P^N → F_P^m.

    Rows of F (in order):
        0 .. m_rand-1                random quadratic forms over the base x
        for each fold f = 0 .. n_folds-1:
            n*(K-1) consistency rows (only when K > 2; must equal 0)
            1 output row  = h_K(w^{(f)} ∘ x)

    fold_degree = K selects vsum_level_fold_fast(K, ., P).  For K > 2 the fold
    is degree-lifted: its DP states become hidden auxiliary coordinates and every
    DP step becomes a quadratic consistency row, so the map stays quadratic and
    the SSH opening applies unchanged.

    fold_weights = "random" (default) gives n_folds independent pseudorandom
    weight vectors.  fold_weights = "geometric" uses w_p = beta^{n-1-p} for each
    base in fold_bases; MQSystem refuses parameters that make x peelable.
    """

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

        # ── fold weight vectors ──────────────────────────────────────────────
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
        self.N = n + self.n_aux                # total variables (base + aux)
        self.n_cons = self.n_aux
        self.m = self.m_rand + self.n_cons + self.n_folds

        # monomial index map for eval_level_mod_fast(2, X, P) over all N vars
        self.idx = {}
        L = self.N
        k = 0
        for s in range(2 * L - 1):
            for i in range(max(0, s - L + 1), s // 2 + 1):
                self.idx[(i, s - i)] = k
                k += 1
        self.nmono = k

        # ── build rows: dense (Q/Lin) + sparse (Qs/Lins) + kind tag ─────────
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
                    else:   # w_{p,1} is linear in x
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
        """Store row densely (Q/Lin) and sparsely (Qs/Lins).
        kind=("fold", f) marks K=2 fold rows for fast_h2 dispatch."""
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
        """h_2(w∘x) = (e₁² + p₂)/2 mod P in O(n) using Newton's identity.

        Same value as the degree-2 fold row built from w[i]*w[j] monomials,
        but O(n) instead of O(n²).
        """
        e1 = p2 = 0
        for wi, xi in zip(w, x):
            y   = wi * xi % P
            e1 += y
            p2 += y * y
        return (e1 % P * (e1 % P) + p2) % P * ((P + 1) // 2) % P

    @staticmethod
    def monomials(X):
        """All X_i X_j (i ≤ j) mod P via eval_level_mod_fast, canonical order."""
        return [mk for bucket in ut.eval_level_mod_fast(2, [int(a) % P for a in X], P)
                for mk in bucket]

    def fold(self, x, f):
        """h_K(w^{(f)} ∘ x) normalised so it is a fixed form regardless of trailing zeros."""
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
        """Base vector x (length n) → full vector X (length N = n + n_aux)."""
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
        """Evaluate F at X ∈ F_P^N → output in F_P^m.

        K=2 fold rows are evaluated in O(n) via fast_h2; all other rows use
        sparse coefficient iteration over the monomial vector (built lazily).
        """
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


# ── attack demo (geometric fold weakness) ─────────────────────────────────────

def _sqrt_mod_p(a):
    """Square root mod P = 2^255-19 (P ≡ 5 mod 8), or None."""
    a %= P
    if a == 0:
        return 0
    if pow(a, (P - 1) // 2, P) != 1:
        return None
    r = pow(a, (P + 3) // 8, P)
    if r * r % P != a:
        r = r * pow(2, (P - 1) // 4, P) % P
    return r if r * r % P == a else None


def _solve_mod_p(A, b):
    """Gaussian elimination over F_P."""
    n = len(A)
    M = [row[:] + [bi] for row, bi in zip(A, b)]
    for col in range(n):
        piv = next(r for r in range(col, n) if M[r][col])
        M[col], M[piv] = M[piv], M[col]
        inv = pow(M[col][col], P - 2, P)
        M[col] = [v * inv % P for v in M[col]]
        for r in range(n):
            if r != col and M[r][col]:
                fac = M[r][col]
                M[r] = [(u_ - fac * w) % P for u_, w in zip(M[r], M[col])]
    return [M[r][n] for r in range(n)]


def peel_geometric_folds(n, bases, fold_values):
    """Given 2n-1 base-beta degree-2 fold values of an unknown x, recover ±x."""
    S = 2 * n - 1
    assert len(bases) == S == len(fold_values)
    A = [[pow(b, S - 1 - s, P) for s in range(S)] for b in bases]
    B = _solve_mod_p(A, fold_values)
    x0 = _sqrt_mod_p(B[0])
    if x0 is None:
        return None
    x = [x0]
    inv0 = pow(x0, P - 2, P)
    for s in range(1, n):
        acc = 0
        for i in range(1, s // 2 + 1):
            acc += x[i] * x[s - i]
        x.append((B[s] - acc) * inv0 % P)
    return x


class RestrictedMap:
    """F′(z) = F(embed(x_S, z)) for a fixed assignment of known positions S,
    together with its bilinear polar form G′(a,b) = F′(a+b)−F′(a)−F′(b)+F′(0).

    Operates over all N = n + n_aux variables; aux positions (n..N-1) are always
    hidden when only base-item positions are in known.
    """

    def __init__(self, sys, known):
        """known : dict {position → field element}  (positions in 0..N-1)"""
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
        """Polar form: four evaluations of F′ (each a fold computation)."""
        fab = self.F(_vadd(a, b))
        fa  = self.F(a)
        fb  = self.F(b)
        return [(u_ - w - t + f0) % P
                for u_, w, t, f0 in zip(fab, fa, fb, self.F0)]

    def batched(self, gamma, v):
        """Fold the m rows into ONE quadratic q(z) = <z,Az> + b.z + c with
        target t = <gamma, v>.  Uses DirectBatched which accumulates in O(h²)
        memory without materialising per-row A_l matrices — mandatory for
        LedgerSystem where range bits push h into the hundreds."""
        db = DirectBatched.from_restricted(self, gamma, v)
        return _Batched(db, db.A, db.b, db.c, db.t)


class DirectBatched:
    """The gamma-batched quadratic  q(z) = <z,Az> + b.z + c,  accumulated
    STRAIGHT from the sparse rows of the system.

    QuadraticForm.from_restricted materialises one dense A_l per row, which is
    O(m*h^2) and becomes infeasible once range-proof bit variables push h into
    the hundreds.  Since the 5-pass prover only ever uses the batched form,
    accumulate it directly: O(h^2) memory, one pass over the sparse terms."""

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
        """G(a,b) = q(a+b) - q(a) - q(b) = <a,Ab> + <b,Aa>."""
        mv = self.qf.matvec
        acc = 0
        for x, y in zip(a, mv(self.A, b)):
            acc += x * y
        for x, y in zip(b, mv(self.A, a)):
            acc += x * y
        return acc % P


# ═══════════════════════════════════════════════════════════════════════════════
# SSH 5-pass MQ identification (Fiat–Shamir, gamma-batched)
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
    """Derive `count` uniform F_P elements from (tag, transcript) via SHAKE256."""
    k = FIELD_BYTES + 16
    raw = hashlib.shake_256(FS_TAG.encode() + tag + transcript).digest(k * count)
    return [int.from_bytes(raw[k * i:k * (i + 1)], "big") % P for i in range(count)]


def _fs_gamma(stmt, m):
    """Fiat-Shamir batching scalar: gamma ← F_P^m from the statement."""
    return _fs_scalars(b"gamma", stmt, m)


def _fs_alpha(statement, commits, rounds):
    """Fiat–Shamir challenge 1: alpha_i uniform in F_P from the commitments."""
    h = hashlib.shake_256()
    for c0, c1 in commits:
        h.update(c0 + c1)
    return _fs_scalars(b"alpha", statement + h.digest(32), rounds)


def _fs_bits(statement, commits, alphas, mids, rounds):
    """Fiat–Shamir challenge 2: Ch_i in {0,1} from the whole transcript."""
    h = hashlib.shake_256(FS_TAG.encode() + b"ch" + statement)
    for c0, c1 in commits:
        h.update(c0 + c1)
    h.update(_vec_bytes(alphas))
    for t1, e1 in mids:
        h.update(_vec_bytes(t1) + _fe_bytes(e1))   # e1 is a scalar
    raw = h.digest((rounds + 7) // 8)
    return [(raw[i // 8] >> (i % 8)) & 1 for i in range(rounds)]


def _round_rand(seed, h):
    """Expand a SEED_BYTES-byte round seed → (r0, t0, e0_scalar) via SHAKE128."""
    k = FIELD_BYTES + 16
    raw = hashlib.shake_128(b"rr" + seed).digest(k * (2 * h + 1))
    vals = [int.from_bytes(raw[k * i:k * (i + 1)], "big") % P for i in range(2 * h + 1)]
    return vals[:h], vals[h:2 * h], vals[2 * h]


def _statement(v, known):
    h = hashlib.shake_256(b"stmt")
    h.update(_vec_bytes(v))
    for i in sorted(known):
        h.update(i.to_bytes(4, "big") + _fe_bytes(known[i]))
    return h.digest(32)


def _smul(a, vec):
    return [a * u_ % P for u_ in vec]


def prove_hidden(sys, v, known, z, rounds=DEFAULT_ROUNDS):
    """GAMMA-BATCHED 5-pass SSH ZK proof of knowledge of z with
    F(embed(known, z)) = v, non-interactive via Fiat-Shamir.

    Pass 0 (batching): gamma ← F_P^m from the statement folds the m MQ rows
    into ONE quadratic  q(z) = t.  A wrong row survives with probability 1/P.

    Per round (h = |hidden|), all arithmetic on the single batched form:
        seed ← {0,1}^SEED_BYTES
        r0, t0 ← F^h,  e0 ← F  (expanded from seed via shake_128)
        r1 = z − r0
        c0 = Com(seed=seed)                c1 = Com(r1, G(t0,r1)+e0)
        alpha ← F_P
        t1 = alpha·r0 − t0                 e1 = alpha·q(r0) − e0   (scalars)
        Ch ← {0,1}
        Ch=0: reveal seed → verifier expands r0,t0,e0 and checks mid equations
        Ch=1: reveal r1   → verifier checks c1 via the batched polar form

    Proof size: ~(2h+1)·32 + SEED_BYTES bytes/round (vs (2h+m)·32 per round
    for the unbatched version).
    """
    R    = RestrictedMap(sys, known)
    assert len(z) == R.h
    stmt = _statement(v, known)
    BF   = R.batched(_fs_gamma(stmt, sys.m), v)

    state, commits = [], []
    for _ in range(rounds):
        seed        = _secrets.token_bytes(SEED_BYTES)
        r0, t0, e0  = _round_rand(seed, R.h)
        r1          = _vsub(z, r0)
        qr0         = BF.q(r0)
        n0, n1      = _secrets.token_bytes(32), _secrets.token_bytes(32)
        c0          = _com(n0, [], [], [], seed=seed)      # commit to seed only
        c1          = _com(n1, r1, [(BF.polar(t0, r1) + e0) % P])
        commits.append((c0, c1))
        state.append((seed, r0, r1, t0, e0, qr0, n0, n1))

    alphas = _fs_alpha(stmt, commits, rounds)
    mids   = [(_vsub(_smul(a, r0), t0), (a * qr0 - e0) % P)
              for a, (seed, r0, r1, t0, e0, qr0, n0, n1) in zip(alphas, state)]
    bits   = _fs_bits(stmt, commits, alphas, mids, rounds)
    responses = [(seed, n0) if ch == 0 else (r1, n1)
                 for ch, (seed, r0, r1, t0, e0, qr0, n0, n1) in zip(bits, state)]
    return {"passes": 5, "batched": True, "seeded": True, "rounds": rounds,
            "commits": commits, "mids": mids, "responses": responses}


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
            if _vsub(_smul(a, r0), t0) != list(t1) or (a * BF.q(r0) - e0) % P != e1 % P:
                return False
        else:
            if len(r) != R.h:
                return False
            y = (a * (BF.t - BF.q(r) + BF.c) - BF.polar(t1, r) - e1) % P
            if _com(nonce, r, [y]) != c1:
                return False
    return True


def serialize_proof(proof):
    """Serialise a prove_hidden proof dict to bytes."""
    out = [proof["rounds"].to_bytes(4, "big")]
    for c0, c1 in proof["commits"]:
        out.append(c0 + c1)
    for t1, e1 in proof["mids"]:
        out.append(_vec_bytes(t1) + _fe_bytes(e1))
    for r, nonce in proof["responses"]:
        if isinstance(r, (bytes, bytearray)):
            out.append(b"\x00" + bytes(r) + nonce)
        else:
            out.append(b"\x01" + _vec_bytes(r) + nonce)
    return b"".join(out)


# ═══════════════════════════════════════════════════════════════════════════════
# Params
# ═══════════════════════════════════════════════════════════════════════════════

def make_params(d, chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE,
                mod=DEFAULT_MOD, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE,
                blinders=DEFAULT_BLINDERS):
    return {"d": d, "chunk_size": chunk_size, "batch_size": batch_size,
            "mod": mod, "seal_batch_size": seal_batch_size, "blinders": blinders}


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


# ── chunk helpers (used by seal tree) ─────────────────────────────────────────

def chunk_of(val, x, chunk_size):
    chunks = list(ut.backward_chunk(val, chunk_size))
    chunks[0] = f"{chunks[0]:{u.PAD}>{chunk_size}}"
    return [u.PAD * chunk_size] * (x - len(chunks)) + chunks


def chunks(x, chunk_size):
    def internal(val):
        return chunk_of(val, x, chunk_size)
    return internal


# ── kept for harness/test compatibility ───────────────────────────────────────
def _permute_row(row, perm):
    return ''.join(row[p] for p in perm)


# ═══════════════════════════════════════════════════════════════════════════════
# Seal-tree machinery  (UNCHANGED from DL version — operates on opaque h strings)
# ═══════════════════════════════════════════════════════════════════════════════

def _seal_hash(val):
    """Hash one leaf value into a domain-hash string.  Must match vs6/core.py."""
    return ut.domain_hash(f"{SEAL_TAG}:{val}".encode())


def _seal_fold_rows(chunk_size):
    """Rows needed to hold one domain-hash-width leaf in the seal fold."""
    return -(-u.DOMAIN_HASH_DIGITS // chunk_size)


def _seal_rows(val, chunk_of_fn):
    return chunk_of_fn(val)


def _seal_chunker(x, chunk_size):
    return chunks(x, chunk_size)


def _seal_from_counts(cnt, chunk_size, d, mod):
    H = [[ut.cell_product_mod(cnt[i][j], 1, mod) for j in range(chunk_size)]
         for i in range(len(cnt))]
    H = [ut.vsum_level_fold_fast(d, H1, mod) for H1 in H]
    return ut.vsum_level(H, b=chunk_size)


def _seal_batch_flat(vals, chunk_size, x, d, mod):
    """Single-level fold of already-hashed values into one scalar."""
    accH     = u.Acc(x, chunk_size)
    chunk_fn = _seal_chunker(x, chunk_size)
    for t, val in enumerate(vals):
        accH.add(_seal_rows(val, chunk_fn))
        if (t & (FLUSH - 1)) == FLUSH - 1:
            accH.flush()
    accH.flush()
    return _seal_from_counts(accH.cnt, chunk_size, d, mod)


def _seal_batch(vals, chunk_size, x, d, mod=DEFAULT_MOD,
                seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
    """Hierarchical fold of hashed scalars into a single root value."""
    vals = list(vals)
    if len(vals) > seal_batch_size:
        vals = [
            _seal_hash(_seal_batch(vals[start:start + seal_batch_size],
                                   chunk_size, x, d, mod, seal_batch_size))
            for start in range(0, len(vals), seal_batch_size)
        ]
        return _seal_batch(vals, chunk_size, x, d, mod, seal_batch_size)
    return _seal_batch_flat(vals, chunk_size, x, d, mod)


def _apply_rows(cnt, rows, sign):
    for i, cnt_i in enumerate(cnt):
        for j, ch in enumerate(rows[i]):
            cnt_i[j][ord(ch) - 48] += sign


def _ps6_build_copath(h_list, touched, chunk_size, x, d, mod, sbs):
    """Compact copath for ps6(compact=True) — unchanged from DL version."""
    levels = [list(h_list)]
    level  = levels[0]
    while len(level) > 1:
        groups     = [level[i:i + sbs] for i in range(0, len(level), sbs)]
        raw        = [_seal_batch_flat(g, chunk_size, x, d, mod) for g in groups]
        is_root    = (len(raw) == 1)
        next_level = raw if is_root else [_seal_hash(v) for v in raw]
        levels.append(next_level)
        level = next_level

    active = set(touched)
    copath = []
    for k in range(len(levels) - 1):
        n_k = len(levels[k])
        siblings_by_group = {}
        for i in active:
            g       = i // sbs
            g_start = g * sbs
            g_end   = min((g + 1) * sbs, n_k)
            siblings_by_group[g] = [levels[k][j] for j in range(g_start, g_end)
                                    if j not in active]
        copath.append(siblings_by_group)
        active = {i // sbs for i in active}
    return copath


class _SealTree:
    """Cached incremental seal tree.

    Leaves are appended and updated in place; every level keeps the counts that
    produced it, so one change costs a fold per level rather than a rebuild.
    Growth is by extension at every level, including the root level, which is
    what keeps `append_leaf` flat in the number of leaves.
    """

    def __init__(self, leaves, x, chunk_size, d, mod, sbs=DEFAULT_SEAL_BATCH_SIZE):
        self.x, self.chunk_size = x, chunk_size
        self.d, self.mod, self.sbs = d, mod, sbs
        self._chunk_of = _seal_chunker(x, chunk_size)
        self.build(leaves)

    def build(self, leaves):
        self.levels = [list(leaves)]
        self.counts = [None]
        level = self.levels[0]
        while True:
            groups = ([level] if len(level) <= self.sbs
                      else [level[i:i + self.sbs] for i in range(0, len(level), self.sbs)])
            cnts   = [self._counts_of(g) for g in groups]
            raw    = [_seal_from_counts(c, self.chunk_size, self.d, self.mod) for c in cnts]
            is_root = len(raw) == 1
            level  = raw if is_root else [_seal_hash(v) for v in raw]
            self.levels.append(level)
            self.counts.append(cnts)
            if is_root:
                break
        return self.root

    def _counts_of(self, vals):
        acc = u.Acc(self.x, self.chunk_size)
        for t, v in enumerate(vals):
            acc.add(_seal_rows(v, self._chunk_of))
            if (t & (FLUSH - 1)) == FLUSH - 1:
                acc.flush()
        acc.flush()
        return acc.cnt

    @property
    def root(self):
        return self.levels[-1][0]

    def _propagate(self, idx, old_v, new_v):
        """Fold one change at level 0 up through the counts.

        `old_v is None` means the entry at `idx` was appended rather than
        replaced — which is also how a freshly opened group announces itself to
        the level above, so growth and update share one path.
        """
        k = 1
        while k < len(self.levels):
            j = idx // self.sbs
            if j == len(self.levels[k]):
                # A new group opens at this level: extend it.  Rebuilding the
                # whole tree here instead is what used to make building by
                # append quadratic in the number of leaves.
                self.counts[k].append(self._counts_of(()))
                self.levels[k].append(None)
            cnt = self.counts[k][j]
            if old_v is not None:
                _apply_rows(cnt, _seal_rows(old_v, self._chunk_of), -1)
            _apply_rows(cnt, _seal_rows(new_v, self._chunk_of), +1)
            raw  = _seal_from_counts(cnt, self.chunk_size, self.d, self.mod)
            prev = self.levels[k][j]
            if k == len(self.levels) - 1:
                if len(self.levels[k]) == 1:
                    self.levels[k][j] = raw          # this level *is* the root
                    return self.root
                self._roof(k, j, raw)                # ... and now it is not
                return self.root
            self.levels[k][j] = _seal_hash(raw)
            old_v, new_v, idx, k = prev, self.levels[k][j], j, k + 1
        return self.root

    def _roof(self, k, j, raw):
        """Level k has just grown past one entry, so it is no longer the root.

        A root level stores its single value unhashed, so becoming an interior
        level means hashing what is there and folding a new level over the top.
        Only ever reached with two entries at level k, since a root level holds
        exactly one.
        """
        self.levels[k] = [_seal_hash(raw) if t == j else _seal_hash(v)
                          for t, v in enumerate(self.levels[k])]
        cnt = self._counts_of(self.levels[k])
        self.counts.append([cnt])
        self.levels.append([_seal_from_counts(cnt, self.chunk_size, self.d,
                                              self.mod)])

    def update_leaf(self, i, new_val):
        old = self.levels[0][i]
        if old == new_val:
            return self.root
        self.levels[0][i] = new_val
        return self._propagate(i, old, new_val)

    def append_leaf(self, val):
        i = len(self.levels[0])
        self.levels[0].append(val)
        return self._propagate(i, None, val)


# ═══════════════════════════════════════════════════════════════════════════════
# MQ batch commit helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _mq_batch_digest(v):
    """Hash an MQ output vector v = F(x) to an integer for use as a seal-tree leaf."""
    return int.from_bytes(
        hashlib.shake_256(BATCH_TAG.encode() + _vec_bytes(v)).digest(32), "big")


def _mq_leaf(v):
    """Seal-tree leaf for one batch's MQ commitment v."""
    return _seal_hash(_mq_batch_digest(v))


def _grid_seal(xi, chunk_size, d, mod):
    """Map one field element through the digit-prime grid and fold it.

    Converts xi to its decimal string, expands to target_len via sparse_expand,
    then computes DIGIT_PRIMES[digit] % mod at each column (combining x_rows rows
    by column-wise product) and folds with vsum_level_fold_fast.
    Returns an integer in [0, P).
    """
    x_rows     = _seal_fold_rows(chunk_size)
    target_len = x_rows * chunk_size
    chunk_fn   = _seal_chunker(x_rows, chunk_size)
    _dp        = [u.DIGIT_PRIMES[v] % mod for v in range(10)]
    xi_str     = ut.sparse_expand(str(xi), target_len, mod)
    combined   = [1] * chunk_size
    for row_str in chunk_fn(xi_str):
        for j, ch in enumerate(row_str):
            p = _dp[int(ch)] if ch.isdigit() else 1
            combined[j] = combined[j] * p % mod
    return int(ut.vsum_level_fold_fast(d, combined, mod)) % P


def _mq_batch(start, vals, sys, blinders, d, chunk_size, mod):
    """Commit one batch of items.

    Returns (h, X, salts, v):
        h      : seal-tree leaf string (= _mq_leaf(v))
        X      : lifted N-vector of field elements (base x_n+blinders items + aux)
        salts  : per-item salts (list, len = len(vals))
        v      : F(X) — the public MQ batch commitment

    x_raw is forward-chunked into groups of chunk_size; each group produces one
    x_mq element via joint column products across all items in the chunk.
    x_n = ceil(len(vals)/chunk_size); sys.n must equal x_n + blinders.
    chunk_idx = local_j // chunk_size  maps each item to its x_mq slot.
    """
    n      = sys.n
    salts  = [_secrets.token_hex(16) for _ in vals]
    x_raw  = [hash_to_field(start + j, salts[j], val)
               for j, val in enumerate(vals)]

    x_rows     = _seal_fold_rows(chunk_size)
    target_len = x_rows * chunk_size
    chunk_fn   = _seal_chunker(x_rows, chunk_size)
    _dp        = [u.DIGIT_PRIMES[v] % mod for v in range(10)]

    # Fold x_raw into x_chunks of size chunk_size; joint column products per chunk.
    # chunk_idx = local_j // chunk_size  (forward chunking, last chunk may be partial)
    x_mq = []
    for k in range(0, len(x_raw), chunk_size):
        x_chunk  = x_raw[k : k + chunk_size]
        combined = [1] * chunk_size
        for xi in x_chunk:
            xi_str = ut.sparse_expand(str(xi), target_len, mod)
            for row_str in chunk_fn(xi_str):
                for j, ch in enumerate(row_str):
                    p = _dp[int(ch)] if ch.isdigit() else 1
                    combined[j] = combined[j] * p % mod
        x_mq.append(int(ut.vsum_level_fold_fast(d, combined, mod)) % P)
    x_mq += _rand_vec(n - len(x_mq))

    X    = sys.lift(x_mq)   # extend base vector to length N (no-op for K=2)
    v    = sys.F(X)
    h    = _mq_leaf(v)
    return h, X, salts, v


# ═══════════════════════════════════════════════════════════════════════════════
# ms6 — commit
# ═══════════════════════════════════════════════════════════════════════════════

def ms6(vals, d, blinders=DEFAULT_BLINDERS, sys=None,
        chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE,
        mod=DEFAULT_MOD, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE,
        workers=DEFAULT_WORKERS,
        fold_degree=2, n_folds=DEFAULT_FOLDS, fold_weights="random",
        fold_bases=None, m_rand=None):
    """Commit to `vals` using the MQ-hardened batched commitment.

    Returns
    -------
    c          : root commitment (seal-tree root)
    h_list     : per-batch seal-tree leaves  h_b = _mq_leaf(v_b)
    x_list     : per-batch row count for seal fold (all equal _seal_fold_rows(chunk_size))
    mq_sec     : list of {"x": X_b, "salts": salts_b, "vals": batch_vals}
                 — KEEP PRIVATE (prover only)
    v_list     : list of v_b = F(X_b)               — public, share with verifier
    sys        : MQSystem instance (public)
    params     : parameter dict consumed by ps6 / vs6

    sys.n = x_n + blinders  where x_n = ceil(batch_size / chunk_size).
    fold_degree, n_folds, fold_weights, fold_bases, m_rand
               : forwarded to MQSystem when sys=None.
    """
    x_n = math.ceil(batch_size / chunk_size)
    n   = x_n + blinders
    if sys is None:
        sys = MQSystem(n, fold_degree=fold_degree, m_rand=m_rand,
                       n_folds=n_folds, fold_weights=fold_weights,
                       fold_bases=fold_bases)
    assert sys.n == n

    groups  = [(start, vals[start:start + batch_size])
               for start in range(0, len(vals), batch_size)]
    if workers and workers > 1 and len(groups) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_mq_batch, start, grp, sys, blinders, d, chunk_size, mod)
                    for start, grp in groups]
            results = [f.result() for f in futs]
    else:
        results = [_mq_batch(start, grp, sys, blinders, d, chunk_size, mod)
                   for start, grp in groups]

    h_list, mq_sec, v_list = [], [], []
    for (start, grp), (h, x, salts, v) in zip(groups, results):
        h_list.append(h)
        mq_sec.append({"x": x, "salts": salts, "vals": list(grp)})
        v_list.append(v)

    x_seal = _seal_fold_rows(chunk_size)
    x_list = [x_seal] * len(h_list)
    c      = _seal_batch(h_list, chunk_size, x_seal, d, mod, seal_batch_size)
    params = make_params(d, chunk_size, batch_size, mod, seal_batch_size, blinders)
    return c, h_list, x_list, mq_sec, v_list, sys, params


# ═══════════════════════════════════════════════════════════════════════════════
# ps6 — open (hiding)
# ═══════════════════════════════════════════════════════════════════════════════

def _mq_ps6_batch(b, iset_b, mq_b, v_b, sys, rounds, batch_start, chunk_size):
    """Generate the SSH proof for one touched batch.

    iset_b     : set of GLOBAL indices claimed in this batch
    mq_b       : {"x": x_b, "salts": salts_b, "vals": batch_vals}
    v_b        : F(x_b)
    batch_start: b * batch_size  (to convert global → local)
    chunk_size : items per x_mq slot;  chunk_idx = local_j // chunk_size
    """
    x_b   = mq_b["x"]
    salts = mq_b["salts"]
    vals  = mq_b["vals"]
    n_items = len(salts)

    # Determine which x_mq slots (chunk indices) are touched.
    local_claimed = {gi - batch_start for gi in iset_b}
    chunk_idxs    = {local_j // chunk_size for local_j in local_claimed}

    # All local indices in touched chunks (capped by actual item count).
    all_locals = set()
    for ci in chunk_idxs:
        for local_j in range(ci * chunk_size, min((ci + 1) * chunk_size, n_items)):
            all_locals.add(local_j)

    # known: {chunk_idx: x_mq[chunk_idx]}  (the pre-computed joint folds)
    known = {ci: x_b[ci] for ci in chunk_idxs}

    R     = RestrictedMap(sys, known)
    z     = [x_b[i] for i in R.hidden]
    proof = prove_hidden(sys, v_b, known, z, rounds)

    return {
        # salts for every item in touched chunks (None for tombstones)
        "salts": {batch_start + lj: salts[lj] for lj in all_locals},
        # values for non-claimed items in touched chunks (verifier needs these
        # to reconstruct the joint column-product fold for known[chunk_idx])
        "vals":  {batch_start + lj: vals[lj] for lj in all_locals
                  if (batch_start + lj) not in iset_b},
        "proof": proof,
        "v":     v_b,
    }


def ps6(iset, h_list, mq_sec, v_list, sys, params, rounds=DEFAULT_ROUNDS,
        expect=None, compact=False, x_list=None, workers=DEFAULT_WORKERS):
    """Open positions `iset` under the MQ commitment.

    Parameters
    ----------
    iset    : iterable of GLOBAL item indices to reveal
    h_list  : per-batch seal-tree leaves (from ms6)
    mq_sec  : per-batch private data (from ms6) — list of {"x":…, "salts":…}
    v_list  : per-batch public MQ commitments (from ms6)
    sys     : MQSystem (from ms6)
    params  : parameter dict (from ms6)

    Returns
    -------
    ps_list : list where
        ps_list[b] = h_b (str)             for untouched batches  (unchanged)
        ps_list[b] = {"salts":{gi:salt},   for touched batches
                      "proof": ssh_proof,
                      "v":     v_b}
    """
    d, chunk_size, batch_size, mod, sbs, blinders = unpack_params(params, expect)
    iset    = set(iset)

    # Check for dead/out-of-range slots.
    for gi in iset:
        b       = gi // batch_size
        local_j = gi - b * batch_size
        salts_b = mq_sec[b]["salts"]
        if local_j >= len(salts_b):
            raise ValueError(f"index {gi} is out of range for batch {b}")
        if salts_b[local_j] is None:
            raise ValueError(f"index {gi} is deleted and cannot be opened")

    touched = set(gi // batch_size for gi in iset)

    # Start from h_list (untouched batches keep their leaf unchanged).
    ps_list = list(h_list)

    if workers and workers > 1 and len(touched) > 1:
        from concurrent.futures import ProcessPoolExecutor
        isets = {b: {gi for gi in iset if gi // batch_size == b} for b in touched}
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futs = {b: ex.submit(_mq_ps6_batch, b, isets[b], mq_sec[b], v_list[b],
                                 sys, rounds, b * batch_size, chunk_size)
                    for b in touched}
            for b, fut in futs.items():
                ps_list[b] = fut.result()
    else:
        for b in touched:
            iset_b     = {gi for gi in iset if gi // batch_size == b}
            ps_list[b] = _mq_ps6_batch(b, iset_b, mq_sec[b], v_list[b],
                                        sys, rounds, b * batch_size, chunk_size)

    if not compact:
        return ps_list

    # Compact mode: copath over the seal tree (unchanged machinery).
    x = (max(x_list) if x_list else _seal_fold_rows(chunk_size))
    copath = _ps6_build_copath(h_list, touched, chunk_size, x, d, mod, sbs)
    return {
        "format":   "compact_v1",
        "n_batches": len(h_list),
        "x":        x,
        "proofs":   {b: ps_list[b] for b in touched},
        "copath":   copath,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Commitment — updatable commitment class
# ═══════════════════════════════════════════════════════════════════════════════

def _get_batch_ids(indices, batch_size=DEFAULT_BATCH_SIZE):
    return [index // batch_size for index in indices]


class Commitment:
    """MQ-hardened ms6 commitment with append / replace / delete support.

    State per batch b:
        x_b          : n-vector of field elements  [items…, blinders/padding…]
        salts_b      : per-item salts  (len = item_count_b ≤ batch_size)
        item_count_b : number of real items in this batch (the rest are blinders)
        v_b          : F(x_b) — public MQ commitment
        h_b          : _mq_leaf(v_b) — seal-tree leaf

    append() fills the last partial batch before opening a new one.
    replace() updates one item's field element in place.
    delete() tombstones a slot (x_b[local] ← 0, item effectively zero-valued).
    """

    def __init__(self, vals, d, blinders=DEFAULT_BLINDERS, sys=None,
                 chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE,
                 mod=DEFAULT_MOD, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE,
                 workers=DEFAULT_WORKERS,
                 fold_degree=2, n_folds=DEFAULT_FOLDS, fold_weights="random",
                 fold_bases=None, m_rand=None):
        vals = list(vals)
        if not vals:
            raise ValueError("Commitment needs at least one value")

        self.d           = d
        self.blinders    = blinders
        self.chunk_size  = chunk_size
        self.batch_size  = batch_size
        self.mod         = mod
        self.seal_batch_size = seal_batch_size
        self.workers     = workers

        # sys.n = x_n + blinders  where x_n = ceil(batch_size / chunk_size)
        x_n = math.ceil(batch_size / chunk_size)
        n   = x_n + blinders
        if sys is None:
            sys = MQSystem(n, fold_degree=fold_degree, m_rand=m_rand,
                           n_folds=n_folds, fold_weights=fold_weights,
                           fold_bases=fold_bases)
        assert sys.n == n
        self.sys = sys

        self.vals        = []
        self.dead        = set()
        self.x_vecs      = []   # per-batch x vectors (field elements, PRIVATE)
        self.salts_list  = []   # per-batch per-item salts
        self.vals_list   = []   # per-batch per-item values  (PRIVATE)
        self.item_counts = []   # per-batch item count (≤ batch_size)
        self.v_list      = []   # per-batch F(x_b)
        self.h_list      = []   # per-batch _mq_leaf(v_b)

        for start in range(0, len(vals), batch_size):
            self._new_batch(vals[start:start + batch_size])

        self._rebuild_tree()

    # ── construction ──────────────────────────────────────────────────────────

    def _new_batch(self, batch_vals):
        b     = len(self.h_list)
        start = sum(self.item_counts)      # global start index
        h, x, salts, v = _mq_batch(start, batch_vals, self.sys, self.blinders,
                                    self.d, self.chunk_size, self.mod)
        self.vals.extend(batch_vals)
        self.x_vecs.append(x)
        self.salts_list.append(list(salts))
        self.vals_list.append(list(batch_vals))
        self.item_counts.append(len(batch_vals))
        self.v_list.append(v)
        self.h_list.append(h)
        return b

    # ── seal tree ─────────────────────────────────────────────────────────────

    def _x_seal(self):
        return _seal_fold_rows(self.chunk_size)

    def _rebuild_tree(self):
        x = self._x_seal()
        self._tree = _SealTree(self.h_list, x, self.chunk_size,
                               self.d, self.mod, self.seal_batch_size)
        self.c = self._tree.root

    def _refresh_root(self, leaf=None, appended=False):
        if self._tree is None:
            return self._rebuild_tree()
        if appended:
            self.c = self._tree.append_leaf(self.h_list[-1])
        elif leaf is not None:
            self.c = self._tree.update_leaf(leaf, self.h_list[leaf])
        else:
            self._rebuild_tree()

    def _update_chunk(self, b, chunk_idx):
        """Recompute x_mq[chunk_idx] from all current items in that chunk."""
        cs          = self.chunk_size
        chunk_start = chunk_idx * cs
        chunk_end   = min(chunk_start + cs, self.item_counts[b])

        x_rows     = _seal_fold_rows(cs)
        target_len = x_rows * cs
        chunk_fn   = _seal_chunker(x_rows, cs)
        _dp        = [u.DIGIT_PRIMES[v] % self.mod for v in range(10)]

        batch_start = self._batch_start(b)
        combined    = [1] * cs
        for local_k in range(chunk_start, chunk_end):
            salt = self.salts_list[b][local_k]
            if salt is None:
                xi = 0   # tombstone: contributes xi=0 to the joint fold
            else:
                gi  = batch_start + local_k
                val = self.vals_list[b][local_k]
                xi  = hash_to_field(gi, salt, val)
            xi_str = ut.sparse_expand(str(xi), target_len, self.mod)
            for row_str in chunk_fn(xi_str):
                for j, ch in enumerate(row_str):
                    p = _dp[int(ch)] if ch.isdigit() else 1
                    combined[j] = combined[j] * p % self.mod

        new_xmq = int(ut.vsum_level_fold_fast(self.d, combined, self.mod)) % P
        base = list(self.x_vecs[b][:self.sys.n])
        base[chunk_idx] = new_xmq
        self.x_vecs[b] = self.sys.lift(base)

    def _reseal(self, b):
        """Recompute v_b and h_b after x_vecs[b] has been updated."""
        self.v_list[b] = self.sys.F(self.x_vecs[b])
        self.h_list[b] = _mq_leaf(self.v_list[b])

    # ── accessors ─────────────────────────────────────────────────────────────

    @property
    def params(self):
        return make_params(self.d, self.chunk_size, self.batch_size,
                           self.mod, self.seal_batch_size, self.blinders)

    def opening(self):
        """(c, h_list, x_list, mq_sec, v_list, sys, params) — same shape as ms6()."""
        x_seal = self._x_seal()
        mq_sec = [{"x": self.x_vecs[b], "salts": self.salts_list[b],
                   "vals": self.vals_list[b]}
                  for b in range(len(self.h_list))]
        return (self.c,
                list(self.h_list),
                [x_seal] * len(self.h_list),
                mq_sec,
                list(self.v_list),
                self.sys,
                self.params)

    @property
    def x_list(self):
        """Seal-fold row counts (integers) for all batches — matches ms6() return value."""
        x_seal = self._x_seal()
        return [x_seal] * len(self.h_list)

    @property
    def live_count(self):
        return len(self.vals) - len(self.dead)

    # ── batch start helper ────────────────────────────────────────────────────

    def _batch_start(self, b):
        return b * self.batch_size

    # ── update primitives ─────────────────────────────────────────────────────

    def append(self, val):
        """Add `val`, returning its global index."""
        last = len(self.h_list) - 1
        if last < 0 or self.item_counts[last] >= self.batch_size:
            self._new_batch([val])
            self._refresh_root(appended=True)
            return len(self.vals) - 1

        b        = last
        local_j  = self.item_counts[b]
        new_salt = _secrets.token_hex(16)
        self.salts_list[b].append(new_salt)
        self.vals_list[b].append(val)
        self.vals.append(val)
        self.item_counts[b] += 1
        self._update_chunk(b, local_j // self.chunk_size)
        self._reseal(b)
        self._refresh_root(leaf=b)
        return len(self.vals) - 1

    def replace(self, index, new_val):
        """Swap the value at `index` in place."""
        if not 0 <= index < len(self.vals):
            raise IndexError(f"index {index} outside 0..{len(self.vals) - 1}")
        if index in self.dead:
            raise ValueError(f"index {index} is deleted; replace() cannot revive a slot")
        b       = index // self.batch_size
        local_j = index - self._batch_start(b)
        # Update stored value; salt is reused so the old proof invalidates.
        self.vals_list[b][local_j] = new_val
        self.vals[index] = new_val
        self._update_chunk(b, local_j // self.chunk_size)
        self._reseal(b)
        self._refresh_root(leaf=b)
        return index

    def delete(self, index):
        """Tombstone the slot at `index` (xi ← 0, item excluded from future proofs)."""
        if not 0 <= index < len(self.vals):
            raise IndexError(f"index {index} outside 0..{len(self.vals) - 1}")
        if index in self.dead:
            raise ValueError(f"index {index} is already deleted")
        b       = index // self.batch_size
        local_j = index - self._batch_start(b)
        # salt=None marks the slot dead (ps6 refuses to open it).
        # vals_list[b][local_j]=None; _update_chunk treats salt=None as xi=0.
        self.salts_list[b][local_j] = None
        self.vals_list[b][local_j]  = None
        self.vals[index] = None
        self.dead.add(index)
        self._update_chunk(b, local_j // self.chunk_size)
        self._reseal(b)
        self._refresh_root(leaf=b)
        return index


# ═══════════════════════════════════════════════════════════════════════════════
# Query governance (unchanged logic, updated param unpacking)
# ═══════════════════════════════════════════════════════════════════════════════

class QueryPolicyViolation(Exception):
    """Raised by QueryGovernor.authorize() when a claim set should not be served."""


class QueryGovernor:
    """Deployment-level policy layer for multi-query correlation risk.

    Refuses to serve an opening whose claim set differs from a previously served
    one by fewer than min_new_items items per batch, and optionally caps the
    number of distinct openings per batch.
    """

    def __init__(self, batch_size=DEFAULT_BATCH_SIZE, min_new_items=3,
                 max_openings_per_batch=None, logger=None):
        self.batch_size             = batch_size
        self.min_new_items          = min_new_items
        self.max_openings_per_batch = max_openings_per_batch
        self.logger                 = logger
        self._history               = {}

    def _local_claim_sets(self, iset):
        by_batch = {}
        for g in iset:
            b = g // self.batch_size
            by_batch.setdefault(b, set()).add(g - b * self.batch_size)
        return {b: frozenset(s) for b, s in by_batch.items()}

    def _warn(self, msg):
        if self.logger is not None:
            self.logger.warning(msg)

    def authorize(self, iset):
        local = self._local_claim_sets(iset)
        for b, claim in local.items():
            history = self._history.get(b, [])
            if claim in history:
                continue
            if (self.max_openings_per_batch is not None
                    and len(history) >= self.max_openings_per_batch):
                self._warn(f"QueryGovernor: batch {b} refused — at cap of "
                           f"{self.max_openings_per_batch}")
                raise QueryPolicyViolation(
                    f"batch {b} is at its opening cap ({self.max_openings_per_batch})")
            for prev in history:
                diff = len(claim ^ prev)
                if diff < self.min_new_items:
                    self._warn(f"QueryGovernor: batch {b} refused — diff={diff} "
                               f"< min_new_items={self.min_new_items}")
                    raise QueryPolicyViolation(
                        f"batch {b}: claim set differs from a prior one by only "
                        f"{diff} item(s) (< min_new_items={self.min_new_items})")
        for b, claim in local.items():
            history = self._history.setdefault(b, [])
            if claim not in history:
                history.append(claim)

    def history_for_batch(self, batch_index):
        return list(self._history.get(batch_index, []))


def ps6_governed(governor, iset, h_list, mq_sec, v_list, sys, params,
                 rounds=DEFAULT_ROUNDS, expect=None):
    """governor.authorize(iset) then ps6(...)."""
    governor.authorize(iset)
    return ps6(iset, h_list, mq_sec, v_list, sys, params,
               rounds=rounds, expect=expect)


# ═══════════════════════════════════════════════════════════════════════════════
# Level-algebra link helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _deep_inner(A, B, mod=P):
    """Elementwise product C = A . B  in F_P."""
    return [a * b % mod for a, b in zip(A, B)]


def _inner_pow(A, k, mod=P):
    """Elementwise power C_p = A_p^k  in F_P."""
    return [pow(int(a), k, mod) for a in A]


# ═══════════════════════════════════════════════════════════════════════════════
# LinkedSystem — joint quadratic map over (a | b | c | aux) or (a | c | aux)
# ═══════════════════════════════════════════════════════════════════════════════

class LinkedSystem:
    """Joint quadratic map encoding the linkage relation as MQ rows.

    relation="mul": X = (a | b | c | aux),  linkage: c_p - a_p·b_p = 0
    relation="pow": X = (a | c | aux),       linkage: c_p - a_p^k   = 0
                    k=2 is a single diagonal quadratic row per p;
                    k>2 is degree-lifted (u_{p,j}=a_p^j, 2≤j≤k).

    Duck-types MQSystem for RestrictedMap / prove_hidden / verify_hidden:
    exposes N, m, Q, Lin, idx, F, lift.

    Rows, in order:
        per vector v in the relation:  m_rand dense random quadratic rows
        linkage rows                   (sparse, see above)
        per vector v:                  n_folds fold rows h_2(w^{(f)} ∘ v)
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

        # aux for k > 2 pow: u_{p,2..k-1}  (u_{p,k} == c_p, so only k-2 slots)
        self.aux_per_pos = 0 if (relation == "mul" or k == 2) else (k - 2)
        self.n_aux = n * self.aux_per_pos
        self.N     = self.nb * n + self.n_aux

        # monomial index map (same convention as MQSystem)
        self.idx, kk = {}, 0
        L = self.N
        for s in range(2 * L - 1):
            for i in range(max(0, s - L + 1), s // 2 + 1):
                self.idx[(i, s - i)] = kk
                kk += 1
        self.nmono = kk

        # fold weight vectors, one random vector per fold per block
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

    # ── variable layout ───────────────────────────────────────────────────────

    def off(self, blk):
        """Offset of block 'blk' in the joint variable vector."""
        return self.blocks.index(blk) * self.n

    def aux_index(self, p, j):
        """Index of aux variable u_{p,j} = a_p^j  for 2 ≤ j ≤ k-1."""
        return self.nb * self.n + p * self.aux_per_pos + (j - 2)

    @staticmethod
    def _key(i, j):
        return (i, j) if i <= j else (j, i)

    def _add(self, q, lin):
        if _HAVE_GMP:
            q   = [_mpz(v) for v in q]
            lin = [_mpz(v) for v in lin]
        self.Q.append(q)
        self.Lin.append(lin)

    def _build(self):
        n = self.n
        # ── dense random rows, one block at a time ────────────────────────────
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

        # ── linkage rows ──────────────────────────────────────────────────────
        self.link_rows = []
        oa, oc = self.off("a"), self.off("c")
        if self.relation == "mul":
            ob = self.off("b")
            for p in range(n):
                q, lin = [0] * self.nmono, [0] * self.N
                q[self.idx[self._key(oa + p, ob + p)]] = P - 1   # −a_p·b_p
                lin[oc + p] = 1                                   # +c_p
                self.link_rows.append(len(self.Q))
                self._add(q, lin)
        else:
            for p in range(n):
                if self.k == 2:
                    q, lin = [0] * self.nmono, [0] * self.N
                    q[self.idx[self._key(oa + p, oa + p)]] = P - 1  # −a_p²
                    lin[oc + p] = 1                                  # +c_p
                    self.link_rows.append(len(self.Q))
                    self._add(q, lin)
                else:
                    # u_{p,2}=a_p²; u_{p,j}=a_p·u_{p,j-1}; c_p=u_{p,k}
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

        # ── fold rows (one set per block) ─────────────────────────────────────
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

    # ── evaluation ────────────────────────────────────────────────────────────

    def fold(self, vec, blk, f):
        """h_2(w^{(f)} ∘ vec) normalised via vsum_level_fold_fast."""
        nz = [i for i in range(len(vec)) if vec[i]]
        if not nz:
            return 0
        pmax  = max(nz)
        inv10 = pow(10, P - 2, P)
        w     = self.W[blk][f]
        xs    = [vec[p] * w[p] % P * pow(inv10, pmax - p, P) % P
                 for p in range(len(vec))]
        return int(ut.vsum_level_fold_fast(2, xs, P))

    def lift(self, vecs):
        """vecs: dict block → list.  Returns the full joint vector X."""
        X = []
        for blk in self.blocks:
            v = [int(x) % P for x in vecs[blk]]
            assert len(v) == self.n
            X += v
        if self.aux_per_pos:
            a   = vecs["a"]
            aux = [0] * self.n_aux
            for p in range(self.n):
                cur = acc = int(a[p]) % P
                for j in range(2, self.k):
                    acc = acc * cur % P
                    aux[self.aux_index(p, j) - self.nb * self.n] = acc
            X += aux
        return X

    def F(self, X):
        """Evaluate the joint map at X ∈ F_P^N → output in F_P^m."""
        assert len(X) == self.N
        X    = [int(v) % P for v in X]
        mono = MQSystem.monomials(X)
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


# ═══════════════════════════════════════════════════════════════════════════════
# Linked commitment API
# ═══════════════════════════════════════════════════════════════════════════════

def commit_linked(vals_a, vals_b=None, relation="mul", k=2,
                  blinders=DEFAULT_BLINDERS, sys=None, **sys_kw):
    """Commit to A and its linked partner(s).  Returns (v, secret, sys).

    relation="mul": needs vals_b of the same length; commits A, B, C = A·B.
    relation="pow": commits A and C = [a_p^k]; vals_b not used.

    Items are hashed to F_P with fresh per-item salts; `blinders` extra random
    positions are appended to every vector so the unopened part stays hidden.
    """
    n = len(vals_a) + blinders
    if relation == "mul":
        if vals_b is None or len(vals_b) != len(vals_a):
            raise ValueError("mul relation needs vals_b of the same length")
    if sys is None:
        sys = LinkedSystem(n, relation, k, **sys_kw)
    assert sys.n == n

    salts_a = [_secrets.token_hex(16) for _ in vals_a]
    a = [hash_to_field(p, s, v)
         for p, (s, v) in enumerate(zip(salts_a, vals_a))]
    a += _rand_vec(n - len(a))        # blinders

    vecs   = {"a": a}
    salts  = {"a": salts_a}
    if relation == "mul":
        salts_b = [_secrets.token_hex(16) for _ in vals_b]
        b = [hash_to_field(10 ** 6 + p, s, v)
             for p, (s, v) in enumerate(zip(salts_b, vals_b))]
        b += _rand_vec(n - len(b))
        vecs["b"] = b
        vecs["c"] = _deep_inner(a, b, P)
        salts["b"] = salts_b
    else:
        vecs["c"] = _inner_pow(a, k, P)

    X = sys.lift(vecs)
    v = sys.F(X)
    return v, {"X": X, "vecs": vecs, "salts": salts}, sys


def open_linked(sys, v, secret, open_positions, rounds=DEFAULT_ROUNDS):
    """Open positions of block 'a' with a 5-pass SSH ZK proof.

    open_positions : iterable of integer indices into block 'a'.
    Returns {"salts": {p: salt}, "proof": ssh_proof}.
    """
    X     = secret["X"]
    known = {sys.off("a") + p: X[sys.off("a") + p] for p in open_positions}
    R     = RestrictedMap(sys, known)
    z     = [X[i] for i in R.hidden]
    proof = prove_hidden(sys, v, known, z, rounds)
    salts = {p: secret["salts"]["a"][p] for p in open_positions}
    return {"salts": salts, "proof": proof}


def verify_linked(sys, v, claims, witness):
    """Verify a linked opening.

    claims  : {position → claimed_value}  (positions in block 'a')
    witness : return value of open_linked
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
