"""
ms6mqfin.py  —  financial ledger commitment on the MQ-hardened ms6 stack.

Architecture
────────────
                 ┌──────────────────────────────────────┐
  Outer layer:   │  Seal tree  (root c, leaf h_mq)      │  ms6 primitives
                 └────────────────┬─────────────────────┘
                                  │
                 ┌────────────────▼─────────────────────┐
  MQ layer:      │  LedgerSystem   F(X) = v              │  ← this file
                 │  m_rand dense random rows             │  MQ hardness
                 │  n_folds fold rows                    │  MQ supplement
                 │  1 sum row       Σ bal_i = total      │  ledger sum
                 │  na recomp rows  bal_i = Σ 2^b b_ib  │  range decomp
                 │  na·B bit rows   b_ib² = b_ib         │  bit constraint
                 └────────────────┬─────────────────────┘
                                  │
                 ┌────────────────▼─────────────────────┐
  ZK layer:      │  prove_hidden / verify_hidden          │  ms6/core.py
                 │  gamma-batched 5-pass SSH              │
                 └──────────────────────────────────────┘

Variable layout in x (length n = 2·na + k):
  [0 .. na-1]          stored[i]  = (balance[i] + mask[i]) % P
  [na .. 2·na-1]       mask[i]    (random field element)
  [2·na .. 2·na+k-1]   blinders   (random field elements)

Extended X (length N = n + na·B), computed by lift(x):
  [n + i·B + b]   bit b of balance[i] = (stored[i] − mask[i]) % P

Opening account i reveals stored[i] and mask[i]:
  known = {i: stored[i], na+i: mask[i]}
  balance[i] = (stored[i] − mask[i]) % P   (verifier checks)

Public v (the MQ output, sent with every proof):
  v[sum_row]      = Σ balance[i] mod P  (= total)
  v[range_row_i]  = 0  (recomp satisfied)
  v[bit_row_k]    = 0  (bit constraint satisfied)
  v[0..m_rand+nf) = random-looking entries from MQ rows

Verification (verify_account) checks:
  1. balance = (stored − mask) mod P
  2. h_mq = _mq_leaf(v) matches leaf used to build commitment c
  3. verify_hidden(sys, v, {known}, proof) holds
"""

import math
import secrets as _secrets
import hashlib

from mq.ms6 import (MQSystem, RestrictedMap, prove_hidden, verify_hidden,
                 serialize_proof, DirectBatched, _SealTree,
                 DEFAULT_ROUNDS, P)
from mq.ms6.core import (_rand_vec, _vadd, _vsub,
                      _mq_leaf as _ms6_mq_leaf, _seal_fold_rows)


# ═══════════════════════════════════════════════════════════════════════════════
# Leaf hash  (mirrors ms6/core.py _mq_leaf; ms6mqfin is prover-side only)
# ═══════════════════════════════════════════════════════════════════════════════

def _mq_leaf(v):
    """Hash the MQ output v into a seal-tree leaf (str, hex digest)."""
    return _ms6_mq_leaf(v)


# ═══════════════════════════════════════════════════════════════════════════════
# LedgerSystem — duck-typed MQSystem with ledger constraint rows
# ═══════════════════════════════════════════════════════════════════════════════

class LedgerSystem:
    """MQ system for a financial ledger.

    Extends a base MQSystem (over the high-entropy block) with three extra
    constraint layers encoding ledger semantics:

      Sum row        :  Σ_i stored[i] - Σ_i mask[i]  = total   (linear)
      Recomp rows    :  stored[i] - mask[i] = Σ_b 2^b · bit[i][b]  (linear)
      Bit-constraint :  bit[i][b]² - bit[i][b] = 0               (quadratic)

    The base MQSystem rows (dense random + fold) provide MQ hardness.
    The constraint rows encode the ledger relation in the same polynomial map,
    so ONE gamma-batched 5-pass SSH proof covers all of them simultaneously.

    Parameters
    ----------
    n_accounts : int       number of accounts
    blinders   : int       number of blinder coordinates (k)
    m_rand     : int|None  dense random rows (default n-1)
    n_folds    : int       fold rows (default 2)
    range_bits : int       bits per balance (B; balances must be in [0, 2^B))
    """

    def __init__(self, n_accounts, blinders, m_rand=None, n_folds=2,
                 range_bits=30):
        na = n_accounts
        k  = blinders
        B  = range_bits

        self.n_accounts = na
        self.blinders   = k
        self.range_bits = B

        # ── variable layout ──────────────────────────────────────────────────
        self.stored_off = 0
        self.mask_off   = na
        self.blind_off  = 2 * na
        self.bit_off    = 2 * na + k        # first bit-variable position in X

        n = 2 * na + k                      # base block width (high-entropy)
        N = n + na * B                      # total variables (incl. bit vars)
        self.n = n
        self.N = N

        # ── base MQSystem (dense random + fold rows) ─────────────────────────
        base = MQSystem(n, n_folds=n_folds, m_rand=m_rand)
        self.m_rand      = base.m_rand
        self.n_folds     = base.n_folds
        self.K           = base.K
        self.W           = base.W
        self.fold_rows   = list(base.fold_rows)   # will stay unchanged
        self.fold_weights= base.fold_weights
        self.bases       = base.bases

        m_base = base.m         # m_rand + n_folds (for K=2; more for K>2)

        # ── monomial index map ────────────────────────────────────────────────
        # Use the same bucket order as MQSystem.monomials() for base pairs,
        # so that monomials(x_base)[kk] == x_base[i]*x_base[j] where
        # self.idx[(i,j)] == kk.
        self.idx = {}
        kk = 0
        L = n
        for s in range(2 * L - 1):
            for i in range(max(0, s - L + 1), s // 2 + 1):
                j = s - i
                self.idx[(i, j)] = kk
                kk += 1
        nmono_base = kk

        # Diagonal monomials for bit variables (needed by bit-constraint rows).
        for bk in range(na * B):
            bv = n + bk                    # position of this bit variable in X
            self.idx[(bv, bv)] = kk
            kk += 1
        self.nmono = kk

        # ── Q/Lin: None (dense storage impossible for large N) ────────────────
        self.Q   = None
        self.Lin = None

        # ── sparse rows (Qs/Lins/kind) ────────────────────────────────────────
        # Copy base rows verbatim (their Qs/Lins reference base-block monomials).
        self.Qs   = list(base.Qs)
        self.Lins = list(base.Lins)
        self.kind = list(base.kind)

        # ── sum row ───────────────────────────────────────────────────────────
        # Σ_i stored[i] - Σ_i mask[i] = total  →  row evaluates to total.
        sum_lins = ([(i,       1)   for i in range(na)] +
                    [(na + i, P-1)  for i in range(na)])
        self.Qs.append([])
        self.Lins.append(sum_lins)
        self.kind.append(("sum",))
        self.sum_row = len(self.Qs) - 1

        # ── recomp rows (range decomposition) ────────────────────────────────
        # stored[i] - mask[i] - Σ_b 2^b · bit[i][b] = 0
        self.range_rows = []
        for i in range(na):
            bit_lins = [(n + i * B + b, (P - pow(2, b, P)) % P)
                        for b in range(B)]
            lins = [(i, 1), (na + i, P - 1)] + bit_lins
            self.Qs.append([])
            self.Lins.append(lins)
            self.kind.append(("recomp", i))
            self.range_rows.append(len(self.Qs) - 1)

        # ── bit-constraint rows ───────────────────────────────────────────────
        # bit[i][b]² - bit[i][b] = 0   for every bit variable
        self.bit_rows = []
        for bk in range(na * B):
            bv       = n + bk
            mono_kk  = self.idx[(bv, bv)]
            self.Qs.append([(mono_kk, 1)])   # +bit²
            self.Lins.append([(bv, P - 1)])  # -bit
            self.kind.append(("bit", bk))
            self.bit_rows.append(len(self.Qs) - 1)

        self.m = len(self.Qs)
        assert self.m == m_base + 1 + na + na * B

        # ── cached aux (K=2 only for now) ────────────────────────────────────
        self.n_aux = 0
        self.aux_per_fold = 0

    # ── static helpers (mirror MQSystem API) ─────────────────────────────────

    @staticmethod
    def monomials(X):
        return MQSystem.monomials(X)

    @staticmethod
    def fast_h2(w, x):
        return MQSystem.fast_h2(w, x)

    # ── lift: base block → full X ─────────────────────────────────────────────

    def lift(self, x_base):
        """Embed the base block into the full variable space.

        Appends na·B bit variables derived from the balance:
            bit[i][b] = (balance[i] >> b) & 1
        where balance[i] = (x_base[stored[i]] − x_base[mask[i]]) % P.

        If balance[i] ≥ 2^B the high bits are silently dropped; commit_ledger
        validates balances before calling lift.
        """
        x_base = [int(a) % P for a in x_base]
        assert len(x_base) == self.n, f"expected {self.n} base coords, got {len(x_base)}"
        na, B = self.n_accounts, self.range_bits
        bits = []
        for i in range(na):
            balance_i = (x_base[i] - x_base[na + i]) % P
            for b in range(B):
                bits.append((balance_i >> b) & 1)
        return x_base + bits

    # ── F: evaluate all rows ──────────────────────────────────────────────────

    def F(self, X):
        """Evaluate all m rows of the ledger map.

        Dispatch:
          fold rows     → O(n) fast_h2 over the base block
          sum/recomp    → sparse linear accumulation over X
          bit rows      → bit² − bit  (O(1) per row)
          dense random  → sparse linear combination of base monomials
        """
        assert len(X) == self.N, f"expected {self.N} variables, got {len(X)}"
        X = [int(a) % P for a in X]
        x_base = X[:self.n]
        na, B, n = self.n_accounts, self.range_bits, self.n

        mono = None     # lazy: only build for dense random rows
        out  = []
        for qs, lins, kind in zip(self.Qs, self.Lins, self.kind):
            if kind is not None:
                tag = kind[0]

                if tag == "fold":
                    f = kind[1]
                    out.append(self.fast_h2(self.W[f], x_base))
                    continue

                if tag in ("sum", "recomp"):
                    # Pure linear; no quadratic terms.
                    acc = 0
                    for k, c in lins:
                        acc += c * X[k]
                    out.append(int(acc % P))
                    continue

                if tag == "bit":
                    bk  = kind[1]
                    bv  = n + bk
                    bit = X[bv]
                    out.append(int((bit * bit - bit) % P))
                    continue

            # Dense random row: sparse sum over base-block monomials.
            if mono is None:
                mono = self.monomials(x_base)
            acc = 0
            for k, c in qs:
                acc += c * mono[k]
            for k, c in lins:
                acc += c * X[k]
            out.append(int(acc % P))

        return out

    # ── fold (used by ZK proof machinery) ────────────────────────────────────

    def fold(self, x, f):
        return MQSystem.fast_h2(self.W[f], x)


# ═══════════════════════════════════════════════════════════════════════════════
# Seal-tree helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _build_seal_tree(h_mq, d, mod, seal_batch_size, chunk_size=1):
    """Wrap a single MQ leaf into a seal tree and return (c, tree)."""
    x = _seal_fold_rows(chunk_size)
    tree = _SealTree([h_mq], x, chunk_size, d, mod, seal_batch_size)
    return tree.root, tree


def _verify_seal_tree(c, h_mq, d, mod, seal_batch_size, chunk_size=1):
    """Recompute the seal-tree root from a leaf and check it equals c."""
    root, _ = _build_seal_tree(h_mq, d, mod, seal_batch_size, chunk_size)
    assert root == c, "seal-tree root mismatch — v has been tampered"


# ═══════════════════════════════════════════════════════════════════════════════
# commit_ledger
# ═══════════════════════════════════════════════════════════════════════════════

def commit_ledger(balances, sys=None, *,
                  blinders=None, range_bits=None, n_folds=2, m_rand=None,
                  d=8, mod=P, seal_batch_size=1000):
    """Commit a list of balances to a LedgerSystem.

    Builds the x vector directly (no hash_to_field for ledger coords):
      stored[i] = (balance[i] + mask[i]) % P   (random mask chosen here)
      mask[i]   = random field element
      blinders  = random field elements

    Returns
    -------
    public : dict with keys "c", "v", "total", "h_mq"
    secret : dict with keys "x", "x_base", "stored", "mask", "balances"
    sys    : the LedgerSystem used (same as input if provided)
    """
    balances = list(balances)
    na = len(balances)

    if sys is None:
        if range_bits is None:
            raise ValueError("range_bits required when sys is not given")
        if blinders is None:
            raise ValueError("blinders required when sys is not given")
        sys = LedgerSystem(na, blinders, m_rand=m_rand, n_folds=n_folds,
                           range_bits=range_bits)

    B = sys.range_bits
    for i, bal in enumerate(balances):
        if not (0 <= bal < 2**B):
            raise ValueError(
                f"balance[{i}]={bal} out of [0, 2^{B}={2**B}); "
                f"either raise range_bits or reduce the balance")

    # Build x_base: stored + mask + blinders
    mask_list   = [_secrets.randbelow(P) for _ in range(na)]
    stored_list = [(bal + m) % P for bal, m in zip(balances, mask_list)]
    blind_list  = _rand_vec(sys.blinders)
    x_base      = stored_list + mask_list + blind_list

    # Lift and evaluate
    X = sys.lift(x_base)
    v = sys.F(X)

    # Outer seal-tree commitment
    h_mq        = _mq_leaf(v)
    total       = sum(balances)
    c, _        = _build_seal_tree(h_mq, d, mod, seal_batch_size)

    public = {
        "c":     c,
        "v":     v,
        "total": total,
        "h_mq":  h_mq,
        # tree params (needed to re-verify the seal)
        "_d":    d, "_mod": mod, "_sbs": seal_batch_size,
    }
    secret = {
        "x":        X,
        "x_base":   x_base,
        "stored":   stored_list,
        "mask":     mask_list,
        "balances": balances,
    }
    return public, secret, sys


# ═══════════════════════════════════════════════════════════════════════════════
# verify_total
# ═══════════════════════════════════════════════════════════════════════════════

def verify_total(sys, public):
    """Check that v[sum_row] equals the claimed total.

    This is a deterministic check on the public v vector — no ZK involved.
    It shows the committed total is consistent with the committed balances,
    but does NOT by itself prove the balances are valid (use verify_account).
    """
    v     = public["v"]
    total = public["total"]
    assert v[sys.sum_row] == total % P, (
        f"sum row mismatch: v[sum_row]={v[sys.sum_row]} != total%P={total%P}")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# verify_range
# ═══════════════════════════════════════════════════════════════════════════════

def verify_range(sys, public):
    """Check that all recomp and bit-constraint rows evaluate to zero in v.

    A non-zero entry would mean the committed bit decomposition is inconsistent
    or a bit variable is not in {0, 1}.  Together with verify_account these
    checks show the committed balances are provably in [0, 2^B).
    """
    v = public["v"]
    for row in sys.range_rows:
        assert v[row] == 0, (
            f"recomp row {row} = {v[row]} != 0 (range decomp inconsistent)")
    for row in sys.bit_rows:
        assert v[row] == 0, (
            f"bit-constraint row {row} = {v[row]} != 0 (bit not in {{0,1}})")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# open_account
# ═══════════════════════════════════════════════════════════════════════════════

def open_account(sys, public, secret, account, rounds=DEFAULT_ROUNDS):
    """Generate a ZK proof that account `account` holds `balance`.

    Reveals stored[account] and mask[account] so the verifier can recover
    balance = (stored − mask) % P.  All other coordinates (including all
    bit variables and other accounts' stored/mask values) stay hidden.

    Returns a statement dict suitable for verify_account.
    """
    na     = sys.n_accounts
    stored = secret["stored"][account]
    mask   = secret["mask"][account]

    # known: only the two coordinates being opened
    known = {account: stored, na + account: mask}

    v = public["v"]
    X = secret["x"]
    z = [X[i] for i in range(sys.N) if i not in known]

    proof = prove_hidden(sys, v, known, z, rounds=rounds)

    return {
        "account":  account,
        "balance":  secret["balances"][account],
        "stored":   stored,
        "mask":     mask,
        "proof":    proof,
        "v":        v,   # public; verifier hashes it to check the seal root
    }


# ═══════════════════════════════════════════════════════════════════════════════
# verify_account
# ═══════════════════════════════════════════════════════════════════════════════

def verify_account(sys, public, statement):
    """Verify that account `account` holds `balance` under commitment c.

    Checks (in order):
      1. balance = (stored − mask) % P
      2. balance is in [0, 2^B)
      3. h_mq = _mq_leaf(v) matches the seal-tree root c
      4. verify_hidden: the ZK proof of knowledge of hidden coords z with
         F(embed({stored, mask}, z)) = v
    """
    account = statement["account"]
    balance = statement["balance"]
    stored  = statement["stored"]
    mask    = statement["mask"]
    proof   = statement["proof"]
    v       = statement["v"]
    na      = sys.n_accounts

    # 1. balance consistency
    assert (stored - mask) % P == balance % P, (
        "stored − mask ≠ claimed balance (mod P)")

    # 2. range check
    assert 0 <= balance < 2**sys.range_bits, (
        f"claimed balance {balance} not in [0, 2^{sys.range_bits})")

    # 3. seal-tree root
    h_mq = _mq_leaf(v)
    _verify_seal_tree(
        public["c"], h_mq,
        public["_d"], public["_mod"], public["_sbs"])

    # 4. ZK proof
    known = {account: stored, na + account: mask}
    assert verify_hidden(sys, v, known, proof), "SSH proof failed"

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

# serialize_proof already imported from ms6; re-export so callers can do
#   from ms6mqfin import serialize_proof
__all__ = [
    "LedgerSystem",
    "commit_ledger",
    "open_account",
    "verify_account",
    "verify_total",
    "verify_range",
    "serialize_proof",
]
