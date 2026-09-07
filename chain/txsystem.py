"""TxSystem — the per-transaction MQ map.

One transaction, one polynomial map, one proof.  The system is a duck-typed
MQSystem in exactly the sense mq/ms6 needs (it exposes n, N, m, Qs, Lins, idx,
nmono, F, lift), so prove_hidden / verify_hidden / RestrictedMap / DirectBatched
operate on it unchanged — the same trick examples/ledger_system.py plays for a
balance table, re-cut for a spend.

Variable layout, base block (all high-entropy, all hidden):

    slot 0 … k-1        input notes,  n_note coordinates each
    slot k … k+m-1      output notes, n_note coordinates each
    bind_pos            the transaction binding scalar (public; revealed)

Extended block, appended by lift():

    bit_off + i*B + b   bit b of output i's value

Rows, in build order:

    note rows      one copy of NOTE_SYS's whole map per note slot.  Their v
                   entries ARE that note's commitment vector, which is what
                   ties a hidden value to the commitment the ledger stores.
    sum row        sum(inputs) - sum(outputs)        = fee     (public)
    asset rows     asset_s - asset_0                 = 0
    recomp rows    value_out_i - sum_b 2^b * bit[i][b] = 0
    bit rows       bit^2 - bit                       = 0
    nullifier rows the public nullifier form over each input slot
    owner rows     owner coordinate of each input slot (published pubkey)
    bind row       the binding scalar                = beta

Only OUTPUT values carry range rows.  Input values are already known to lie in
[0, 2^B) by induction: every note in the UTXO set was either issued at genesis
(checked by the issuer) or was an output of an accepted transaction (range
proven then).  With k, m small and B << 255 the sum row cannot wrap the field,
so conservation over the integers follows from conservation mod P.
"""
from __future__ import annotations

from functools import lru_cache

from mq.ms6 import MQSystem, P

from .notes import nullifier_coeffs, system_for
from .params import ChainParams, NOTE_ASSET, NOTE_OWNER, NOTE_VALUE


class TxSystem:
    """MQ system for one transaction shape (k inputs, m outputs)."""

    def __init__(self, params: ChainParams, n_inputs: int, n_outputs: int):
        if n_inputs < 1:
            raise ValueError("a transaction needs at least one input "
                             "(issuance goes through chain.state.issue)")
        if n_outputs < 1:
            raise ValueError("a transaction needs at least one output")

        self.params = params
        self.k = n_inputs
        self.m_out = n_outputs
        self.note_sys = nsys = system_for(params)
        self.n_note = n_note = params.n_note
        self.range_bits = B = params.range_bits

        self.n_slots = n_slots = n_inputs + n_outputs
        self.slot_off = [s * n_note for s in range(n_slots)]
        self.bind_pos = n_slots * n_note

        self.n = n = self.bind_pos + 1          # base block width
        self.bit_off = n
        self.N = n + n_outputs * B              # + range-decomposition bits

        # ── monomial index map ────────────────────────────────────────────────
        # Base pairs in MQSystem.monomials() bucket order, so that
        # monomials(x_base)[idx[(i, j)]] == x_base[i] * x_base[j].
        self.idx = {}
        kk = 0
        L = n
        for s in range(2 * L - 1):
            for i in range(max(0, s - L + 1), s // 2 + 1):
                self.idx[(i, s - i)] = kk
                kk += 1
        # Diagonals for the bit variables (the only monomials they appear in).
        for bk in range(n_outputs * B):
            bv = n + bk
            self.idx[(bv, bv)] = kk
            kk += 1
        self.nmono = kk

        self.Q = self.Lin = None                # dense storage never built
        self.Qs, self.Lins, self.kind = [], [], []

        # ── note rows: one copy of NOTE_SYS per slot ─────────────────────────
        inv = [None] * nsys.nmono
        for (i, j), k_ in nsys.idx.items():
            inv[k_] = (i, j)

        self.note_rows = []
        for s in range(n_slots):
            off = self.slot_off[s]
            rows = []
            for l in range(nsys.m):
                qs = []
                for k_, c in nsys.Qs[l]:
                    i, j = inv[k_]
                    qs.append((self.idx[(off + i, off + j)], int(c)))
                lins = [(off + i, int(c)) for i, c in nsys.Lins[l]]
                nk = nsys.kind[l]
                kind = (("nfold", s, nk[1]) if nk is not None and nk[0] == "fold"
                        else ("nrow", s, l))
                rows.append(self._add_row(qs, lins, kind))
            self.note_rows.append(rows)

        # ── sum row: sum(in) - sum(out) = fee ────────────────────────────────
        sum_lins = []
        for s in range(n_slots):
            coef = 1 if s < n_inputs else P - 1
            sum_lins.append((self.slot_off[s] + NOTE_VALUE, coef))
        self.sum_row = self._add_row([], sum_lins, ("lin", "sum"))

        # ── asset rows: every note in the transaction shares one asset ───────
        self.asset_rows = []
        a0 = self.slot_off[0] + NOTE_ASSET
        for s in range(1, n_slots):
            lins = [(self.slot_off[s] + NOTE_ASSET, 1), (a0, P - 1)]
            self.asset_rows.append(self._add_row([], lins, ("lin", "asset")))

        # ── range decomposition of each output value ─────────────────────────
        self.range_rows, self.bit_rows = [], []
        for i in range(n_outputs):
            off = self.slot_off[n_inputs + i]
            lins = [(off + NOTE_VALUE, 1)]
            lins += [(self.bit_off + i * B + b, (P - pow(2, b, P)) % P)
                     for b in range(B)]
            self.range_rows.append(self._add_row([], lins, ("lin", "recomp")))
        for bk in range(n_outputs * B):
            bv = self.bit_off + bk
            self.bit_rows.append(
                self._add_row([(self.idx[(bv, bv)], 1)], [(bv, P - 1)],
                              ("bit", bv)))

        # ── nullifier rows: the public form over each input slot ────────────
        self.nf_rows = []
        form = nullifier_coeffs(n_note)
        for j in range(n_inputs):
            off = self.slot_off[j]
            qs = [(self.idx[(off + i, off + jj)], int(c)) for i, jj, c in form]
            self.nf_rows.append(self._add_row(qs, [], ("nf", j)))

        # ── owner rows: expose each input's owner coordinate ────────────────
        # Output owners stay hidden; only the spender must be identified so a
        # signature can be checked against the note's own owner slot.
        self.owner_rows = []
        for j in range(n_inputs):
            off = self.slot_off[j]
            self.owner_rows.append(
                self._add_row([], [(off + NOTE_OWNER, 1)], ("lin", "owner")))

        # ── binding row ──────────────────────────────────────────────────────
        self.bind_row = self._add_row([], [(self.bind_pos, 1)], ("lin", "bind"))

        self.m = len(self.Qs)

        self.n_aux = 0
        self.aux_per_fold = 0
        self.K = 2
        self.W = nsys.W

    # ── construction helper ──────────────────────────────────────────────────

    def _add_row(self, qs, lins, kind):
        self.Qs.append([(k, c) for k, c in qs if c])
        self.Lins.append([(k, c) for k, c in lins if c])
        self.kind.append(kind)
        return len(self.Qs) - 1

    # ── MQSystem surface ─────────────────────────────────────────────────────

    @staticmethod
    def monomials(X):
        return MQSystem.monomials(X)

    @staticmethod
    def fast_h2(w, x):
        return MQSystem.fast_h2(w, x)

    def fold(self, x, f):
        raise NotImplementedError(
            "TxSystem folds are per-note-slot; use F() or the batched form")

    def lift(self, x_base):
        """Base block -> full variable vector, appending output range bits."""
        x_base = [int(a) % P for a in x_base]
        if len(x_base) != self.n:
            raise ValueError(f"expected {self.n} base coords, got {len(x_base)}")
        B = self.range_bits
        bits = []
        for i in range(self.m_out):
            value = x_base[self.slot_off[self.k + i] + NOTE_VALUE]
            for b in range(B):
                bits.append((value >> b) & 1)
        return x_base + bits

    def F(self, X):
        """Evaluate every row at X."""
        if len(X) != self.N:
            raise ValueError(f"expected {self.N} variables, got {len(X)}")
        X = [int(a) % P for a in X]
        x_base = X[:self.n]
        mono = None
        out = []
        for qs, lins, kind in zip(self.Qs, self.Lins, self.kind):
            tag = kind[0]

            if tag == "nfold":                      # O(n_note) fast path
                _, s, f = kind
                off = self.slot_off[s]
                out.append(self.fast_h2(self.note_sys.W[f],
                                        x_base[off:off + self.n_note]))
                continue

            if tag == "lin":                        # pure linear rows
                acc = 0
                for k_, c in lins:
                    acc += c * X[k_]
                out.append(int(acc % P))
                continue

            if tag == "bit":                        # bit^2 - bit
                bv = kind[1]
                b = X[bv]
                out.append(int((b * b - b) % P))
                continue

            # note dense rows and nullifier rows: sparse over base monomials
            if mono is None:
                mono = self.monomials(x_base)
            acc = 0
            for k_, c in qs:
                acc += c * mono[k_]
            for k_, c in lins:
                acc += c * X[k_]
            out.append(int(acc % P))
        return out

    # ── views onto a public v vector ─────────────────────────────────────────

    def note_vector_of(self, v, slot: int):
        """The slot's note commitment vector, as carried inside v."""
        return [int(v[r]) for r in self.note_rows[slot]]

    def input_slots(self):
        return range(self.k)

    def output_slots(self):
        return range(self.k, self.n_slots)

    def __repr__(self):
        return (f"TxSystem({self.params.name}, {self.k}in/{self.m_out}out, "
                f"n={self.n} N={self.N} m={self.m} h={self.N - 1})")


@lru_cache(maxsize=64)
def _cached(fingerprint, n_inputs, n_outputs, params):
    return TxSystem(params, n_inputs, n_outputs)


def tx_system(params: ChainParams, n_inputs: int, n_outputs: int) -> TxSystem:
    """Cached TxSystem — pure function of (params, shape), so every node in
    the network derives an identical system without transmitting it."""
    return _cached(params.name, n_inputs, n_outputs, params)
