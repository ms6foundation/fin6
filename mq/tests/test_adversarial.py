"""Adversarial suite: batch-routing coverage plus tamper/forge attempts.

Exercises claims within one batch, spanning several with untouched batches in
between, in the uneven final batch, and a fully-claimed batch (empty hidden
set) — then tries to break it: tampered values, wrong-index substitution,
fabricated values, cross-batch swaps, an iset/proof mismatch, and MQ-level
equivocation (wrong v, wrong salt, replayed proof for a different opened set).

Two things here are load-bearing rather than stylistic:
  * the __main__ guard and run() wrapper
  * results go through the shared `check`
"""
import random
import sys

sys.set_int_max_str_digits(2000000)

from harness import ms6, ps6, vs6, M, standalone  # noqa: E402


def run(check):
    chunk_size, d = 10, 3
    BATCH_SIZE = 20
    N = 97   # deliberately not a multiple of BATCH_SIZE → uneven last batch
    vals = [(1720941241 + (i**70) ^ (i**99)) % 2**200 for i in range(N)]
    rnd  = random.Random(42)

    c, h_list, x_list, mq_sec, v_list, sys_, params = ms6(
        vals, d, chunk_size=chunk_size, batch_size=BATCH_SIZE)
    n_batches = len(h_list)
    print(f"n_batches={n_batches} (N={N}, batch_size={BATCH_SIZE})")

    def verify(claims, ps_list=None):
        if ps_list is None:
            ps_list = ps6(claims.keys(), h_list, mq_sec, v_list, sys_, params)
        vs6(c, claims, ps_list, x_list, sys_, params)

    def expect_pass(name, fn):
        try:
            fn()
            ok = True
        except Exception:
            ok = False
        return check(f"adversarial   : {name}", ok)

    def expect_reject(name, fn):
        try:
            fn()
            ok = False
        except AssertionError:
            ok = True
        except Exception:
            ok = True
        return check(f"adversarial   : {name} -- rejected", ok)

    # ── honest cases ──────────────────────────────────────────────────────────

    # 1. single claim, single batch
    expect_pass("single claim (batch 0)", lambda: verify({5: vals[5]}))

    # 2. two claims in the SAME batch
    expect_pass("two claims, same batch", lambda: verify({2: vals[2], 7: vals[7]}))

    # 3. claims spanning multiple batches, with an untouched batch in between
    expect_pass("claims spanning 3 batches, gaps between",
                lambda: verify({5: vals[5], 45: vals[45], 90: vals[90]}))

    # 4. claim in the last (short/uneven) batch
    last_idx = N - 1
    expect_pass(f"claim in final uneven batch (idx {last_idx})",
                lambda: verify({last_idx: vals[last_idx]}))

    # 5. claim EVERY item in one batch (fully-claimed batch)
    batch0_idxs = list(range(0, BATCH_SIZE))
    expect_pass("fully-claimed batch",
                lambda: verify({i: vals[i] for i in batch0_idxs}))

    # 6. claims touching every batch
    expect_pass("claims touching every batch",
                lambda: verify({i: vals[i] for i in [0, 25, 45, 65, 90]}))

    # ── adversarial cases ─────────────────────────────────────────────────────

    # 7. tampered claim (+1)
    ps7 = ps6([5, 45], h_list, mq_sec, v_list, sys_, params)
    expect_reject("tampered claim (+1)",
                  lambda: vs6(c, {5: vals[5] + 1, 45: vals[45]},
                               ps7, x_list, sys_, params))

    # 8. wrong-index substitution (real value, wrong position)
    expect_reject("wrong-index substitution",
                  lambda: vs6(c, {5: vals[6], 45: vals[45]},
                               ps7, x_list, sys_, params))

    # 9. fully fabricated value
    expect_reject("fully fabricated value",
                  lambda: vs6(c, {5: rnd.randrange(2**200), 45: vals[45]},
                               ps7, x_list, sys_, params))

    # 10. cross-batch swap (vals[5]'s value claimed at position 45 too)
    expect_reject("cross-batch value swap",
                  lambda: vs6(c, {5: vals[5], 45: vals[5]},
                               ps7, x_list, sys_, params))

    # 11. proof for a DIFFERENT iset than what's claimed
    ps11 = ps6([5], h_list, mq_sec, v_list, sys_, params)
    expect_reject("claims/proof iset mismatch",
                  lambda: vs6(c, {45: vals[45]}, ps11, x_list, sys_, params))

    # 12. MQ equivocation: swap v_b for a different value in ps_list
    #     The proof was built for the real v; a different v → statement mismatch.
    import copy
    ps12 = ps6([5], h_list, mq_sec, v_list, sys_, params)
    ps12_bad = copy.deepcopy(ps12)
    # Flip the first component of v in the touched batch.
    b0 = 5 // BATCH_SIZE
    ps12_bad[b0]["v"] = [(x ^ 1) for x in ps12_bad[b0]["v"]]
    expect_reject("MQ equivocation: wrong v in ps_b",
                  lambda: vs6(c, {5: vals[5]}, ps12_bad, x_list, sys_, params))

    # 13. Wrong salt in ps_list (the hash_to_field(gi, salt, val) won't match x_b[local]).
    ps13 = ps6([5], h_list, mq_sec, v_list, sys_, params)
    ps13_bad = copy.deepcopy(ps13)
    ps13_bad[b0]["salts"][5] = "deaddead" * 4
    expect_reject("wrong per-item salt in ps_b",
                  lambda: vs6(c, {5: vals[5]}, ps13_bad, x_list, sys_, params))

    # 14. Replayed proof from a completely different commit (wrong h_list root).
    c2, h2, x2, sec2, v2, _, params2 = M.ms6(
        [(i * 7 + 3) % 2**200 for i in range(N)],
        d, chunk_size=chunk_size, batch_size=BATCH_SIZE)
    ps14 = ps6([5], h2, sec2, v2, sys_, params2)
    # Try to use the foreign proof against the original commitment.
    expect_reject("replayed proof from different commit",
                  lambda: vs6(c, {5: vals[5]}, ps14, x_list, sys_, params))

    # ── digit encoding ────────────────────────────────────────────────────────
    # The seal-tree fold uses digit-based encoding: check it's injective.
    collisions = [
        ([6],       [2, 3]),
        ([4],       [2, 2]),
        ([9],       [3, 3]),
        ([8],       [2, 2, 2]),
        ([1, 1, 1, 6], [2, 3]),
    ]

    def counts(digits):
        cnt = [0] * 11
        for dg in digits:
            cnt[dg] += 1
        return cnt

    sep = all(M.ut.cell_product(counts(a), 1) != M.ut.cell_product(counts(b), 1)
              for a, b in collisions)
    check("adversarial   : digit encoding separates all known collisions", sep)

    seen, injective = {}, True
    for a in range(10):
        for b in range(a, 10):
            for c_ in range(b, 10):
                for e in range(c_, 10):
                    key = M.ut.cell_product(counts([a, b, c_, e]), 1)
                    if key in seen:
                        injective = False
                    seen[key] = (a, b, c_, e)
    check("adversarial   : no two distinct 4-digit multisets share a cell value",
          injective)


if __name__ == "__main__":
    standalone(run, "test_adversarial checks")
