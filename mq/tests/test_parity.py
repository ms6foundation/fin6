"""Parity between the deliberately duplicated prover and verifier copies.

vs6/ duplicates a slice of ms6/ so the verifier can be installed alone.
Nothing in the language keeps the copies in step, so these compare their
OUTPUTS on identical inputs (not source text -- docstrings legitimately
differ). This is the only check that catches drift in code no proof path
happens to exercise."""
import random as _random

from harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, _seal_hash, chunk_of, chunks,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    _V  = V
    _vu = vs6pkg.utils6
    _vut = _vu.Utils()
    prng = _random.Random(4242)
    ri   = lambda b=160: prng.randrange(1, 1 << b)
    mod_ = DEFAULT_MOD

    def parity(group, cases):
        drifted = sorted(n for n, (a, b) in cases.items() if a != b)
        check(f"copy parity   : {group}"
              + (f" -- DRIFTED: {', '.join(drifted)}" if drifted else ""),
              not drifted)

    # ── seal-tree helpers ──────────────────────────────────────────────────
    svals = [str(ri(200)) for _ in range(15)]
    perm_ = list(range(12)); _random.Random(11).shuffle(perm_)
    idxs  = [prng.randrange(0, 10000) for _ in range(50)]
    seal_cases = {}
    for n_, sbs_ in ((1, 1000), (5, 1000), (30, 4), (501, 100)):
        lv = [_seal_hash(ri(200)) for _ in range(n_)]
        seal_cases[f"_seal_batch(n={n_},sbs={sbs_})"] = (
            _seal_batch(lv, 12, 2, 3, mod_, sbs_),
            _V._seal_batch(lv, 12, 2, 3, mod_, sbs_))

    pp = make_params(3, 12, 5, mod_, 7, blinders=8)
    parity("ms6.py <-> vs6.py", {
        "chunk_of":      ([chunk_of(v, 3, 12) for v in svals],
                          [_V.chunk_of(v, 3, 12) for v in svals]),
        "_permute_row":  ([_permute_row(r[:12], perm_) for r in svals],
                          [_permute_row(r[:12], perm_) for r in svals]),  # same func
        "_get_batch_ids": (_get_batch_ids(idxs, 1000), _V._get_batch_ids(idxs, 1000)),
        "PARAM_KEYS":    (PARAM_KEYS, _V.PARAM_KEYS),
        "unpack_params": (unpack_params(pp), _V.unpack_params(pp)),
        **seal_cases,
    })

    # ── utils6 helpers ─────────────────────────────────────────────────────
    ints  = [ri(220) for _ in range(10)]
    cnts  = [[prng.randrange(0, 30) for _ in range(10)] for _ in range(5)]
    vrows = [[ri(120) for _ in range(8)] for _ in range(4)]
    A_    = ut.h_vector_mod(3, mod_, values=vrows[0])
    B_    = ut.h_vector_mod(3, mod_, values=vrows[1])
    parity("ms6.utils6 <-> vs6.utils6", {
        "DEFAULT_MOD":   (u.DEFAULT_MOD, _vu.DEFAULT_MOD),
        "domain_hash":   ([ut.domain_hash(f"tag:{v}".encode()) for v in ints],
                          [_vut.domain_hash(f"tag:{v}".encode()) for v in ints]),
        "backward_chunk": ([list(ut.backward_chunk(str(v), 12)) for v in ints],
                           [list(_vut.backward_chunk(str(v), 12)) for v in ints]),
        "cell_product":  ([ut.cell_product(c, m) for c in cnts for m in (1, 3)],
                          [_vut.cell_product(c, m) for c in cnts for m in (1, 3)]),
        "cell_product_mod": ([ut.cell_product_mod(c, m, mod_) for c in cnts for m in (1, 3)],
                              [_vut.cell_product_mod(c, m, mod_) for c in cnts for m in (1, 3)]),
        "vsum_level":    ([ut.vsum_level(r, b=b) for r in vrows for b in (1, 4)],
                          [_vut.vsum_level(r, b=b) for r in vrows for b in (1, 4)]),
        "vsum_level_fold_fast": (
            [ut.vsum_level_fold_fast(N, r, mod_) for r in vrows for N in (1, 3)],
            [_vut.vsum_level_fold_fast(N, r, mod_) for r in vrows for N in (1, 3)]),
    })

    # ── MQ copy parity ─────────────────────────────────────────────────────
    # Both ms6/core.py and vs6/core.py duplicate MQSystem, RestrictedMap,
    # verify_hidden, hash_to_field, _mq_batch_digest.  Check they agree.
    import hashlib, secrets as _sec
    P = M.P
    n = 10
    sys_m = M.MQSystem(n)
    sys_v = V.MQSystem(n)

    def rand_vec(k):
        return [_random.Random(prng.random()).randrange(P) for _ in range(k)]

    x_tests = [rand_vec(n) for _ in range(5)]
    parity("MQSystem.F (ms6 <-> vs6)", {
        f"F(x{i})": (sys_m.F(x), sys_v.F(x))
        for i, x in enumerate(x_tests)
    })

    # _mq_batch_digest
    parity("_mq_batch_digest (ms6 <-> vs6)", {
        f"digest{i}": (M._mq_batch_digest(sys_m.F(x)), V._mq_batch_digest(sys_v.F(x)))
        for i, x in enumerate(x_tests)
    })

    # hash_to_field
    parity("hash_to_field (ms6 <-> vs6)", {
        "htf": ([M.hash_to_field(i, "salt", i * 3) for i in range(10)],
                [V.hash_to_field(i, "salt", i * 3) for i in range(10)]),
    })

    # End-to-end: an SSH proof produced by ms6.prove_hidden must verify under
    # vs6.verify_hidden (this is the same as the round-trip but at the MQ level).
    known_pos = {0: rand_vec(1)[0], 3: rand_vec(1)[0]}
    hidden    = [i for i in range(n) if i not in known_pos]
    z         = rand_vec(len(hidden))   # one entry per hidden coordinate
    full_x    = [0] * n
    for i, a in known_pos.items():
        full_x[i] = a
    for i, a in zip(hidden, z):
        full_x[i] = a
    v_val = sys_m.F(full_x)
    proof = M.prove_hidden(sys_m, v_val, known_pos, z, rounds=10)
    check("copy parity   : ms6.prove_hidden accepted by vs6.verify_hidden",
          V.verify_hidden(sys_v, v_val, known_pos, proof))


if __name__ == "__main__":
    standalone(run, "test_parity checks")
