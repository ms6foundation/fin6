"""x_list determinism and basic Commitment sizing checks.

In the MQ scheme x_list is constant (all entries equal _seal_fold_rows(chunk_size))
so the key invariants here are: x_list is uniform, c is correctly assembled,
and two independent commits of the same vals produce valid (if not identical)
proofs."""
from harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    d, u_cs, u_bs = D, U_CS, U_BS

    # x_list is all-uniform in the MQ scheme (seal_fold_rows(chunk_size)).
    det_vals = [mk(i) for i in range(37)]
    _, _, x_list_1, *_ = ms6(det_vals, d, chunk_size=u_cs, batch_size=u_bs)
    _, _, x_list_2, *_ = ms6(det_vals, d, chunk_size=u_cs, batch_size=u_bs)
    check("x-sizing      : x_list is uniform (constant per chunk_size)",
          len(set(x_list_1)) == 1)
    check("x-sizing      : x_list identical across independent commits",
          x_list_1 == x_list_2)

    # Two independent commits of the same vals each produce a valid proof.
    c1, h1, x1, mq1, v1, sys1, p1 = ms6(det_vals, d, chunk_size=u_cs, batch_size=u_bs)
    c2, h2, x2, mq2, v2, sys2, p2 = ms6(det_vals, d, chunk_size=u_cs, batch_size=u_bs,
                                          sys=sys1)   # shared sys for cross-verify
    check("x-sizing      : first commit verifies",
          vs6(c1, {0: det_vals[0], 5: det_vals[5]},
               ps6([0, 5], h1, mq1, v1, sys1, p1), x1, sys1, p1))
    check("x-sizing      : second independent commit also verifies",
          vs6(c2, {0: det_vals[0], 5: det_vals[5]},
               ps6([0, 5], h2, mq2, v2, sys2, p2), x2, sys2, p2))

    # Commitment class produces valid proofs.
    C = Commitment(det_vals, d, chunk_size=u_cs, batch_size=u_bs)
    # ms6() uses fresh random salts each time, so two independent commits
    # of the same data produce different roots.  Check that Commitment's own
    # root appears in its h_list fold (internal consistency).
    x_seal = M._seal_fold_rows(u_cs)
    check("x-sizing      : Commitment.c equals _seal_batch of its own h_list",
          C.c == _seal_batch(C.h_list, u_cs, x_seal, d, C.mod))
    check("x-sizing      : Commitment round-trip verifies",
          proves(C, [0, len(det_vals) - 1]))


if __name__ == "__main__":
    standalone(run, "test_sizing checks")
