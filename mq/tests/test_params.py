"""The shared parameter dict and its enforcement.

params reaches the verifier FROM the prover: it carries no secrets but is
not self-authenticating, so structural validation always runs and expect=
pins it against out-of-band agreement."""
from harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    base  = [mk(i) for i in range(12)]
    extra = [mk(i) for i in range(100, 107)]
    B     = Commitment(base + extra, D, chunk_size=U_CS, batch_size=U_BS)
    c_b, h_b, x_b, mq_b, v_b, sys_b, p_b = B.opening()

    # -- params enforcement ------------------------------------------------
    p_ok = B.params
    check("params        : correct expect= accepted",
          proves_with_expect(B, [0], dict(p_ok)))

    def rejects(expect_or_params, use_as_expect=True):
        try:
            ps = ps6({0}, h_b, mq_b, v_b, sys_b, p_b)
            if use_as_expect:
                vs6(c_b, {0: B.vals[0]}, ps, x_b, sys_b, p_b,
                    expect=expect_or_params)
            else:
                vs6(c_b, {0: B.vals[0]}, ps, x_b, sys_b,
                    expect_or_params)
            return False
        except ParamMismatch:
            return True

    check("params        : wrong pinned d rejected",   rejects({"d": p_ok["d"] + 1}))
    check("params        : wrong pinned mod rejected",  rejects({"mod": p_ok["mod"] - 2}))
    check("params        : typo in expect key rejected", rejects({"chunck_size": 12}))
    check("params        : nonsense mod rejected",
          rejects({**p_ok, "mod": 1}, use_as_expect=False))
    check("params        : ms6/vs6 PARAM_KEYS agree", PARAM_KEYS == VS6_PARAM_KEYS)


if __name__ == "__main__":
    standalone(run, "test_params checks")
