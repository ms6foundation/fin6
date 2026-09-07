"""End-to-end commit -> open -> verify, at a realistic size.

The smoke test: if this fails, nothing else in the suite is meaningful."""
from harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    chunk_size, batch_size, d = 40, 1000, 3

    vals = [mk(i) for i in range(10000)]
    c, h_list, x_list, mq_sec, v_list, sys_, params = ms6(
        vals, d, chunk_size=chunk_size, batch_size=batch_size,
        seal_batch_size=batch_size)

    print(f"batches: {len(h_list)}")
    claims = {0: vals[0], 4: vals[4]}

    agreed = {"d": d, "chunk_size": chunk_size, "batch_size": batch_size,
              "seal_batch_size": batch_size, "mod": DEFAULT_MOD}

    ps_list = ps6(claims.keys(), h_list, mq_sec, v_list, sys_, params)
    check("round trip    : commit -> open -> verify over %d items" % len(vals),
          vs6(c, claims, ps_list, x_list, sys_, params, workers=1, expect=agreed))

    # A wrong value must be rejected.
    tampered = dict(claims)
    tampered[0] = vals[1]
    try:
        vs6(c, tampered, ps_list, x_list, sys_, params, workers=1, expect=agreed)
        rejected = False
    except AssertionError:
        rejected = True
    check("round trip    : tampered claim rejected", rejected)


if __name__ == "__main__":
    standalone(run, "test_roundtrip checks")
