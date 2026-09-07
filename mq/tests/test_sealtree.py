"""Stage 4: the cached _SealTree.

The cached root must equal an uncached _seal_batch fold at every step --
across builds, updates, and appends at every group boundary."""
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
    d, u_cs = D, U_CS
    base  = [mk(i) for i in range(12)]
    extra = [mk(i) for i in range(100, 107)]
    B     = Commitment(base + extra, D, chunk_size=U_CS, batch_size=U_BS)

    # -- stage 4: cached seal tree -----------------------------------------
    check("stage 4 cache  : cached c == uncached _seal_batch",
          B.c == _seal_batch(B.h_list, B.chunk_size, max(B.x_list), d, B.mod))

    # Synthetic leaf tests at small fan-outs to cross every group boundary.
    # Leaves must be pre-hashed (_seal_hash) just like real batch leaves.
    rng     = _random.Random(11)
    tree_ok = True
    for sbs in (2, 3, 4):
        leaves = [_seal_hash(rng.randrange(1, 2 ** 160))]
        T = _SealTree(leaves, 2, u_cs, d, DEFAULT_MOD, sbs=sbs)
        for _ in range(25):
            nv = _seal_hash(rng.randrange(1, 2 ** 160))
            T.append_leaf(nv)
            leaves.append(nv)
            tree_ok &= T.root == _seal_batch(leaves, u_cs, 2, d, DEFAULT_MOD,
                                             seal_batch_size=sbs)
            i  = rng.randrange(len(leaves))
            nv = _seal_hash(rng.randrange(1, 2 ** 160))
            T.update_leaf(i, nv)
            leaves[i] = nv
            tree_ok &= T.root == _seal_batch(leaves, u_cs, 2, d, DEFAULT_MOD,
                                             seal_batch_size=sbs)
    check("stage 4 cache  : root tracks _seal_batch over appends/updates", tree_ok)

    # Growth must be by extension, not rebuild.  append_leaf used to rebuild the
    # whole tree whenever a new group opened, which made building a tree by
    # append quadratic in the number of leaves; this is the tripwire for that.
    calls = []
    T = _SealTree([_seal_hash(rng.randrange(1, 2 ** 160))], 2, u_cs, d,
                  DEFAULT_MOD, sbs=2)
    real_build = T.build
    T.build = lambda leaves: (calls.append(len(leaves)), real_build(leaves))[1]
    grown = [T.levels[0][0]]
    for _ in range(40):                       # crosses five levels at sbs=2
        nv = _seal_hash(rng.randrange(1, 2 ** 160))
        T.append_leaf(nv)
        grown.append(nv)
    check("stage 4 growth : append never rebuilds the tree", calls == [])
    check("stage 4 growth : root still tracks _seal_batch after 40 appends",
          T.root == _seal_batch(grown, u_cs, 2, d, DEFAULT_MOD,
                                seal_batch_size=2))
    check("stage 4 growth : grown tree matches one built in a single pass",
          T.root == _SealTree(grown, 2, u_cs, d, DEFAULT_MOD, sbs=2).root)

    # Verify _seal_batch fold matches Commitment's stored root after appends.
    C = Commitment([mk(i) for i in range(4)], d, chunk_size=u_cs, batch_size=2)
    C.append(mk(100))
    check("stage 4 cache  : root correct after append into new batch",
          C.c == _seal_batch(C.h_list, C.chunk_size, max(C.x_list), d, C.mod))


if __name__ == "__main__":
    standalone(run, "test_sealtree checks")
