"""ms6 — commit / prove side of the MQ-hardened batched commitment.

Public API
----------
ms6(vals, d, ...)        → (c, h_list, x_list, mq_sec, v_list, sys, params)
prove_hidden(...)        → gamma-batched 5-pass SSH proof
prove_hidden3(...)       → gamma-batched 3-pass SSH proof      (ssh3.py)
prove_mpcith(...)        → MPC-in-the-head proof               (mpcith.py)
ps6(iset, h_list, ...)   → ps_list
Commitment(vals, d, ...) → updatable commitment object

Zero-prover-dependency rule
---------------------------
Nothing in this package imports from vs6.  The verifier (vs6 package) can
be installed, audited, and deployed completely independently of ms6.
Shared logic (MQSystem, RestrictedMap, verify_hidden, hash_to_field, seal-tree
helpers) is duplicated verbatim in vs6; a bit-for-bit regression test across
the two copies is the recommended enforcement.
"""
from .core import (
    # ── main prover / committer API ──────────────────────────────────────
    ms6,
    ps6,
    Commitment,

    # ── MQ system (public; passed from prover to verifier) ───────────────
    MQSystem,
    RestrictedMap,

    # ── ZK identification protocol ───────────────────────────────────────
    prove_hidden,
    verify_hidden,
    hash_to_field,
    serialize_proof,
    DirectBatched,

    # ── parameter helpers ────────────────────────────────────────────────
    make_params,
    unpack_params,
    PARAM_KEYS,
    ParamMismatch,

    # ── query governance ─────────────────────────────────────────────────
    QueryGovernor,
    QueryPolicyViolation,
    ps6_governed,

    # ── linked commitment (level-algebra relations) ───────────────────────
    LinkedSystem,
    commit_linked,
    open_linked,
    verify_linked,

    # ── defaults ─────────────────────────────────────────────────────────
    DEFAULT_CHUNK_SIZE,
    DEFAULT_BATCH_SIZE,
    DEFAULT_WORKERS,
    DEFAULT_SEAL_BATCH_SIZE,
    DEFAULT_MOD,
    DEFAULT_BLINDERS,
    DEFAULT_ROUNDS,
    DEFAULT_FOLDS,

    # ── field constants ───────────────────────────────────────────────────
    P,
    FIELD_BYTES,

    # ── geometric-fold attack helper (educational) ────────────────────────
    peel_geometric_folds,
    GEOMETRIC_CAP_DIVISOR,

    # ── seal-tree internals (used by tests / harness) ─────────────────────
    _seal_batch,
    _SealTree,
    _seal_hash,
    chunk_of,
    chunks,
    _permute_row,
    _get_batch_ids,

    # ── module-level singletons ───────────────────────────────────────────
    ut,
    gen,
)
from .ssh3 import (prove_hidden3, verify_hidden3, serialize_proof3,
                   fs_trits, DEFAULT_ROUNDS_3PASS)
from .mpcith import (prove_mpcith, verify_mpcith, serialize_proof_mpcith,
                     sacrifice_check_in_the_clear, matvec_transpose,
                     repetitions_for, tree_leaves, tree_path, tree_rebuild,
                     DEFAULT_PARTIES)

from . import utils6
from . import pow6
from . import ssh3
from . import mpcith

__all__ = [
    # main API
    "ms6", "ps6", "Commitment",
    # MQ system
    "MQSystem", "RestrictedMap",
    # ZK — 5-pass (core), 3-pass (ssh3), MPC-in-the-head (mpcith)
    "prove_hidden", "verify_hidden", "hash_to_field",
    "serialize_proof", "DirectBatched",
    "prove_hidden3", "verify_hidden3", "serialize_proof3", "fs_trits",
    "DEFAULT_ROUNDS_3PASS",
    "prove_mpcith", "verify_mpcith", "serialize_proof_mpcith",
    "sacrifice_check_in_the_clear", "matvec_transpose", "repetitions_for",
    "tree_leaves", "tree_path", "tree_rebuild", "DEFAULT_PARTIES",
    # params
    "make_params", "unpack_params", "PARAM_KEYS", "ParamMismatch",
    # governance
    "QueryGovernor", "QueryPolicyViolation", "ps6_governed",
    # linked commitment
    "LinkedSystem", "commit_linked", "open_linked", "verify_linked",
    # defaults
    "DEFAULT_CHUNK_SIZE", "DEFAULT_BATCH_SIZE", "DEFAULT_WORKERS",
    "DEFAULT_SEAL_BATCH_SIZE", "DEFAULT_MOD", "DEFAULT_BLINDERS",
    "DEFAULT_ROUNDS", "DEFAULT_FOLDS",
    # constants
    "P", "FIELD_BYTES",
    # attack / educational
    "peel_geometric_folds", "GEOMETRIC_CAP_DIVISOR",
    # seal-tree
    "_seal_batch", "_SealTree", "_seal_hash",
    "chunk_of", "chunks",
    "_permute_row", "_get_batch_ids",
    # singletons
    "ut", "gen",
    # sub-modules
    "utils6", "pow6", "ssh3", "mpcith",
]
