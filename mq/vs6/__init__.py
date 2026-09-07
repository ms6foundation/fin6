"""vs6 — verifier side of the MQ-hardened batched commitment.

Public API
----------
vs6(c, claims, ps_list, x_list, sys, params, ...) → True
verify_hidden(...)   → 5-pass SSH          verify_hidden3(...) → 3-pass SSH
verify_mpcith(...)   → MPC-in-the-head

Zero-prover-dependency rule
---------------------------
Nothing in this package imports from ms6.  A party that only ever verifies
proofs can install and audit just this directory, without loading any code
that generates secret salts or produces proofs.  Shared logic (MQSystem,
RestrictedMap, verify_hidden, hash_to_field, seal-tree helpers) is duplicated
verbatim here; examples/selftest.py compares outputs bit-for-bit to enforce
that the copies stay in step.

`expect=` pins incoming params against values agreed out-of-band — params
arrives from the prover and is not self-authenticating.  Always set it when
the prover is not the same process as the caller.
"""
from .core import (
    # ── main verifier API ─────────────────────────────────────────────────
    vs6,

    # ── MQ system (receives the sys object from the prover) ───────────────
    MQSystem,
    RestrictedMap,

    # ── ZK verification ───────────────────────────────────────────────────
    verify_hidden,
    hash_to_field,

    # ── linked commitment (level-algebra relations) ───────────────────────
    LinkedSystem,
    verify_linked,

    # ── parameter helpers ─────────────────────────────────────────────────
    unpack_params,
    PARAM_KEYS,
    ParamMismatch,

    # ── defaults ──────────────────────────────────────────────────────────
    DEFAULT_CHUNK_SIZE,
    DEFAULT_BATCH_SIZE,
    DEFAULT_WORKERS,
    DEFAULT_SEAL_BATCH_SIZE,
    DEFAULT_MOD,
    DEFAULT_BLINDERS,
    DEFAULT_ROUNDS,

    # ── field constants ───────────────────────────────────────────────────
    P,
    FIELD_BYTES,

    # ── seal-tree internals (used by tests / harness) ─────────────────────
    _seal_batch,
    _seal_hash,
    chunk_of,
    chunks,
    _get_batch_ids,

    # ── module-level singleton ────────────────────────────────────────────
    ut,
)
from .ssh3 import verify_hidden3, serialize_proof3, fs_trits
from .mpcith import (verify_mpcith, serialize_proof_mpcith, matvec_transpose,
                     repetitions_for, tree_rebuild)

from . import utils6
from . import ssh3
from . import mpcith

__all__ = [
    # main API
    "vs6",
    # MQ system
    "MQSystem", "RestrictedMap",
    # ZK — one verifier per protocol, none of them able to prove
    "verify_hidden", "hash_to_field",
    "verify_hidden3", "serialize_proof3", "fs_trits",
    "verify_mpcith", "serialize_proof_mpcith", "matvec_transpose",
    "repetitions_for", "tree_rebuild",
    # linked commitment
    "LinkedSystem", "verify_linked",
    # params
    "unpack_params", "PARAM_KEYS", "ParamMismatch",
    # defaults
    "DEFAULT_CHUNK_SIZE", "DEFAULT_BATCH_SIZE", "DEFAULT_WORKERS",
    "DEFAULT_SEAL_BATCH_SIZE", "DEFAULT_MOD", "DEFAULT_BLINDERS",
    "DEFAULT_ROUNDS",
    # constants
    "P", "FIELD_BYTES",
    # seal-tree
    "_seal_batch", "_seal_hash",
    "chunk_of", "chunks", "_get_batch_ids",
    # singletons
    "ut",
    # sub-modules
    "ssh3", "mpcith",
    # sub-modules
    "utils6",
]
