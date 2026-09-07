"""Shared fixtures and the pass/fail reporter for the test modules.

Imports reach past the public API on purpose: several checks are about
internals (the seal tree, the deliberately duplicated helpers), not just
observable behaviour.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vs6 as vs6pkg                                              # noqa: E402
from ms6 import core as M                                         # noqa: E402
from ms6 import utils6 as u                                       # noqa: E402
from vs6 import core as V                                         # noqa: E402
from vs6 import vs6, ParamMismatch, PARAM_KEYS as VS6_PARAM_KEYS  # noqa: E402

ms6, ps6, Commitment = M.ms6, M.ps6, M.Commitment
QueryGovernor, QueryPolicyViolation, ps6_governed = (
    M.QueryGovernor, M.QueryPolicyViolation, M.ps6_governed)
make_params, unpack_params, PARAM_KEYS = M.make_params, M.unpack_params, M.PARAM_KEYS
_seal_batch, _SealTree, _seal_hash = M._seal_batch, M._SealTree, M._seal_hash
chunk_of, chunks = M.chunk_of, M.chunks
_permute_row, _get_batch_ids = M._permute_row, M._get_batch_ids
DEFAULT_MOD, ut, gen = M.DEFAULT_MOD, M.ut, M.gen

# Parameters the check bodies share.  Small on purpose: these assert
# equivalences, not throughput, and every one of them runs a real
# commit/open/verify.
D = 3
U_CS, U_BS = 20, 5


def mk(i):
    """Deterministic sample value."""
    return (1720941241 + (i ** 7) ^ (i ** 5)) % 2 ** 120


class Checker:
    """Collects results so one run reports every failure, not just the first."""

    def __init__(self):
        self.failures = []

    def __call__(self, label, ok):
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        if not ok:
            self.failures.append(label)
        return ok

    def report(self, title="checks"):
        if self.failures:
            print(f"\n{len(self.failures)} {title} FAILED:")
            for f in self.failures:
                print(f"  - {f}")
            return 1
        print(f"\nall {title} passed")
        return 0


def proves(C, idxs):
    """A claim over a commitment, through the unmodified ps6/vs6 path --
    Commitment.opening() returns ms6()'s own tuple, params included."""
    c_u, h_u, x_u, mq_sec_u, v_u, sys_u, p_u = C.opening()
    cl   = {i: C.vals[i] for i in idxs}
    ps_u = ps6(cl.keys(), h_u, mq_sec_u, v_u, sys_u, p_u)
    return vs6(c_u, cl, ps_u, x_u, sys_u, p_u)


def proves_with_expect(C, idxs, expect):
    c_u, h_u, x_u, mq_sec_u, v_u, sys_u, p_u = C.opening()
    cl   = {i: C.vals[i] for i in idxs}
    ps_u = ps6(cl.keys(), h_u, mq_sec_u, v_u, sys_u, p_u)
    return vs6(c_u, cl, ps_u, x_u, sys_u, p_u, expect=expect)


def rebuilt(C, vals_now):
    """The same data committed from scratch under C's own system params."""
    return Commitment(vals_now, D, chunk_size=U_CS, batch_size=U_BS,
                      sys=C.sys)


def standalone(run, title):
    """Entry point for running one test module on its own."""
    check = Checker()
    run(check)
    raise SystemExit(check.report(title))
