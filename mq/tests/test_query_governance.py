"""QueryGovernor: deployment-level mitigation for the multi-query
correlation risk.  The MQ hardening doesn't change the policy logic —
batch_size, claim-set arithmetic, and ps6_governed are all unchanged.
Unit-level checks run against QueryGovernor directly; the end-to-end
check uses a real Commitment with the new MQ API."""
from harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    QueryGovernor, QueryPolicyViolation, ps6_governed,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    # -- the exact obs:ratio construction: {i1} then {i1, i0} ------------
    gov = QueryGovernor(batch_size=20)          # default min_new_items=3
    gov.authorize({5})
    blocked = False
    try:
        gov.authorize({5, 6})
    except QueryPolicyViolation:
        blocked = True
    check("governance    : literal obs:ratio pair ({i1}, {i1,i0}) blocked",
          blocked)

    gov2 = QueryGovernor(batch_size=20)
    gov2.authorize({5})
    blocked2 = False
    try:
        gov2.authorize({6})
    except QueryPolicyViolation:
        blocked2 = True
    check("governance    : disjoint single-item swap ({5},{6}) blocked "
          "by the default (min_new_items=3, diff 2 < 3)", blocked2)

    gov2b = QueryGovernor(batch_size=20, min_new_items=2)
    gov2b.authorize({5})
    blocked2b = False
    try:
        gov2b.authorize({6})
    except QueryPolicyViolation:
        blocked2b = True
    check("governance    : same swap allowed under explicit min_new_items=2",
          not blocked2b)

    # -- sufficiently different claim sets are allowed --------------------
    gov3 = QueryGovernor(batch_size=20, min_new_items=2)
    gov3.authorize({0, 1, 2})
    allowed = True
    try:
        gov3.authorize({10, 11, 12})
    except QueryPolicyViolation:
        allowed = False
    check("governance    : a sufficiently different claim set is allowed",
          allowed)

    # -- exact repeats are always free ------------------------------------
    gov4 = QueryGovernor(batch_size=20, max_openings_per_batch=1)
    gov4.authorize({3, 4})
    repeat_ok = True
    try:
        gov4.authorize({3, 4})
        gov4.authorize({3, 4})
    except QueryPolicyViolation:
        repeat_ok = False
    check("governance    : exact repeats are always free", repeat_ok)

    new_after_cap_blocked = False
    try:
        gov4.authorize({7, 8})
    except QueryPolicyViolation:
        new_after_cap_blocked = True
    check("governance    : new claim refused once max_openings_per_batch hit",
          new_after_cap_blocked)

    # -- per-batch scoping ------------------------------------------------
    gov5 = QueryGovernor(batch_size=20, min_new_items=2)
    gov5.authorize({5})
    ok_other_batch = True
    try:
        gov5.authorize({5, 6, 25})      # batch 0 diff=1, blocks whole request
    except QueryPolicyViolation:
        ok_other_batch = False
    check("governance    : violation on one batch blocks the whole request",
          not ok_other_batch)
    check("governance    : blocked request records nothing on any batch",
          gov5.history_for_batch(1) == [])

    gov6 = QueryGovernor(batch_size=20, min_new_items=2)
    gov6.authorize({5, 25})
    ok_independent = True
    try:
        gov6.authorize({15, 35})
    except QueryPolicyViolation:
        ok_independent = False
    check("governance    : independent different claims across two batches allowed",
          ok_independent)

    # -- logger callback fires on refusal ---------------------------------
    class _FakeLogger:
        def __init__(self): self.warnings = []
        def warning(self, msg): self.warnings.append(msg)

    logger = _FakeLogger()
    gov7 = QueryGovernor(batch_size=20, logger=logger)
    gov7.authorize({1})
    try:
        gov7.authorize({1, 2})
    except QueryPolicyViolation:
        pass
    check("governance    : logger.warning() called on refusal", len(logger.warnings) == 1)

    # -- end-to-end with MQ commitment ------------------------------------
    base = [mk(i) for i in range(12)]
    C    = Commitment(base, D, chunk_size=U_CS, batch_size=U_BS)
    c_u, h_u, x_u, mq_u, v_u, sys_u, p_u = C.opening()
    real_gov = QueryGovernor(batch_size=U_BS)

    ps_1 = ps6_governed(real_gov, {1}, h_u, mq_u, v_u, sys_u, p_u)
    check("governance    : first real opening (ps6_governed) verifies",
          vs6(c_u, {1: C.vals[1]}, ps_1, x_u, sys_u, p_u))

    e2e_blocked = False
    try:
        ps6_governed(real_gov, {1, 0}, h_u, mq_u, v_u, sys_u, p_u)
    except QueryPolicyViolation:
        e2e_blocked = True
    check("governance    : ps6_governed refuses the obs:ratio follow-up",
          e2e_blocked)

    e2e_ok = True
    try:
        ps6_governed(real_gov, {1, 2, 3, 4, 5}, h_u, mq_u, v_u, sys_u, p_u)
    except QueryPolicyViolation:
        e2e_ok = False
    check("governance    : legitimately different follow-up still served",
          e2e_ok)


if __name__ == "__main__":
    standalone(run, "test_query_governance checks")
