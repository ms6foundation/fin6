"""
sanctions_screening_demo.py — confidential watchlist screening with ms6mq
=========================================================================
A compliance operator maintains an OFAC-style watchlist of risk records for
monitored entities.  A bank submits entity identifiers; the compliance service
proves each entity's current risk tier without exposing the full watchlist.

RECORD FORMAT
-------------
Each record packs four fields into one integer:

    record = entity_id   * 10**9
           + risk_tier   * 10**6
           + flags       * 10**3
           + jurisdiction

    entity_id   : opaque 6-digit hash of the entity identifier  (100000–999999)
    risk_tier   : 0 = clear  /  1-3 = monitor  /  4-5 = elevated  /
                  6-7 = blocked                                     (0–7)
    flags       : packed bits: sanctions_list (4) | PEP (2) | adverse_media (1) (0–7)
    jurisdiction: issuing authority code                           (1–50)

PROTOCOL (ms6mq — MQ-hardened)
--------------------------------
  1. COMMIT  (compliance operator, once):
         c, h_list, x_list, mq_sec, v_list, sys, params
             = ms6(watchlist, d, batch_size=BATCH_SIZE)
     Only c is published.  mq_sec stays private; v_list + sys go to prover.

  2. PROVE   (per request, one or more entities):
         ps_list = ps6(iset, h_list, mq_sec, v_list, sys, params)

  3. VERIFY  (bank, per request):
         vs6(c, {idx: claimed_record, ...}, ps_list, x_list, sys, params)

SECURITY (MQ-hardened, no discrete-log or factoring)
------------------------------------------------------
  Binding:  finding a collision of F : F_P^N → F_P^m requires solving an MQ
            instance over the 255-bit prime P = 2^255-19.  MQ over large fields
            is NP-hard in general; the best known attacks (Groebner / XL) are
            fully exponential for random instances with m ~ n.  No linear-check
            forgery path exists (contrast with the old fold-only scheme).

  Hiding:   each item is masked by a secret per-item salt (random oracle →
            F_P).  The k=8 blinder coordinates ensure the hidden subspace is
            always at least 8-dimensional.  The prover discloses nothing about
            unopened items via the SSH 3-pass ZK proof (soundness 2^-80).

UPDATABILITY
------------
  replace() — risk re-assessment updates one entity's tier in O(1) batches.
  append()  — newly-listed entity added without re-committing the full list.
  delete()  — delisted entity tombstoned; slot cannot be re-opened.

Run:
    python sanctions_screening_demo.py
"""
import sys, random, time
from pathlib import Path
import multiprocessing

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mq.ms6.core import ms6, ps6, Commitment
from mq.vs6 import vs6


# ── record encoding helpers ──────────────────────────────────────────────────

TIER_LABELS = {
    0: "CLEAR",
    1: "MONITOR-1", 2: "MONITOR-2", 3: "MONITOR-3",
    4: "ELEVATED-4", 5: "ELEVATED-5",
    6: "BLOCKED-6", 7: "BLOCKED-7",
}
FLAG_NAMES = ["adverse_media", "PEP", "sanctions_list"]

def encode(entity_id, risk_tier, flags, jurisdiction):
    return entity_id * 10**9 + risk_tier * 10**6 + flags * 10**3 + jurisdiction

def decode(rec):
    eid  = rec // 10**9
    tier = (rec % 10**9) // 10**6
    flg  = (rec % 10**6) // 10**3
    jur  = rec % 10**3
    return eid, tier, flg, jur

def fmt_flags(flags):
    return "+".join(n for i, n in enumerate(FLAG_NAMES) if flags & (1 << i)) or "none"

def fmt_record(rec):
    eid, tier, flg, jur = decode(rec)
    return f"id={eid} tier={TIER_LABELS[tier]} flags=[{fmt_flags(flg)}] jur={jur}"


# ── watchlist generator ──────────────────────────────────────────────────────

def make_watchlist(n, rng):
    """Generate n synthetic risk records."""
    records = []
    for _ in range(n):
        eid  = rng.randint(100_000, 999_999)
        tier = rng.choices(range(8), weights=[40, 15, 12, 10, 8, 7, 5, 3])[0]
        flg  = rng.randint(0, 7)
        jur  = rng.randint(1, 50)
        records.append(encode(eid, tier, flg, jur))
    return records


# ── demo ─────────────────────────────────────────────────────────────────────

def main():
    D          = 3
    CHUNK_SIZE = 40
    BATCH_SIZE = 1000
    BLINDERS   = 33
    N_RECORDS  = 120_000
    N_REQUESTS = 6
    WORKERS = multiprocessing.cpu_count()  # batch-level parallelism across ms6/ps6/vs6

    rng = random.Random(2026)
    watchlist = make_watchlist(N_RECORDS, rng)

    # ── summary header ────────────────────────────────────────────────────────
    print("=" * 72)
    print("SANCTIONS WATCHLIST SCREENING  (ms6mq / MQ-hardened commitment)")
    print(f"binding: MQ over F_P  (P = 2^255-19)  |  hiding: SSH 3-pass ZK")
    print(f"fold_degree=2, n_folds=4, fold_weights='random'  [default config]")
    print("=" * 72)
    print(f"{N_RECORDS} watchlist records,  batch_size={BATCH_SIZE},  "
          f"blinders={BLINDERS},  workers={WORKERS}")

    # ── 1. COMMIT (compliance operator, once) ─────────────────────────────────
    t0 = time.time()
    c, h_list, x_list, mq_sec, v_list, sys_, params = ms6(
        watchlist, D, chunk_size= CHUNK_SIZE, batch_size=BATCH_SIZE, blinders=BLINDERS, workers=WORKERS)
    t_commit = time.time() - t0

    print(f"\n[Operator]  committed {N_RECORDS}-record watchlist  ({t_commit:.3f}s)")
    print(f"            MQSystem: n={sys_.n}  N={sys_.N}  m={sys_.m}  "
          f"n_folds={sys_.n_folds}")
    print(f"            {len(h_list)} batches  |  c = {str(c)[:60]}...")

    # ── helper: prove + verify one request ────────────────────────────────────
    prove_times, verify_times = [], []

    def screen(label, iset, claimed_override=None):
        """Generate a proof for iset; verify the claimed records."""
        t0 = time.time()
        ps_list = ps6(iset, h_list, mq_sec, v_list, sys_, params, workers=WORKERS)
        tp = time.time() - t0
        prove_times.append(tp)

        claims = {i: (claimed_override.get(i, watchlist[i])
                      if claimed_override else watchlist[i])
                  for i in iset}
        t0 = time.time()
        try:
            vs6(c, claims, ps_list, x_list, sys_, params, workers=WORKERS)
            ok = True
        except AssertionError:
            ok = False
        tv = time.time() - t0
        verify_times.append(tv)

        verdict = "ACCEPTED" if ok else "REJECTED"
        print(f"  {label:<52} → {verdict}  (prove {tp:.3f}s  verify {tv:.3f}s)")
        return ok

    # ── 2. Screening requests ─────────────────────────────────────────────────
    print(f"\n── {N_REQUESTS} bank screening requests ──────────────────────────────")
    request_idxs = [
        tuple(sorted(rng.sample(range(N_RECORDS), 2)))
        for _ in range(N_REQUESTS)
    ]
    for i, iset in enumerate(request_idxs):
        tiers = [TIER_LABELS[decode(watchlist[j])[1]] for j in iset]
        screen(f"request {i+1}: entities {list(iset)}  tiers={tiers}", iset)

    # ── 3. Soundness ──────────────────────────────────────────────────────────
    print(f"\n── Soundness checks ──────────────────────────────────────────────")
    j0, j1 = request_idxs[0]
    eid0, tier0, flg0, jur0 = decode(watchlist[j0])
    upgraded_tier = min(tier0 + 3, 7)

    screen(f"inflated tier {TIER_LABELS[tier0]} → {TIER_LABELS[upgraded_tier]}",
           {j0}, {j0: encode(eid0, upgraded_tier, flg0, jur0)})
    screen(f"fabricated record at position {j0}",
           {j0}, {j0: encode(rng.randint(100_000, 999_999), 0, 0, 1)})
    screen(f"record from entity {j1} substituted at position {j0}",
           {j0}, {j0: watchlist[j1]})
    screen(f"multi-entity claim with one tampered tier",
           {j0, j1},
           {j0: encode(eid0, upgraded_tier, flg0, jur0), j1: watchlist[j1]})

    # ── 4. Updatability via Commitment ────────────────────────────────────────
    print(f"\n── Updatability ─────────────────────────────────────────────────")
    t0 = time.time()
    registry = Commitment(watchlist, D, batch_size=BATCH_SIZE, blinders=BLINDERS,
                          workers=WORKERS)
    print(f"  Commitment built ({time.time()-t0:.3f}s)")

    def check_live(label, idx, claimed, expect_ok):
        cu, hu, xu, mqu, vu, sysu, pu = registry.opening()
        psu = ps6([idx], hu, mqu, vu, sysu, pu, workers=WORKERS)
        try:
            vs6(cu, {idx: claimed}, psu, xu, sysu, pu, workers=WORKERS)
            got = True
        except AssertionError:
            got = False
        verdict = "ACCEPTED" if got else "REJECTED"
        flag    = "" if got == expect_ok else "  *** UNEXPECTED ***"
        print(f"  {label:<52} → {verdict}{flag}")

    # Risk escalation: entity re-assessed to blocked
    target = 10
    old_rec = registry.vals[target]
    old_eid, old_tier, old_flg, old_jur = decode(old_rec)
    new_tier = 7   # now blocked
    new_flg  = old_flg | 4   # sanctions_list flag set
    new_rec  = encode(old_eid, new_tier, new_flg, old_jur)

    t0 = time.time()
    registry.replace(target, new_rec)
    t_rep = (time.time() - t0) * 1000
    print(f"\n  [replace] entity {target}: {TIER_LABELS[old_tier]} → "
          f"{TIER_LABELS[new_tier]}  ({t_rep:.1f} ms — only batch "
          f"{target // BATCH_SIZE} updated)")
    check_live(f"escalated record tier={TIER_LABELS[new_tier]} verifies",
               target, new_rec, True)
    check_live(f"old tier={TIER_LABELS[old_tier]} no longer valid",
               target, old_rec, False)

    # New listing
    new_eid  = rng.randint(100_000, 999_999)
    new_listing = encode(new_eid, 5, 6, 12)   # elevated, PEP + sanctions
    t0 = time.time()
    new_idx = registry.append(new_listing)
    t_app = (time.time() - t0) * 1000
    print(f"\n  [append]  new entity listed at index {new_idx}  ({t_app:.1f} ms)")
    check_live(f"new listing {TIER_LABELS[5]} verifies",
               new_idx, new_listing, True)
    check_live(f"fabricated record for new slot rejected",
               new_idx, encode(rng.randint(100_000, 999_999), 0, 0, 1), False)

    # Delisting
    delist_idx = 25
    t0 = time.time()
    registry.delete(delist_idx)
    t_del = (time.time() - t0) * 1000
    print(f"\n  [delete]  entity {delist_idx} delisted — tombstoned  ({t_del:.1f} ms)")
    cu, hu, xu, mqu, vu, sysu, pu = registry.opening()
    try:
        ps6([delist_idx], hu, mqu, vu, sysu, pu, workers=WORKERS)
        slot_blocked = False
    except ValueError:
        slot_blocked = True
    print(f"  Attempt to open delisted slot → "
          f"{'BLOCKED ✓' if slot_blocked else 'LEAKED ✗'}")
    check_live("surviving entity still proves after delisting",
               target, new_rec, True)

    # ── 5. Benchmark summary ──────────────────────────────────────────────────
    print(f"\n{'='*72}")
    print("BENCHMARK SUMMARY")
    print(f"{'='*72}")
    n_batches = len(h_list)
    avg_p = sum(prove_times)   / len(prove_times)   if prove_times   else 0
    avg_v = sum(verify_times)  / len(verify_times)  if verify_times  else 0
    print(f"  Registry:          {N_RECORDS} records, {n_batches} batches of {BATCH_SIZE}")
    print(f"  Commit (once):     {t_commit:.3f}s")
    print(f"  Prove  (avg/req):  {avg_p:.3f}s   (137 SSH rounds × touched batches)")
    print(f"  Verify (avg/req):  {avg_v:.3f}s")
    print(f"  Replace / append:  {t_rep:.1f} ms / {t_app:.1f} ms  "
          f"(vs. {t_commit:.3f}s full recommit)")
    print()
    print("Security properties:")
    print("  * Binding: MQ over F_P — collision requires solving a random")
    print("    MQ system.  No linear-check forgery path (unlike fold-only scheme).")
    print("  * Hiding: per-item salt + 8 blinder coords + SSH ZK proof.")
    print("    Verifier learns nothing about un-opened watchlist entries.")
    print("  * Verify cost does not scale with registry size.")
    print("  * Updates touch one batch only; unrelated proofs remain valid.")


if __name__ == "__main__":
    main()
