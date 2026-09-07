"""
ms6acc_params -- sizing B, N, m, blinders and folds for ms6acc_mq.

These are ESTIMATES from the standard MQ cryptanalysis literature, not proofs.
They follow the usual recipe: assume the system behaves like a semi-regular
sequence, take the degree of regularity from the Hilbert series, and cost a
Groebner/XL solve as binom(n + d_reg, d_reg)^omega.  Use them to avoid clearly
bad parameters, not as a security guarantee.

--------------------------------------------------------------------------
THE ONE THING THAT MATTERS MOST: DO NOT OVER-DETERMINE THE HIDDEN SYSTEM
--------------------------------------------------------------------------
An opening publishes m field elements and hides h coordinates.  The attacker
therefore faces m equations in h unknowns.  For MQ, EXTRA EQUATIONS MAKE THE
PROBLEM EASIER -- sharply so:

        h = 48:   m = 48 -> ~2^187      m = 56 -> ~2^101      m = 96 -> ~2^61
        h = 64:   m = 64 -> ~2^250      m = 72 -> ~2^138      m = 128 -> ~2^79

and once m >= h(h+1)/2 the system linearises and is solved in polynomial time.
So every extra published row costs security.  In ms6acc_mq the gap is

        m - h = (m_rand + n_folds) - (n - opened)
              = n_folds + opened - 1          when m_rand = n - 1

i.e. it does not shrink as n grows -- it is set by the fold count and by how
many positions an opening reveals.  Keeping n_folds SMALL is worth more than
making n large.  (This also re-frames the earlier advice in this project:
"n_folds ~ n" would have been actively harmful, and 8 folds is already on the
generous side.  2-4 is the better default.)

--------------------------------------------------------------------------
LOW-ENTROPY COORDINATES DO NOT COUNT
--------------------------------------------------------------------------
Bit variables from a range proof, and any committed value with little entropy,
must NOT be counted towards h: an attacker can guess them (hybrid attack) and
solve the smaller remaining system.  ledger_params() below therefore sizes on
the high-entropy block only -- stored values, masks and blinders -- and treats
every range-proof bit as free to the attacker.  This is conservative; the real
cost of guessing na*B bits is high, but assuming it is zero keeps the sizing
honest and cheap to satisfy (blinders are almost free).

--------------------------------------------------------------------------
WHAT B, N, m EACH DO
--------------------------------------------------------------------------
  k  (blinders)    SIZE THIS AGAINST COLLUSION.  If every other account holder
                   pools their openings, the only unknowns left are the
                   blinders, so k alone must reach lambda bits: k ~ 48 for
                   2^128 with 2 folds.  Sizing k against an outsider who knows
                   nothing gives absurdly small answers (a 1000-account ledger
                   "needs" 2 blinders) and is wrong for any multi-holder use.
  B  (range_bits)  Set by the LARGEST VALUE you must represent, not by
                   security: B = ceil(log2(max_value + 1)).  It has no effect
                   on MQ hardness (bits carry no entropy) but dominates proof
                   SIZE, since h grows by na*B.  Choose the smallest B that
                   covers your value range, and in a chosen unit (cents, not
                   micro-units) -- every wasted bit is na field elements of
                   proof per round.
  N  (variables)   N = n_accounts blocks + blinders (+ na*B bits).  Drives
                   proof size linearly and prover time quadratically.
  m  (rows)        m_rand + n_folds (+ range rows).  m_rand >= n-1 is needed
                   so the dense rows carry the hardness; n_folds should be as
                   small as you can live with, for the reason above.
                   Blinders remain the cheapest security in the system:
                   +1 blinder is +1 to h and +0 to m.
"""
from math import comb, log2, ceil

import mq.ms6 as mq

OMEGA = 2                  # linear-algebra exponent; 2 is the optimistic
                           # (attacker-favourable) choice, so estimates are
                           # conservative for the defender


# ---------------------------------------------------------------- core model
def d_reg(n, m, cap=400):
    """Degree of regularity of a semi-regular sequence of m quadratics in n
    variables: index of the first non-positive coefficient of
    (1 - z^2)^m / (1 - z)^n."""
    if n <= 0 or m <= 0:
        return None
    num = [0] * (cap + 1)
    num[0] = 1
    for _ in range(m):                      # multiply by (1 - z^2)
        new = num[:]
        for i in range(cap, 1, -1):
            new[i] -= num[i - 2]
        num = new
    ser = num
    for _ in range(n):                      # divide by (1 - z)^n
        acc, out = 0, []
        for c in ser:
            acc += c
            out.append(acc)
        ser = out
    for d, c in enumerate(ser):
        if c <= 0:
            return d
    return None


def groebner_bits(n, m, omega=OMEGA):
    """log2 cost of a direct Groebner/XL solve of m quadratics in n unknowns."""
    if m >= n * (n + 1) // 2:
        return 0.0                          # linearisation: polynomial time
    d = d_reg(n, m)
    if d is None:
        return float("inf")
    return omega * log2(comb(n + d, d))


def hiding_bits(h, m, field_bits=None, omega=OMEGA):
    """Security of one opening: m published rows, h hidden coordinates.
    Over a large field the hybrid attack (guess some variables, solve the
    rest) is useless -- each guessed variable costs a full field element --
    so this is just the direct solve."""
    return groebner_bits(h, m, omega)


def binding_bits(N, m, omega=OMEGA):
    """Second-preimage: fix x, solve F(x + d) = F(x) for d != 0.  That is m
    quadratics in N unknowns.  Kipnis-Patarin-Goubin solves underdetermined
    systems in polynomial time once N >= m(m+1); Thomae-Wolf gives a milder
    speedup for N > m, which we approximate by charging the solve at the
    reduced equation count m - (N // m) + 1."""
    if m <= 0:
        return 0.0
    if N >= m * (m + 1):
        return 0.0
    if N > m:
        m_eff = max(2, m - (N // m) + 1)
        return groebner_bits(m_eff, m_eff, omega)
    return groebner_bits(N, m, omega)


# ---------------------------------------------------------------- sizing
def analyse(n, n_folds, blinders, opened=2, m_rand=None, range_bits=0,
            n_accounts=0, label=""):
    """Score a concrete configuration.  n is the base (high-entropy) width."""
    m_rand = (n - 1) if m_rand is None else m_rand
    m = m_rand + n_folds
    h = n - opened
    out = {
        "label": label, "n": n, "m": m, "h": h, "gap": m - h,
        "blinders": blinders, "folds": n_folds, "opened": opened,
        "hiding": hiding_bits(h, m),
        "binding": binding_bits(n, m),
    }
    out["security"] = min(out["hiding"], out["binding"])
    if range_bits and n_accounts:
        out["N_total"] = n + n_accounts * range_bits
        out["m_total"] = m + n_accounts * (range_bits + 1)
    return out


def size_for(lam=128, opened=2, n_folds=2, payload=8, max_blinders=1024,
             collusion=True):
    """Smallest blinder count k giving >= lam bits for a payload of `payload`
    high-entropy committed coordinates.

    collusion=True (the default, and the right choice for a ledger): assume
    every OTHER payload coordinate is known to the attacker -- all the other
    account holders pooling their own openings, or a leak.  Then the only
    unknowns left are the blinders and the target's own coordinates, so k must
    carry the security on its own.  This is what stops the estimator from
    concluding that a 1000-account ledger needs 2 blinders because it has
    2000 payload coordinates: those coordinates are exactly what the colluders
    know.

    collusion=False sizes against an outsider who knows nothing, which is only
    appropriate for a single-writer commitment with no other openings."""
    for k in range(2, max_blinders + 1):
        n = payload + k
        full = analyse(n, n_folds, k, opened)
        if collusion:
            # worst case: all payload coordinates but the target's are known
            eff_h = k + max(0, 2 - opened)
            worst = hiding_bits(max(eff_h, 1), full["m"])
            sec = min(worst, full["binding"])
        else:
            sec = full["security"]
        if sec >= lam:
            full["security"] = sec
            full["collusion"] = collusion
            return full
    return None


def ledger_params(n_accounts, max_value, lam=128, n_folds=2, opened=2):
    """Size a ms6acc_finance ledger.

    B comes from the value range; the security sizing counts ONLY the
    high-entropy block (stored + masks + blinders), treating every range-proof
    bit as known to the attacker."""
    B = max(1, ceil(log2(max_value + 1)))
    payload = 2 * n_accounts                       # stored + mask coordinates
    # an opening reveals stored_p and mask_p -> 2 positions
    cfg = size_for(lam, opened=opened, n_folds=n_folds, payload=payload)
    if cfg is None:
        return None
    k = cfg["blinders"]
    base_n = payload + k
    N = base_n + n_accounts * B
    m = cfg["m"] + n_accounts * (B + 1)
    h = N - opened
    # proof size of the batched, seed-compressed 5-pass SSH at `lam` rounds
    fb = mq.FIELD_BYTES
    per_round = 2 * 32 + (h + 1) * fb + 32 + ((1 + 16) + (1 + h * fb)) / 2
    return {"n_accounts": n_accounts, "range_bits": B, "blinders": k,
            "base_n": base_n, "N": N, "m": m, "h": h,
            "m_rand": cfg["n"] - 1, "n_folds": n_folds,
            "security_bits": cfg["security"],
            "proof_kb": (4 + lam * per_round) / 1024}


# ---------------------------------------------------------------- report
if __name__ == "__main__":
    print("=" * 78)
    print("1. EXTRA PUBLISHED ROWS ARE EXPENSIVE  (m equations, h unknowns)")
    print("=" * 78)
    print(f"{'h':>4} | " + "".join(f"m=h+{g:<3}" .rjust(9) for g in (0, 2, 4, 8, 16, 32)))
    for h in (24, 32, 40, 48, 64, 80):
        cells = []
        for g in (0, 2, 4, 8, 16, 32):
            b = hiding_bits(h, h + g)
            cells.append((f"{b:.0f}" if b else "poly").rjust(9))
        print(f"{h:>4} | " + "".join(cells))
    print("\n  m - h = n_folds + opened - 1  (with m_rand = n-1), so the gap is fixed")
    print("  by the fold count, not by n.  Fewer folds is worth more than bigger n.")

    print("\n" + "=" * 78)
    print("2. CURRENT DEFAULTS  (DEFAULT_FOLDS = %d, opening 2 positions)" % mq.DEFAULT_FOLDS)
    print("=" * 78)
    print(f"{'config':>28} {'n':>4} {'m':>4} {'h':>4} {'gap':>4} {'hiding':>7} {'binding':>8} {'verdict':>9}")
    for n, folds, k in [(16, 8, 8), (24, 8, 8), (48, 8, 40), (64, 8, 40), (96, 8, 40)]:
        r = analyse(n, folds, k)
        v = "OK" if r["security"] >= 128 else ("weak" if r["security"] >= 100 else "TOO LOW")
        print(f"{f'n={n} folds={folds} k={k}':>28} {r['n']:>4} {r['m']:>4} {r['h']:>4} "
              f"{r['gap']:>4} {r['hiding']:>7.0f} {r['binding']:>8.0f} {v:>9}")
    print("\n  The demo defaults (n=16, folds=8) are ~2^30 -- fine for a demo, not for use.")

    print("\n" + "=" * 78)
    print("3. RECOMMENDED SIZING  (blinders are the cheap lever: +1 to h, +0 to m)")
    print("=" * 78)
    print("  (sized against collusion: k alone must carry lambda bits)")
    print(f"{'lambda':>7} {'folds':>6} {'payload':>8} {'blinders':>9} {'n':>4} {'m':>4} {'h':>4} {'bits':>6}")
    for lam in (128, 192, 256):
        for folds in (2, 4, 8):
            r = size_for(lam, n_folds=folds, payload=8)
            if r:
                print(f"{lam:>7} {folds:>6} {8:>8} {r['blinders']:>9} {r['n']:>4} {r['m']:>4} "
                      f"{r['h']:>4} {r['security']:>6.0f}")
    print("\n  Reading: at lambda=128 with 2 folds you need ~%d blinders; with 8 folds"
          % size_for(128, n_folds=2, payload=8)["blinders"])
    print("  you need %d.  Folds are a supplement -- buy them with a real budget."
          % size_for(128, n_folds=8, payload=8)["blinders"])

    print("\n" + "=" * 78)
    print("4. LEDGER SIZING  (ms6acc_finance; bits counted as ZERO entropy)")
    print("=" * 78)
    print(f"{'accounts':>9} {'max value':>14} {'B':>3} {'k':>4} {'N':>5} {'m':>5} {'h':>5} "
          f"{'bits':>6} {'proof':>9}")
    for na, mx, desc in [(8, 10 ** 6, "$10k in cents"),
                         (8, 10 ** 11, "$1B in cents"),
                         (64, 10 ** 11, "$1B in cents"),
                         (1000, 10 ** 11, "$1B in cents")]:
        p = ledger_params(na, mx)
        if p is None:
            print(f"{na:>9} {mx:>14,}   -- no configuration within max_blinders")
            continue
        sec = p["security_bits"]
        secs = "inf" if sec == float("inf") else f"{sec:.0f}"
        print(f"{na:>9} {mx:>14,} {p['range_bits']:>3} {p['blinders']:>4} {p['N']:>5} "
              f"{p['m']:>5} {p['h']:>5} {secs:>6} {p['proof_kb']:>7.0f}KB")
    print("\n  B is set by the value range alone.  Choosing cents over micro-units,")
    print("  or capping per-account balances, is the cheapest way to shrink proofs.")

    print("\n" + "=" * 78)
    print("5. VALIDATION AGAINST THE CODE")
    print("=" * 78)
    from mq.ms6 import MQSystem, RestrictedMap, _rand_vec
    for n, folds in [(24, 2), (32, 4)]:
        S = MQSystem(n, n_folds=folds)
        x = _rand_vec(n)
        X = S.lift(x)
        R = RestrictedMap(S, {0: X[0], 3: X[3]})
        pred = analyse(n, folds, 0)
        assert S.m == pred["m"], (S.m, pred["m"])
        assert R.h == pred["h"], (R.h, pred["h"])
        print(f"  MQSystem(n={n}, n_folds={folds}): m={S.m} h={R.h} -- matches the model "
              f"(gap {S.m - R.h}, ~2^{pred['security']:.0f})")
    print("\nall checks passed")