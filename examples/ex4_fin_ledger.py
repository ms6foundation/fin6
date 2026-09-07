"""
ex4_fin_ledger.py -- confidential ledger using the ms6mqfin LedgerSystem.

Demonstrates the full stack:

  1. Parameter sizing via ms6acc_params.size_for() / ledger_params()
  2. Commit a ledger with range proofs (LedgerSystem)
  3. Proof of reserves: verify the committed total
  4. Range proof: every balance provably in [0, 2^B)
  5. Selective disclosure: one account proves its balance
  6. Tamper resistance: forged balance, wrong mask, root mismatch all rejected
  7. Multi-account audit
  8. Security / proof-size table across deployment scales

Run:
    cd ms6mqfin && python examples/ex4_fin_ledger.py
"""
import sys
import time
import copy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ledger_system import (LedgerSystem, commit_ledger, open_account,
                      verify_account, verify_total, verify_range, serialize_proof)
from utils import size_for, ledger_params
from mq.ms6 import P


def section(n, title):
    print(f"\n{'─'*62}")
    print(f"  {n}. {title}")
    print(f"{'─'*62}")


# ── scenario ─────────────────────────────────────────────────────────────────
N_ACCOUNTS = 8
MAX_VALUE  = 10_000_000 * 100   # $10 M in cents  (~30 bits)
LAMBDA     = 128
N_FOLDS    = 2

BALANCES = [
    125_000_00,    # $125,000
    430_00,        # $430
    9_812_500_00,  # $9,812,500
    600_000_00,    # $600,000
    1_200,         # $12
    777_777_00,    # $777,777
    250_000_00,    # $250,000
    334_000_00,    # $334,000
]
assert len(BALANCES) == N_ACCOUNTS

# ── 1. parameter sizing ───────────────────────────────────────────────────────
section(1, "Parameter sizing")

cfg = ledger_params(N_ACCOUNTS, MAX_VALUE, lam=LAMBDA, n_folds=N_FOLDS)
if cfg is None:
    raise SystemExit("no valid config")

B = cfg["range_bits"]
K = cfg["blinders"]
print(f"  accounts      : {N_ACCOUNTS}")
print(f"  range_bits B  : {B}  (balances in [0, {2**B:,}))")
print(f"  blinders k    : {K}  (collusion-case {LAMBDA}-bit security)")
print(f"  n (base)      : {cfg['base_n']}")
print(f"  N (total)     : {cfg['N']}  (= n + na·B)")
print(f"  m (rows)      : {cfg['m']}")
print(f"  security      : {cfg['security_bits']:.0f} bits")
print(f"  proof/account : ~{cfg['proof_kb']:.0f} KB  (at {LAMBDA} rounds)")

# ── 2. commit ─────────────────────────────────────────────────────────────────
section(2, "Commit ledger")

assert all(b < 2**B for b in BALANCES)

t0 = time.time()
public, secret, ledger = commit_ledger(
    BALANCES, blinders=K, range_bits=B, n_folds=N_FOLDS, m_rand=cfg["m_rand"], d=8)
tc = time.time() - t0

print(f"  committed {N_ACCOUNTS} accounts in {tc:.2f}s")
print(f"  LedgerSystem: n={ledger.n}  N={ledger.N}  m={ledger.m}")
print(f"    m_rand={ledger.m_rand}  n_folds={ledger.n_folds}  range_bits={ledger.range_bits}")
print(f"    sum_row={ledger.sum_row}  range_rows={ledger.range_rows[:3]}…  "
      f"bit_rows={ledger.bit_rows[:3]}…")
print(f"  root c = {public['c']}")
print(f"  total  = ${public['total']/100:,.2f}")

# ── 3. proof of reserves ──────────────────────────────────────────────────────
section(3, "Proof of reserves (verify_total)")

verify_total(ledger, public)
print(f"  ✓  v[sum_row] = {public['v'][ledger.sum_row]}  == total % P")

forged = copy.copy(public)
forged["total"] = public["total"] + 10_000_00
try:
    verify_total(ledger, forged)
    raise SystemExit("FAIL: inflated total accepted")
except AssertionError:
    print("  ✓  inflated total by $10,000 → rejected")

# ── 4. range proof ────────────────────────────────────────────────────────────
section(4, "Range proof (verify_range)")

verify_range(ledger, public)
print(f"  ✓  all {N_ACCOUNTS} recomp rows = 0  ({N_ACCOUNTS}·{B} bit-constraint rows = 0)")
print(f"  ✓  every balance provably in [0, 2^{B} = {2**B:,})")

# ── 5. selective disclosure ───────────────────────────────────────────────────
section(5, "Selective disclosure — account 2")

ACCOUNT = 2
t0 = time.time()
stmt = open_account(ledger, public, secret, account=ACCOUNT)
tp = time.time() - t0

t0 = time.time()
verify_account(ledger, public, stmt)
tv = time.time() - t0

proof_kb = len(serialize_proof(stmt["proof"])) / 1024
print(f"  account {ACCOUNT}: balance = ${stmt['balance']/100:,.2f}")
print(f"  prove {tp:.2f}s   verify {tv:.2f}s   proof {proof_kb:.0f} KB")
print(f"  hidden: {N_ACCOUNTS-1} other accounts + {K} blinders + {N_ACCOUNTS}·{B} bit vars")
print(f"  ✓  verify_account passed")

# ── 6. tamper resistance ──────────────────────────────────────────────────────
section(6, "Tamper resistance")

# 6a. inflated balance
bad = dict(stmt); bad["balance"] = stmt["balance"] + 1_00
try:
    verify_account(ledger, public, bad)
    raise SystemExit("FAIL: inflated balance accepted")
except AssertionError:
    print("  ✓  inflated balance → rejected")

# 6b. wrong mask (off by 1, so stored-mask ≠ balance)
bad = dict(stmt); bad["mask"] = (stmt["mask"] + 1) % P
try:
    verify_account(ledger, public, bad)
    raise SystemExit("FAIL: wrong mask accepted")
except AssertionError:
    print("  ✓  wrong mask → rejected (stored-mask ≠ balance)")

# 6c. proof replayed against wrong account
bad = dict(stmt); bad["account"] = (ACCOUNT + 1) % N_ACCOUNTS
try:
    verify_account(ledger, public, bad)
    raise SystemExit("FAIL: replayed proof accepted")
except AssertionError:
    print("  ✓  proof replayed against wrong account → rejected")

# 6d. tampered root
bad_pub = dict(public); bad_pub["c"] = public["c"] + 1
try:
    verify_account(ledger, bad_pub, stmt)
    raise SystemExit("FAIL: tampered root accepted")
except AssertionError:
    print("  ✓  tampered seal-tree root → rejected")

# ── 7. multi-account audit ────────────────────────────────────────────────────
section(7, "Multi-account audit (all accounts, 20 rounds)")

t0 = time.time()
stmts = [open_account(ledger, public, secret, a, rounds=20)
         for a in range(N_ACCOUNTS)]
t_open = time.time() - t0

t0 = time.time()
for s in stmts:
    verify_account(ledger, public, s)
t_verify = time.time() - t0

total_kb = sum(len(serialize_proof(s["proof"])) for s in stmts) / 1024
print(f"  open  {N_ACCOUNTS} accounts in {t_open:.1f}s")
print(f"  verify {N_ACCOUNTS} accounts in {t_verify:.1f}s")
print(f"  total proof payload: {total_kb:.0f} KB")
assert sum(s["balance"] for s in stmts) == public["total"]
print(f"  ✓  balances sum to published total ${public['total']/100:,.2f}")

# ── 8. sizing table ───────────────────────────────────────────────────────────
section(8, "Parameter sizing across deployment scales (λ=128, 2 folds)")

print(f"  {'accounts':>9} {'max_value':>14} {'B':>3} {'k':>5} {'n':>5} "
      f"{'N':>6} {'m':>6} {'sec':>6} {'proof/acct':>11}")
cases = [
    (8,    10**9,   "$10M cents"),
    (8,    10**11,  "$1B  cents"),
    (64,   10**11,  "$1B  cents"),
    (500,  10**11,  "$1B  cents"),
    (1000, 10**11,  "$1B  cents"),
]
for na, mx, _ in cases:
    p = ledger_params(na, mx, lam=128, n_folds=2)
    if p is None:
        print(f"  {na:>9} {mx:>14,}   -- no config")
        continue
    sec = p["security_bits"]
    ss = "inf" if sec == float("inf") else f"{sec:.0f}"
    print(f"  {na:>9} {mx:>14,} {p['range_bits']:>3} {p['blinders']:>5} "
          f"{p['base_n']:>5} {p['N']:>6} {p['m']:>6} {ss:>6} "
          f"{p['proof_kb']:>9.0f} KB")

print(f"\n  B from value range; k sized for collusion-case security.")
print(f"  N = n + na·B; range proof rows dominate for many accounts.")
print()
print("all checks passed")
