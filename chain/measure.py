"""What this build costs, measured rather than remembered.

    python3 -m chain.measure                 # writes docs/measurements.md
    python3 -m chain.measure --quick         # the cheap probes only
    python3 -m chain.measure --print         # to stdout, write nothing

Class D's one recurring item was that **nothing measures any of this**, and the
reason that matters is not tidiness.  This repository's own history is that
measurement corrects documentation: a preset two revisions behind its own
source, a certificate that was 56.2 KB and not 54.7, a three-backend submission
of 3.27 MB against a 1 MB ceiling nobody had related to it, a rate limit priced
for a proof twelve times cheaper than the one it buys.  None of those were
careless.  They happened because **a number written in prose has nowhere to
fail**.  This module is somewhere for them to fail.

## What is and is not asserted

The output is a *record*, not a threshold.  Absolute timings are a claim about
one machine, so a test that compares them across machines is a coin flip
wearing a lab coat, and the honest thing is to say so rather than invent a
tolerance.  What travels between machines is **shape** — flat is flat anywhere,
and a cost that scales with an attacker's state scales everywhere — so the
shape claims are asserted in `chain/tests/test_measure.py` and the numbers are
committed here for a human to read and compare.

Every timing is a **best of n**.  The minimum is the least noisy estimate of
what the work costs; a mean measures the machine's other tenants.
"""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import time

DOC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "measurements.md")


def best_of(fn, n: int) -> float:
    """Milliseconds for one call, best of n."""
    best = None
    for i in range(n):
        started = time.perf_counter()
        fn(i)
        taken = (time.perf_counter() - started) * 1000.0
        best = taken if best is None else min(best, taken)
    return best


# ═══════════════════════════════════════════════════════════════════════════════
# The probes
# ═══════════════════════════════════════════════════════════════════════════════

def probe_penalty_box(sizes=(16, 1024, 4096)) -> list:
    """One violation, against a box of each size.

    `Gate.penalise` is on the attacker's path — it is what a malformed frame
    causes — so anything here that scales with the size of the box is a defence
    whose cost the attacker sets.  It used to sort the whole box: 2.9 us empty,
    288.5 us full.
    """
    from .net.gate import Gate

    out = []
    for size in sizes:
        gate = Gate(penalty_seconds=3600.0, max_penalised=size)
        for i in range(size):
            gate.penalise(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", now=0.0)
        out.append((size, best_of(lambda i: gate.penalise(f"x{i}", now=0.0), 400)))
    return out


def probe_limiter(sizes=(16, 1024, 4096)) -> list:
    """A frame from an address the node has not seen, against each table size.

    The same shape as the penalty box and cheaper for an attacker to reach: it
    costs no disconnect, only an address it has not used yet.
    """
    from .net.limits import Limiter

    out = []
    for size in sizes:
        lim = Limiter(idle_after=1e9, max_sources=size + 1)
        for i in range(size):
            lim.check(f"src-{i}", "status", now=0.0)
        out.append((size, best_of(
            lambda i: lim.check(f"new-{i}", "status", now=0.0), 400)))
    return out


def probe_append(sizes=(1_000, 20_000, 100_000), window: int = 400) -> list:
    """The marginal cost of one append to the UTXO accumulator.

    Part four's open item: ~1.4 ms flat, an interpreter ceiling rather than an
    algorithmic one, capping a node near 125 tx/s at ten million notes.

    A **mean over a window**, not a best-of, and the difference is the point.
    The defect part four fixed was a *periodic* one — the tree was rebuilt
    whenever a new `sbs` group opened — and the minimum is exactly the
    estimator that cannot see a cost paid every thousandth call.  The window is
    wider than a group for the same reason.
    """
    from .seal import SealAccumulator

    out = []
    for size in sizes:
        acc = SealAccumulator("utxo")
        for i in range(size):
            acc.add(f"cm:{i:064x}")
        started = time.perf_counter()
        for i in range(window):
            acc.add(f"cm:{size + i:064x}")
        out.append((size, (time.perf_counter() - started) * 1000.0 / window))
    return out


def probe_proof(presets=("demo", "launch")) -> list:
    """Prove, verify, and the bytes, for one transaction per preset.

    The number the rate limit is priced against (`limits.PRICED_AT_MS`) and the
    number the queue depth is derived from, both in one place — so a preset
    change that moves them is visible here rather than in a stall.
    """
    from .network import bootstrap, transfer
    from .params import PRESETS
    from .store import codec
    from .transaction import verify_transaction

    out = []
    for name in presets:
        params = PRESETS[name]
        _, holders, _ = bootstrap(["v00"], {"alice": [1000], "bob": [250]},
                                  params)
        prove = best_of(
            lambda i: transfer(holders["alice"], holders["bob"], 10 + i, 1,
                               params), 3)
        tx, _ = transfer(holders["alice"], holders["bob"], 7, 1, params)
        backend = params.default_backend
        verify = best_of(
            lambda i: verify_transaction(tx, params, backend=backend), 3)
        out.append((name, backend, prove, verify, len(codec.encode(tx)) / 1024.0))
    return out


def probe_derived(units) -> list:
    """What the node does with those numbers, for each measured unit cost.

    Two constants stopped being constants in part thirteen: the work queue's
    depth and the price of a submission.  Both were sized against a 25.4 ms
    verification and neither could notice that `LAUNCH` made one 0.31 s.  This
    row is the check that the derivation is live — the depth should fall and
    the price should rise as the measured unit grows.
    """
    from .net.budget import EpochBudget, Meter
    from .net.clock import Clock
    from .net.limits import Limiter

    out = []
    clock = Clock(effective_ms=0, epoch_millis=19_749)
    for unit_ms in units:
        budget = EpochBudget(clock, meter=Meter(unit_ms, alpha=0.0)).open(1)
        lim = Limiter()
        lim.observe_unit(unit_ms)
        out.append((unit_ms, budget.servable(), lim.cost_of("tx"),
                    lim.floor_capacity()))
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# The record
# ═══════════════════════════════════════════════════════════════════════════════

def machine() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                                capture_output=True, text=True,
                                timeout=5).stdout.strip()
    except Exception:
        commit = ""
    return {"python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "commit": commit or "unknown",
            "when": time.strftime("%Y-%m-%d")}


def render(quick: bool = False) -> str:
    started = time.time()
    where = machine()
    lines = [
        "# What this build costs",
        "",
        "*Generated by `python3 -m chain.measure`. Do not edit by hand.*",
        "",
        "A record, not a threshold. Absolute timings are a claim about one",
        "machine; what travels is the **shape**, and the shape claims are",
        "asserted in `chain/tests/test_measure.py`. Part thirteen, class D.",
        "",
        f"| | |", "|---|---|",
        f"| measured | {where['when']} at `{where['commit']}` |",
        f"| python | {where['python']} |",
        f"| platform | {where['platform']} ({where['machine']}) |",
        f"| scope | {'quick probes only' if quick else 'everything'} |",
        "SCOPE_ROW",
        "",
        "## The two hot paths an attacker controls",
        "",
        "Both must be **flat**: a cost that grows with the state an attacker",
        "can grow is a defence whose price the attacker sets.",
        "",
        "| remembered offenders | one `Gate.penalise()` |",
        "|---|---|",
    ]
    box = probe_penalty_box()
    for size, ms in box:
        lines.append(f"| {size:,} | {ms * 1000:.1f} µs |")
    lines += ["", "| known sources | one frame from a new address |", "|---|---|"]
    for size, ms in probe_limiter():
        lines.append(f"| {size:,} | {ms * 1000:.1f} µs |")

    lines += ["", "## The append ceiling", "",
              "Flat is the claim. A term that grows with the tree is the",
              "quadratic append coming back — see part four.", "",
              "| notes already in the tree | marginal append |", "|---|---|"]
    for size, ms in probe_append((1_000, 5_000) if quick else
                                 (1_000, 20_000, 100_000)):
        lines.append(f"| {size:,} | {ms:.2f} ms |")

    if not quick:
        lines += ["", "## A transaction, per preset", "",
                  "| preset | backend | prove | verify | encoded |",
                  "|---|---|---|---|---|"]
        for name, backend, prove, verify, kb in probe_proof():
            lines.append(f"| `{name}` | {backend} | {prove:,.0f} ms | "
                         f"{verify:,.0f} ms | {kb:,.0f} KB |")

    lines += ["", "## What the node derives from those numbers", "",
              "The depth falls and the price rises as a unit of work gets",
              "dearer. Both used to be written down, and neither could notice",
              "that `LAUNCH` made a verification twelve times slower.", "",
              "| measured unit | queue depth | `tx` price | client burst |",
              "|---|---|---|---|"]
    for unit, depth, price, burst in probe_derived((25.4, 100.0, 310.0, 900.0)):
        lines.append(f"| {unit:,.1f} ms | {depth} | {price:,.0f} tokens | "
                     f"{burst:,.0f} tokens |")
    lines.append("")
    took = time.time() - started
    return "\n".join(lines).replace(
        "SCOPE_ROW", f"| this run took | {took:,.0f} s |")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--quick", action="store_true",
                    help="skip the probes that prove transactions")
    ap.add_argument("--print", dest="to_stdout", action="store_true",
                    help="write nothing, print the record")
    ap.add_argument("--out", default=DOC)
    args = ap.parse_args(argv)

    started = time.time()
    text = render(quick=args.quick)
    if args.to_stdout:
        print(text)
        return 0
    with open(args.out, "w") as fh:
        fh.write(text + "\n")
    print(f"wrote {args.out} in {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":                                   # pragma: no cover
    sys.exit(main())
