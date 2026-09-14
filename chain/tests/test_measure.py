"""The shape of what this build costs.  Review class D, part thirteen.

`chain/measure.py` records numbers; this asserts the claims those numbers are
supposed to satisfy.  The split matters and is the answer to the sketch's own
open item — *what does "a material move" mean in a regression check?*

An absolute timing is a claim about the machine the suite happens to be running
on, so comparing one against a committed figure is a coin flip with a lab coat
on.  What survives a change of machine is **shape**:

  * flat is flat anywhere;
  * a cost that scales with state an attacker can grow scales everywhere;
  * and a derived number moves in the direction its derivation says.

So the timings live in `docs/measurements.md` for a human, and the shapes live
here, where a change that reintroduces a scan fails the suite on any machine.
"""
import os

from chain import measure
from chain.net.budget import QUEUE_CAPACITY, QUEUE_FLOOR
from chain.net.limits import COSTS, MAX_PRICE_MULTIPLE, PRICED_AT_MS

#: Generous on purpose. The claim under test is "flat", and the failure it has
#: to catch is a scan — which is a factor of a hundred, not of four. A tighter
#: bound would measure the machine's other tenants.
FLAT = 8.0


def _flat(rows, what):
    """`rows` is [(size, ms)], smallest first."""
    small, large = rows[0][1], rows[-1][1]
    assert large < small * FLAT, (
        f"{what}: {large * 1000:.1f} us at {rows[-1][0]:,} against "
        f"{small * 1000:.1f} us at {rows[0][0]:,} — this is being scanned")


# ── the two hot paths an attacker controls ───────────────────────────────────

def test_remembering_offenders_is_flat_in_how_many_are_remembered():
    _flat(measure.probe_penalty_box((16, 512, 4096)), "the penalty box")


def test_admitting_a_new_source_is_flat_in_how_many_are_known():
    _flat(measure.probe_limiter((16, 512, 4096)), "the limiter's source table")


# ── the append ceiling ───────────────────────────────────────────────────────

def test_the_append_cost_is_flat_in_the_size_of_the_tree():
    """Part four fixed a quadratic term here, and this is the watch for it.

    What it catches and what it does not, stated rather than implied: a gross
    regression — a rebuild on *every* append — shows up at any size and this
    will fail on it.  The term part four actually removed was
    `N x 4.1 us / 1000`, which crosses the flat cost at about 340,000 notes and
    is a few percent at the sizes a test suite can afford.  Catching *that*
    again is what the 100,000-note row in `docs/measurements.md` is for: a
    human comparing two runs, not an assertion.
    """
    rows = measure.probe_append((1_000, 5_000), window=400)
    assert rows[-1][1] < rows[0][1] * 3.0, rows


# ── the numbers the node derives ─────────────────────────────────────────────

def test_a_dearer_unit_of_work_shrinks_the_queue_and_raises_the_price():
    rows = measure.probe_derived((25.4, 100.0, 310.0, 900.0))
    depths = [r[1] for r in rows]
    prices = [r[2] for r in rows]
    bursts = [r[3] for r in rows]
    assert depths == sorted(depths, reverse=True), depths
    assert prices == sorted(prices), prices
    assert depths[0] > depths[-1], "a depth that does not move is not derived"
    assert prices[0] < prices[-1], "a price that does not move is not derived"
    assert depths[0] == QUEUE_CAPACITY and depths[-1] >= QUEUE_FLOOR
    assert prices[0] == COSTS["tx"], "the written price is the floor"
    assert prices[-1] <= COSTS["tx"] * MAX_PRICE_MULTIPLE
    for unit, depth, price, burst in rows:
        assert burst >= price, \
            f"at {unit} ms a unit the burst {burst:.0f} cannot hold one {price:.0f}"


def test_the_derivation_is_a_no_op_at_the_unit_it_was_written_for():
    """Both constants were argued for at 25.4 ms. Deriving them must reproduce
    what somebody argued, or this is a new policy wearing a fix's clothes."""
    unit, depth, price, _ = measure.probe_derived((PRICED_AT_MS,))[0]
    assert depth == QUEUE_CAPACITY and price == COSTS["tx"]


# ── the record itself ────────────────────────────────────────────────────────

def test_the_committed_record_exists_and_says_what_it_is():
    path = os.path.join(os.path.dirname(measure.__file__), "..", "docs",
                        "measurements.md")
    if not os.path.exists(path):
        raise AssertionError("docs/measurements.md is missing — regenerate it "
                             "with python3 -m chain.measure")
    text = open(path).read()
    assert "python3 -m chain.measure" in text, "it must say how to regenerate"
    assert "commit" in text or "at `" in text, \
        "a measurement without a build is a number without a claim"


def test_the_record_can_be_regenerated_without_touching_the_committed_one():
    """`--print` exists so that running the probes is never a file edit."""
    text = measure.render(quick=True)
    assert text.startswith("# What this build costs")
    assert "µs" in text and "ms" in text
