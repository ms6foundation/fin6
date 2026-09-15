# An instrument before a knob

*Part thirteen. Review class D. Design only.*

Class D is nine items and one sentence, and the sentence contains the nine:

> And the one that keeps recurring across three documents: **nothing measures
> any of this.** "Seven nodes agreed for an hour" and "the node did not fall
> over" are not tests.

The class is ranked *operational, any time*. "Any time" is doing more work in
that sentence than it can carry. Every item in it is a number to choose, and a
number cannot be chosen by argument — so a knob nobody can measure is not a
knob that can be turned late, it is a knob that cannot be turned at all. The
work class D needs is therefore not nine decisions. It is **one instrument, and
then the decisions follow from what it says**.

To check that claim rather than assert it, I spent ten minutes measuring three
of the nine before writing this. Two of them were wrong. §2 is what they said.

## 1. Nine items are four stories

The list reads as independent knobs and is not. Grouped by what would settle
them, class D is four:

| story | items | what they share |
|---|---|---|
| **The price of being wrong** | rate-limit thresholds · throttle tolerance for a broken prover · penalty-box eviction · whether shedding is observable · queue depth | All price the same scarce thing — a node's CPU inside a decide window — against callers it cannot identify. Set independently, they contradict each other. |
| **The cost of keeping history** | snapshot cadence · archive incentives · fsync honesty | All about what survives a restart, and who pays to make it survive. |
| **The ceilings** | the 1.4 ms flat fold · sample rates at the upper tiers | Two limits on throughput, one measured and one that does not exist yet (§5). |
| **Claims nothing checks** | chaos stages assert nothing · locality tags are self-declared | Not numbers at all. One is missing test machinery, the other is a trust assumption filed under operations. |

The first story is the one with a network on the other end of it, so it is
where the instrument should point first.

## 2. Ten minutes of measuring, three answers

### 2.1 The penalty box charges the defender

`Gate.penalise` calls `_sweep`, and `_sweep` sorts the whole box whenever it is
over capacity. `penalise` is on the attacker's path — it is what a malformed
frame causes — so the cost of remembering offenders is paid per offence, by the
node, at a rate the offender sets:

| entries in the box | one `penalise()` | at 1,000 violations/s |
|---|---|---|
| 0 | 2.9 µs | 0.3% of a core |
| 1,000 | 23.9 µs | 2.4% of a core |
| 4,096 (`MAX_PENALISED`) | **288.5 µs** | **29.5% of a core** |

A hundredfold. The box's own docstring anticipated the shape of this —
*"remembering offenders is itself state they can grow, so the box is a cache
with an eviction policy and not a ledger"* — and then paid for the eviction
policy on the hot path. The eviction *choice* is right, incidentally: it drops
the entries expiring soonest, so a flood of first offenders evicts itself
before it evicts a hardened one. It is the bookkeeping that is wrong, and it is
wrong in the direction that matters, because it scales with the attack.

This is a fix, not a design: sweep on a clock rather than on every violation,
or keep the box in expiry order so eviction is a pop. What makes it a class D
item is that **nothing would ever have told anyone** — the gate's tests assert
that an offender waits, which it does, in 288 microseconds.

### 2.2 A submission is priced by its size, and paid for in verification

The rate limiter charges a caller twice: once for the bytes it decoded, once
for the kind. A `tx` costs 50 tokens plus one per 8 KB, against a client bucket
of 240 tokens and 20 a second. Those numbers were chosen when a proof cost
25 ms to verify — `INITIAL_UNIT_MS = 25.4`, mpcith at `LOCAL` parameters.

At `LAUNCH` parameters the same backend verifies in **0.31 s**, and the price
did not move:

| | proof | tokens | sustained rate | verification per address |
|---|---|---|---|---|
| `LOCAL` (the price was set here) | 60 KB | 57.5 | one per 2.9 s | 0.9% of a core |
| `LAUNCH` (the chain ships here) | 378 KB | 97.3 | one per 4.9 s | **6.4% of a core** |

Sixteen addresses saturate a core, and none of them has broken a rule: a frame
carrying a bad proof is a *well-formed* frame, so `Gate.penalise` never sees
it — the gate only ever penalises `FrameError`. Repeating one bad body is
already handled well (`PROOF_STRIKES` demotes it after three, so any one body
costs at most three verifications), so the residual is exactly a wallet — or an
imitation of one — shipping *distinct* transactions that do not verify. That is
indistinguishable from a broken prover, which is the review's own framing of
the item, and the answer to it is a price rather than a diagnosis.

The same stale unit sits in the queue. `QUEUE_CAPACITY = 256` is justified as
*"about 6.5 seconds of verification"*, which it was at 25.4 ms. Working the
budget forward at 0.31 s and the shipped 19.749 s epoch:

```
decide window      0.60 x 19.749 s          = 11.85 s
reserve            min(128 units, 50%)      =  5.92 s   (capped, not units)
discretionary slack                         =  5.92 s
a stranger's floor  50% of the slack        =  2.96 s   ->  9.6 verifications
over MAX_EPOCHS_QUEUED = 3 epochs           =  29 of 256 served
```

So roughly **nine tenths of a full queue is guaranteed to expire unserved** at
launch parameters. Nothing is broken by that — expiry is designed, and the
budget's `Meter` *does* self-correct, because it replaces the estimate with
measurement. The point is the asymmetry: the one constant that learns is the
one that was least in need of learning, and the two that cannot learn are
counts derived from a cost that has since moved by a factor of twelve.

### 2.3 The fold cost is exactly what the document says

The item reads *"the 1.4 ms flat fold cost (an interpreter ceiling, ~125 tx/s
at ten million notes)"*. Measured on this build:

| notes already in the tree | marginal append |
|---|---|
| 1,000 | 1.02 ms |
| 20,000 | 1.22 ms |
| 100,000 | 1.31 ms |

Flat, as claimed, and converging on the documented 1.4 ms. Part four's fix to
the quadratic term is holding. This one needed no design work and it is the
reason to say so out loud: a measurement that confirms is worth as much as one
that does not, and the only thing missing is that **nothing runs it**, so the
next change to `_SealTree` moves this number silently in either direction.

## 3. The instrument, in three parts

### 3.1 Assertions in the chaos stages

Part six's stage table is the right frame and is now out of date, because two
of its blockers were removed in the review work:

| stage | what | then | now |
|---|---|---|---|
| 3 | hardening wired into the node loop | presets built, not wired | unchanged |
| 4 | chaos: kill, pause, partition, skew | kill and pause assert; partition and skew assert nothing | unchanged, and it is the gap |
| 5 | growth: admit nodes, found a grid, tiers 1 → 2 → 3 | blocked on peer discovery | **unblocked** — C6 shipped the directory |
| 7 | chunked snapshot transfer | not started | **done** — C7 |

The missing assertions are the ones that turn a stage from a demonstration into
a test. Each is one line of the health check that already exists, run at the
right moment:

- a **partition** heals within N epochs, and the roots agree on both sides of
  it before and after — this is the one that would catch a silent fork, which
  is the only failure in this system that is worse than stopping;
- a **skewed clock** puts a node in the wrong view and its attestations are
  ignored rather than counted, with the epoch still finalising;
- a **flood** — the stage that does not exist at all — runs against a node
  while the decide deadline has to be met, and asserts the deadline was met,
  the shed counters moved, and no honest submission was lost that the budget
  did not say it had lost.

`chain/tests/test_budget.py` exercises the arithmetic with a fake clock, which
is right and is not the same claim. Nothing has ever put load on a live node.

### 3.2 Numbers that rot visibly

This repository's own history is that measurement corrects documentation:
`STRONG`'s parameters were two revisions behind their own source, a certificate
was 56.2 KB and not 54.7, a three-backend submission was 3.27 MB against a 1 MB
ceiling nobody had related to it, and §2.2 above is the same story again. The
pattern is not carelessness; it is that a number written in prose has nowhere
to fail.

So the instrument's second part is a committed file of measurements with a
runner that regenerates it — proof cost per backend and preset, append cost at
three tree sizes, `penalise()` at three box sizes, frame decode, epoch wall
time — and a CI comparison that fails on a material move. The numbers then
live where a change to `_SealTree` or a new preset makes them wrong *loudly*.

### 3.3 One honest number for the store

`PRAGMA synchronous=FULL` with WAL is the right setting and is a claim about
the device, not about SQLite: consumer SSDs and several filesystems acknowledge
a flush they have not completed. Part four's crash-safety argument — *"a crash
in the middle of an epoch costs the epoch and nothing else"* — rests on it.

The work is not to fix it, because it cannot be fixed in software. It is to
**test it once on the hardware a node will actually run on** (write, cut power
or kill the VM, reopen, compare the tip against what was acknowledged) and to
record the result next to the claim. A node whose disk lies is not a node with
a slower store, it is a node that can acknowledge a block it does not have.

## 4. What each knob needs before it can be set

| item | the measurement that would settle it |
|---|---|
| rate-limit thresholds | verification cost per preset, against the token price. §2.2 makes this a derivation, not a judgement. |
| throttle tolerance for a broken prover | the cost curve of distinct invalid submissions per address per epoch, with and without a strike rule at the address level. |
| penalty-box eviction | §2.1, then the same run after the sweep is moved off the hot path. |
| shedding observable to a client | not a measurement — a protocol question (§5). |
| queue depth | slack per epoch ÷ unit cost × `MAX_EPOCHS_QUEUED`. The queue should be sized by what it can serve, and that number moves with the parameters, so it should be derived at start-up rather than written down. |
| snapshot cadence | export time and size at realistic state, against restart time from the store. Today there is no cadence at all: exports happen when a peer asks and are memoised for one height. |
| archive incentives | the size of `FULL` against `COMPACT` over a year of blocks. The question "who keeps history" cannot be argued before someone knows what it weighs. |
| fsync honesty | §3.3, once, per hardware profile. |
| the 1.4 ms fold | §2.3, tracked rather than re-measured. |
| sample rates at the upper tiers | nothing — the mechanism does not exist (§5). |
| locality tags | nothing — a trust assumption, not a number (§5). |

## 5. Three of these are misfiled

**Sample rates at the upper tiers is not a rate.** The tiered design promises
that each tier re-checks the tier below with a different proof system, audited
by seeded sample — *"the real prize: protocol diversity"*. Reading the code:
`SuperWorkload.validate` checks quorum certificates, partition compliance and
delta collisions, and **verifies no transaction proof at all**; nor does the
top tier. Above tier 0 nobody re-verifies anything, so the ladder's
independence is currently an aspiration rather than a property. It is also
moot at launch, because `LAUNCH` ships **one** backend — a deliberate, argued
choice — so there is no second system to audit with. This is a *mechanism*
that does not exist, coupled to a parameter decision already taken. It belongs
with the tiering work, not in an operations list.

**Whether shedding is observable to a client is a wire question.** `submit` is
fire-and-forget by design, and the design is argued: *"the node answers
nothing, and a wallet finds out what happened by asking `txstatus`."* But
"your transaction has not finalised yet" and "this node shed your transaction
and it will expire in three epochs" are different facts, and today a client
cannot distinguish them — the shed counters go out in `status`, aggregated,
where no wallet is looking. Giving a submission a refusal reason is a message
change, and message changes are class B. It should be decided with the format
work, where it costs a field, rather than later where it costs an activation.

**Locality tags being self-declared is §6's item, not class D's.** It is listed
in both places. It is safe exactly as long as the roster is permissioned, and
the review's §6 already says so; repeating it under operations makes it look
like a threshold somebody could tune.

## 6. The order I would work in

| | work | why here |
|---|---|---|
| 1 | ~~Move `_sweep` off the hot path~~ **Done** | §2.1 is a live denial-of-service amplifier with a one-function fix. It was two — see §7.1. |
| 2 | ~~Derive `QUEUE_CAPACITY` and the submission price from the measured unit cost~~ **Done** | §2.2. Both are already computable at start-up from numbers the node holds. See §7.2. |
| 3 | ~~The measurement runner and its committed output~~ **Done** | Everything below needs it, and it is the item that stops the others from rotting. See §7.3. |
| 4 | Assertions on partition and skew; a flood stage | Part six's stage 4, finished. |
| 5 | Stage 5 — growth over sockets, tiers 1 → 2 → 3 | Unblocked by C6, and it is also the first live exercise of part twelve's tiers. |
| 6 | One power-cut test, recorded | §3.3. Cheap, once, and the crash-safety claim depends on it. |

Items 1 and 2 are fixes that measurement found and are not really design work.
Item 3 is the actual deliverable of class D. Items 4–6 are what the instrument
is for.

## 7. Built — items 1 to 3

### 7.1 Both hot paths, not one

The sketch named `Gate._sweep`. Fixing it turned up **the same amplifier in a
second place**, and a cheaper one for an attacker to reach: `Limiter._sweep`
sorts every bucket it holds, and it runs when a frame arrives from an address
the node has not seen. That costs an attacker no disconnect at all — just an
address it has not used yet.

| path | trigger | before | after |
|---|---|---|---|
| `Gate.penalise` | a malformed frame | 2.9 µs empty → **288.5 µs** at 4,096 | 0.8 µs → **1.3 µs** |
| `Limiter.check` on a new source | a frame from an unseen address | 5.8 µs empty → **331.7 µs** at 4,096 | 1.3 µs → **1.3 µs** |

Neither policy changed, which is the part worth insisting on. The penalty box
still evicts the entry that would expire soonest — so a flood of first
offenders at two seconds each evicts itself rather than displacing an address
that has worked its way up to a minute — and the limiter still forgets idle
sources, oldest first. What changed is that both now keep their state *in the
order they need it*: the box is a min-heap on expiry, so dropping what has
expired and evicting when full are a pop from the same end; the bucket table is
an `OrderedDict` used as an LRU, so the sweep is a pop rather than a sort.

One thing the rewrite had to get right: "oldest" in the limiter means least
recently *used*, not first seen. An `OrderedDict` gives that only if every use
touches the entry, which is now asserted — a source that has been talking all
along must not be evicted before one that went quiet.

### 7.2 Two constants became derivations

`EpochBudget.servable()` reads the budget's own arithmetic forwards — slack,
minus this priority's floor, over the measured unit, times how many epochs a
job may wait — and `WorkQueue.resize()` applies it at the top of every epoch.
`Limiter.cost_of("tx")` multiplies the written price by how much dearer a unit
of work is now than the 25.4 ms it was priced at.

| measured unit | queue depth | `tx` price | client burst |
|---|---|---|---|
| 25.4 ms — what the numbers were written for | 256 | 50 | 178 |
| 100 ms | 88 | 197 | 325 |
| 310 ms — `LAUNCH` | **28** | **610** | 738 |
| 900 ms | 9 | 1,772 | 1,900 |

The first row is the test that matters most: **at the unit both constants were
argued for, the derivation reproduces both of them exactly.** A fix that
quietly becomes a new policy is not a fix.

Three guards came out of building it, and the middle one is a trap the module's
own docstring had already warned about:

- the price never falls below the number somebody argued for, because measuring
  a cheap proof is not an argument for cheap submissions;
- **the ceiling must never become a ban.** At twelve times the written price a
  submission costs 610 tokens against a 240-token bucket — so no client could
  ever submit anything again, which is precisely the failure `limits` describes
  as *"a per-frame ceiling a source can never afford is not a ceiling, it is a
  decoy"*. The burst floor now rises with the price so one largest-possible
  submission still fits. The refill *rate* does not move, and that is the half
  that bounds sustained abuse: a dearer submission means fewer per minute, not
  none;
- and the multiple is capped, so one pathological proof cannot close the door
  on every wallet.

### 7.3 The record, and what a regression check can honestly assert

`python3 -m chain.measure` writes `docs/measurements.md`: the two hot paths at
three sizes each, the append cost at three tree sizes, prove/verify/bytes per
preset, and the numbers the node derives from them. It takes about three
minutes; `--quick` skips the proving and takes about fifteen seconds.

The open item this closes is the sketch's own — *what does "a material move"
mean?* It means nothing, between machines, and the honest answer is to stop
pretending otherwise. So the split is:

- **`docs/measurements.md` records the numbers**, with the build, the Python
  version and the platform beside them, because a timing without a machine is
  not a measurement;
- **`chain/tests/test_measure.py` asserts the shapes**, which do travel: flat
  is flat anywhere, a cost that scales with state an attacker can grow scales
  everywhere, and a derived number moves in the direction its derivation says.
  Reverting either sweep fails the suite on any machine.

The append probe changed estimator on the way, for a reason worth keeping: the
defect part four fixed was *periodic* — a rebuild whenever a new `sbs` group
opened — and a best-of-n is exactly the statistic that cannot see a cost paid
every thousandth call. It is a mean over a window wider than a group. The test
also says what it cannot catch: the `N x 4.1 us / 1000` term crosses the flat
cost at about 340,000 notes, which no test suite is going to fill, so that one
is watched by a human comparing two runs of the 100,000-note row.

## 8. What this does not do

- **It sets no thresholds.** Deliberately. Three of the nine turned out to have
  a *derivation* rather than a judgement behind them (§4), and the rest need a
  number nobody has yet.
- **It does not make the chaos harness general.** Partition and skew already
  exist as configuration; what is missing is assertions, not machinery.
- **It does not address archive incentives.** Who keeps history and why they
  would is a governance question wearing an operations costume, and it should
  be answered next to succession rather than here.
- **It changes nothing about the ceiling.** The 1.4 ms fold is where a C or
  gmpy2 inner loop would pay, as part four said; that is a project, not a knob.

## Open items

| item | why it is still open |
|---|---|
| An address-level strike rule for invalid proofs | `PROOF_STRIKES` bounds one body; nothing bounds one address across bodies. A strike rule there has a censorship shape to avoid — the same one the per-body rule already had to dodge. |
| ~~What "material move" means in a regression check~~ **Answered** | It means nothing between machines, so nothing compares timings across them: `docs/measurements.md` records the numbers with the machine beside them, and `test_measure.py` asserts the shapes, which do travel. §7.3. |
| An address-level cost for a queue that shrank | The derived depth is smaller than the written one at launch parameters, which is correct and also means `offer` refuses sooner. Whether a refused submission should cost its sender more than an accepted one is the same question as the strike rule below, and neither is settled. |
| Snapshot cadence as a restart strategy | Today exports serve peers only. Whether a node should checkpoint for its own restart is a different question with a different answer, and neither has been measured. |
| The upper tiers' sample mechanism | §5 defers it rather than settling it; it needs the tier work of part twelve to land first. |
| Nothing here has run on more than one host | Every figure on this page came from one laptop-class machine. The numbers that matter most — decide-deadline margin under load — are the ones a single host cannot produce. |

## Rendered version

Diagrammed: https://claude.ai/code/artifact/33d0af02-9d6a-4bf6-8414-cc4326627405
