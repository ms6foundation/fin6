# When the top tier does not agree

*Part twelve. Review C2. Design only.*

The review's line is four words long — *the supreme grid is a global stall
point* — and reading the code to size the work turned up two things the line
does not say.

The first is a number. The supreme grid is seated from the *leaders* of the
super grids, so it has one seat per super grid: at the sizing rule's own
example of 343 nodes it has **seven**. Quorum over seven is five, so **three
absent nodes out of 343 stop the entire network for an epoch** — and they are
redrawn every epoch, so it is not a risk you take once.

The second is that **the supreme tier has never run over a network**.
`chain/net/node.py` runs `SoloWorkload` and nothing else; `run_tiered_epoch` —
and with it phases S and X — exists only in the in-process simulation. So this
is not a repair of a live path. It is the last chance to design a tier before
it carries anything, which is the cheap moment and the reason to spend it now.

## 1. What actually stalls, and what does not

Phases run in sequence because each tier's membership is the tier below's
leaders. Failure is handled differently at each, and only the top is
all-or-nothing:

| tier | if one unit fails | if all fail |
|---|---|---|
| local | skipped; its transactions stay in mempools and wait for the next epoch | `"no local grid finalised"` — the epoch aborts |
| super | its children's blocks are dropped for this epoch — `g` grids' work, silently | `"no super grid finalised"` — the epoch aborts |
| **supreme** | **the epoch aborts** | same thing; there is only one |

So the tolerance the design promises is real at the bottom and absent at the
top. A local grid that cannot reach quorum costs its own partition one epoch.
The supreme grid that cannot reach quorum costs *every* partition one epoch.

What an aborted epoch costs, precisely, because it is less than it sounds:

- No network block, so **no register anywhere advances** and the epoch's
  attendance is dropped rather than penalised. Nobody's counter resets
  (`apply` never runs); nobody's counter moves either. A chain that aborts
  every other epoch promotes apprentices at half speed, network-wide.
- **No transaction finalises anywhere**, but none is lost: nothing is evicted
  from a mempool until a block applies, so the same transactions are proposed
  again next epoch.
- The height does not move, and `_check_epoch` ties epoch to height, so the
  next attempt is the same height under a new epoch number and a new seed.
  **Recovery is automatic and costs one epoch — 19.7 s.**

This is a liveness fault, not a safety one. Nothing forks, nothing is lost, and
the chain heals itself. That is why C2 is class C. The reason it is *High*
severity anyway is the next section.

## 2. The whole network's liveness is a seven-of-343 lottery

A committee of `n` seats with quorum `ceil(2n/3)` stalls when `n - q + 1` of
its seats are absent. Treating absences as independent with probability `p` —
crashed, partitioned, slow past the deadline, or deliberately silent — the
chance that one epoch stalls is:

| committee | quorum | absences to stall | p=0.05 | p=0.10 | p=0.20 | p=1/3 |
|---|---|---|---|---|---|---|
| 7 (today, at 343 nodes) | 5 | 3 | 0.004 | 0.026 | 0.148 | 0.429 |
| 21 | 14 | 8 | ~0 | 0.0006 | 0.043 | 0.399 |
| 49 | 33 | 17 | ~0 | ~0 | 0.012 | 0.473 |

At a 19.7 s epoch, `p = 0.10` and seven seats is **a network-wide stall every
13 minutes**. The same absence rate against a committee of 49 is one every
82 days. Nothing about the protocol changed between those two columns — only
how many seats were asked.

Two honest qualifications. At `p = 1/3` committee size stops helping, because
one third absent is the threshold the protocol tolerates by construction and
every committee is at the cliff; size buys margin *below* the cliff, which is
where a real network lives. And the supreme seats are not a random sample: they
are nodes that led a successful ceremony seconds earlier, which correlates with
being alive and correlates with nothing about being honest.

The asymmetry is the finding. **Today the whole network's liveness is exactly
as fragile as one small grid's** — the difference being that when a small grid
stalls, everyone else keeps going.

## 3. The supreme grid decides almost nothing

This is the leverage, and it is worth stating precisely because it changes what
kind of protocol the top tier needs.

Given the set of super blocks to include, every field of the network block is
**derived**:

| field | derived from |
|---|---|
| `utxo_root`, `nf_root`, `witness_root`, counts | `merge_deltas` in canonical order, applied to the previous state |
| `super_root`, `registers_root`, `seats_root` | the included children |
| `foundings_root`, `merges_root` | `plan_foundings` / `plan_merges`, from committed state |
| `history_root`, `protocol`, `height`, `prev_hash` | the chain |
| `quorum` | the committee it was drawn from |

`merge_deltas` documents its own determinism — *"order is the caller's
canonical order, so every node drops the same ones"* — and the order is
`sorted(self.supers)`. So the supreme grid is not choosing a block. **The only
free variable is which certified super blocks are in the set**, and two honest
seats differ on that only when one of them has not received something the other
has: a gossip race, not a decision.

A tempting conclusion follows, and it is wrong, so it is worth killing here.
*If the content is derived and proposals are ordered by inclusion, the top tier
needs no locking — a seat just takes the biggest verifiable set.* No: two
quorums at one height is a fork wherever it happens. If a quorum signs `{1,2}`
while a later quorum signs `{1,2,3}`, two different blocks are final at one
height and the fact that one contains the other does not help anybody who
applied the first. **C1's locking is needed at the top too.** What the derived
content does buy is narrower and still worth having: a view change at tier 2
almost always re-proposes *identical bytes*, and any seat can be the one to
assemble them.

## 4. Road A — a bigger committee, for free

The supreme grid seats **the leaders of the super grids**. Seat **the super
grids' members** instead.

At 343 nodes that is 49 seats rather than 7 — one per local grid — and it
wakes nobody new: those nodes are already awake, already in this epoch's
ceremony, already holding the super blocks. It is the same change at two tiers
(`supreme_members = super_leaders` becomes the union of the finalised super
grids' seats) and it moves the table's first row to its last.

What it costs, honestly:

- **Latency.** The design's own table puts 50 seats at ~2.1 s per tier at
  50 ms RTT against ~0.9 s for 10. The decide window is 0.60 × 19.749 s =
  11.8 s for all three phases in sequence, so the budget holds, but it stops
  being comfortable.
- **Messages, not proofs.** Each seat verifies the same merged block it would
  have verified anyway; there are simply more attesters. Certificates grow —
  which is what A3's committed seat order and bitmap encoding were built for.
- It does not help at `p = 1/3`, and no committee size does.

This is the cheapest large win on the page and it is not a format change: the
committee is chosen at run time and the header already records the quorum the
block needed (review B4).

## 5. Road B — no fixed leader at the top

With content derived (§3), the proposer at tier 2 is doing assembly, not
selection. So let **any seat propose** once its slice opens, and define the
acceptance rule over sets:

1. A proposal carries its super blocks with their certificates, so a seat can
   verify a super block it has never seen — inclusion is checkable, not
   trusted.
2. A seat prefers the **larger verifiable set**; between incomparable sets of
   equal size, the lower `super_id` list lexicographically. Deterministic, so
   two honest seats presented with the same two proposals prefer the same one.
3. A seat that has attested is **locked**, exactly as in C1, and a view change
   at tier 2 collects locks and binds the next proposer, exactly as in C1.

The gain is that the failure C1 exists for — *the leader is dead and everyone
waits* — mostly stops existing at the top, because there is no single node
whose silence costs the slice. The residual failure is the one Road A
addresses: not enough of the committee is alive to make a quorum, which no
proposal rule can fix.

Cost: a reconciliation rule and a deadline are a protocol, and this one has an
edge nobody should discover live — a seat holding `{1,2,4}` must *fetch* super
3 to adopt `{1,2,3}`, so the rule needs a bound on how much fetching a proposal
may demand before a seat gives up on it and lets the slice lapse.

## 6. Road C — views at the top, and nothing else

If A and B are both too much for now, the minimum is C1's machinery applied one
tier up: slice the supreme phase's budget into views, lock on attest, collect
view changes, bind the next leader. `chain/viewchange.py` is written against
(chain_id, height, epoch, view) and a quorum of seated signers; the supreme
grid has all four.

It is strictly weaker than A+B and worth saying why: it fixes the *dead leader*
and leaves the *seven-seat committee* exactly as fragile. Against the table in
§2, it converts one of the three absences into a tolerated one and nothing
more. It also spends budget that the three-phase epoch does not have much of —
11.8 s across three phases, sliced again.

Do it anyway if A and B slip, because a dead leader is the likeliest single
failure. Do not do it *instead* of A, because A is where the numbers move.

## 7. Absence at the top is free, and should not be

The supreme grid has no register. Standing lives in `GridRegister`, one per
*local* grid, advanced by an `AttendanceRoll` carried in the block — and the
supreme grid is not a local grid, has no persistent membership, and produces no
roll of its own. So a node that no-shows at tier 1 or tier 2 pays nothing,
while the same node missing its local ceremony loses its attendance streak.

The incentives are therefore inverted exactly where the blast radius is largest:
the cheapest place in the network to be absent is the only place where being
absent stops everybody.

The fix should not be a fourth register. Standing has a home — the node's own
grid — and the supreme roll is derived from the supreme certificate the same
way a local roll is derived from a local one. **Record tier-1 and tier-2
attendance as an entry in each seat's home-grid register**, carried in the same
network block, committed in the same `registers_root`. Two things have to be
decided rather than assumed:

- whether a missed supreme ceremony should reset a counter or merely fail to
  advance it (the local rule resets at `forgiveness = 0`, which is harsh for a
  seat whose selection it did not choose);
- and whether *leading* at a higher tier should count for more than attending,
  since `led_count` is already recorded and already unused.

## 8. The structural road, and why it is a pre-genesis decision

Everything above makes the committee harder to stall. None of it removes the
committee. The only design that removes it is **per-partition finality**: each
grid advances its own partition's roots, and the network header becomes a tree
over `K` partition roots that anyone can recompute — no single committee on the
critical path, and a stalled grid costs its own partition only, which is
already how the bottom tier behaves.

It is more plausible than it sounds, because the hard part is already done:

- **Nullifiers are strictly partitioned.** `nf mod K` decides where a note may
  be spent, and B3 established that a transaction spanning two partitions has
  no home by construction. So the nullifier accumulator splits cleanly into `K`
  independent trees.
- **Outputs do not partition by note**, because a payee's note lands where the
  payee's `rho` puts it — but they partition perfectly *by creating grid*, and
  a spend needs a witness in whichever tree holds the note, not in its own. So
  `K` append-only UTXO trees, each written by one grid, is sound.

What it costs is everything the single global root currently buys: the header's
roots and counts, the witness layer a light client checks its own note against
(part eight), the history spine, the snapshot format, and `K` changing under
foundings and merges — a retired grid's tree cannot be deleted, because notes
in it are still spendable.

That is a **rule change**, and rule changes now have a mechanism: `protocol.py`
and activation heights, built as the review's first finding. The mechanism has
one property that makes this a decision for *now*:

> Adding an activation later is a governance act that produces a new document
> and, by construction, a new chain; scheduling one in advance is just a number.

So **the option to ever do this has to be bought before genesis**, by reserving
activation heights in the genesis document. The honest caveat is that a
reserved slot is a deadline rather than an option — a node that reaches an
activation height for a version it does not implement halts, correctly — so the
escape hatch is shipping version 2 as "no rule changes" if the slot arrives
unused. A deliberate no-op is cheap. A chain that discovers it needs a rule
change and has nowhere to put one is not.

## 9. What I would build, in order

| | work | fixes | cost |
|---|---|---|---|
| 1 | ~~**Road A** — seat the super grids' members, not their leaders~~ **Done** | the committee, which is where §2's numbers live | one selection rule; latency and certificate size |
| 2 | ~~**§7** — tier-1/2 attendance in the home-grid register~~ **Done** | absence at the top being free | a roll derivation and two governance decisions. See §9.2 |
| 3 | ~~**Road C** — C1's views at the supreme tier~~ **Done in process** | the dead leader | budget arithmetic; reuses `viewchange.py`. See §9.4 |
| 4 | **Road B** — leaderless assembly with a set-preference rule | the leader as a role at tier 2 | a reconciliation rule and a fetch bound. **Left**, deliberately — see §9.5 |
| 5 | ~~**§8** — reserve activation heights in the genesis document~~ **Done** | keeping the structural road open | a number, before genesis. See §9.3 |

Items 1–4 are live-network changes and can be sequenced; item 5 is not, and is
the only part of C2 that expires at genesis.

### 9.1 Built — Road A

`supreme_members` is the union of the seats of every super grid that finalised,
rather than one leader from each. Two things fell out of writing it that the
sketch did not say.

**The collapse stopped being a special case.** Two tiers used to be a separate
branch that seated the only super grid's members; the union of one super grid's
seats *is* that grid, so the branch is gone and both cases are one rule.

**`owner_of` had to widen with it.** It answers "was my own super grid left out
of this block", and it was keyed by leader, because leaders were the only seats
there were. A member that is not a leader has exactly as much right to ask, and
now does.

The numbers, from the test fixture rather than from the sizing table — 40 nodes,
eight local grids, two super grids:

| | seats | quorum | absences tolerated |
|---|---|---|---|
| one leader per super grid | 2 | 2 | **0** |
| every super seat | 8 | 6 | 2 |

Zero is the number worth keeping. At that size the old committee could not
survive a *single* silent node: one absence and every partition on the network
lost the epoch. It is asserted in `test_a_committee_of_leaders_tolerated_no_absence_at_all`,
against a real epoch rather than an example, so it fails if the seating ever
narrows again.

### 9.2 Built — service at the upper tiers

Three counters on `MemberRecord` — `higher_seated`, `higher_attended`,
`higher_led` — credited into each member's **home grid** register, committed in
the same `registers_root`, with `higher_missed` derivable from the first two.
No fourth register, as §7 asked.

**Everything is derived from the block and nothing is carried in it**, which is
what makes it checkable rather than announced. A super grid's seats are the
leaders of the children it carries; the supreme committee is the union of
those, which after Road A is the leaders of every child in the block; who
attended is what each certificate proves, and the certificates are verified
before any of this is read. The one thing that was *not* derivable was who
led — `CeremonyBlockHeader` has carried `leader_id` since part two and the two
tiers above it never did. Both headers carry it now, each refused if it names
anybody but the leader that view seated, which also stops the archive losing
who led the tier that decides the roots.

**The timing is the attendance roll's, and it had to be.** The first attempt
credited service from the block being applied — and broke state sync, because
`snapshot.load` checks that the live registers fold to the header's
`registers_root`, and service applied after the root was computed makes them
disagree. So service keeps the same beat as a roll: block *h* commits a
register root every seat could compute before block *h* existed, from the
service the *previous* block derived. `TierWorld.prev_service` holds it,
`LocalWorkload._register_after` applies it in exactly the order
`apply_network_block` does, and a `service` table persists it — the third time
this lesson has arrived, after `grid_roll` and `grid_cert`, and the snapshot
payload carries it for the same reason it carries the certificates.

**The two decisions §7 said had to be taken rather than assumed.**

*Does a missed supreme ceremony reset a local counter?* **No**, and the
counters are separate so that it cannot. A seat at the upper tiers is drawn by
a lottery the member does not control; folding it into `consecutive` would let
a node lose the standing it earned at home for an epoch it was conscripted
into. `credit_service` touches neither the epoch nor the streak.

*Does leading count for more than attending?* It is **counted apart** —
`higher_led` beside `higher_attended` — rather than weighted. Turning either
counter into a *consequence* (a standing penalty, exclusion from the committee)
is a governance decision that should be taken with numbers from a live network
rather than an intuition here, and the record is what makes those numbers
exist. Today absence at the top is visible in a committed root; it was not
visible anywhere at all.

**One latent bug surfaced.** Crediting service widened the set of registers a
block touches, and the store commit then tried to write a register for a grid
this block had merged away — a `KeyError` that C4 had left behind and that only
a block both merging a grid *and* touching it could reach.

### 9.3 Built — the slots are reserved

`protocol.RESERVED_SLOTS` schedules protocol 2 at height 1,596,840 and protocol
3 at 4,790,520 — about one year and three years at the shipped 19.749 s epoch —
and a **launch** document carries them. A test document carries none, because a
fixture that halts at a height is a fixture with a fuse in it.

The document says what that commits an operator to, in its own caveats, naming
the heights:

> protocol [2, 3] activate later and this build implements 1: a node running it
> will halt at the first of those heights rather than fork — 2 at 1,596,840
> (~1y), 3 at 4,790,520 (~3y). A reserved slot is a deadline, and shipping the
> version as "no rule changes" is the escape hatch.

And a document that reserves *nothing* now says that too, which is the caveat
that matters more: a chain with no slot cannot adopt a rule change at all, only
be replaced by a different chain.

Adding the schedule re-digested `config/genesis-7.json` — it is inside the hash
the chain id is, which is the whole reason this had to happen before genesis
rather than after — so the founders re-ratified and the mint, which binds to
`mint_context()`, was minted again.

### 9.4 Built — views at the top, and what is still missing

The supreme phase now runs up to `SUPREME_VIEWS` views. Each reseats the whole
committee from a fresh seed and skips the leaders already tried — exactly what
`ceremony.run_epoch` has done at tier 0 since part one, applied at the tier
where a silent leader costs *everybody* the epoch. A budget rather than a
guarantee: if every view fails the epoch produces nothing, as before, and the
chain recovers at the next one.

**What this is not is the network protocol, and the distinction is the whole of
C1.** In one process a ceremony finalises for every seat or for none, so there
is no view in which one seat has finalised a block the others are giving up
on — which is the failure that makes a retry loop unsafe over sockets.
`chain/viewchange.py` is the answer to that and is wired into the *networked*
node, which runs one grid. When the upper tiers run over sockets they need the
locking here too; today they run in `run_tiered_epoch` alone. Marked "done in
process" rather than "done" for that reason.

**The harness needed one addition to stage the failure at all.** A behaviour
keyed by node id applies wherever that node leads, which was blunt enough while
there was one tier: silencing the supreme leader also silenced it in its own
grid, so the local phase changed, so the committee changed, and the experiment
measured something else. A `(tier, node_id)` key aims at one seat in one
ceremony; a bare node id still means everywhere. The test that matters reads
straight now — same committee, same view-0 seating, one view lost, the next one
carries it — and the budget test asserts the thing C2 is actually about: the
tiers below did their work and lost it.

### 9.5 Not built — Road B, and why not yet

Four of the five are in. Road B is left, and the reason is the same one that
decided B5: its gain is on a surface that does not exist yet.

What Road B buys is that *any* seat can assemble the block, so no single node's
silence costs a slice. In one process that is already covered — Road C reseats
the committee and the next leader carries it, and a ceremony there finalises
for every seat or for none. The gain appears when the upper tiers run over
sockets, where a slice is wall-clock time and a proposal has to travel; and
that is also where its cost appears, because the rule needs a **fetch bound**:
a proposal carrying super blocks a seat does not hold is a larger set, and it
is also a denial vector wearing a larger set's clothes. That bound is a number,
and this repository's rule for numbers is that they are measured rather than
argued — `chain/measure.py` exists precisely so that the measuring has
somewhere to go.

So Road B waits for the first live run of three tiers, which is also part
thirteen's item 5 and the thing that will correct at least one figure in §2.

## 10. What this does not do

- **It does not make the supreme tier optional.** Global roots need a global
  view, and one committee is how you get one. Roads A–C make it harder to
  stall; only §8 removes it, at the price of a different ledger shape.
- **It does not address the super tier's silent loss.** A super grid that fails
  drops every local block beneath it for that epoch, without a word in the
  block about what went missing. Smaller than C2 and the same shape; it should
  be named as its own item rather than folded in here.
- **It does not improve anything at `p = 1/3`.** An adversary at the safety
  threshold can deny liveness at the top roughly half the time under every
  proposal here, and the only answers to that are economic or governance ones.
- **It changes no format.** Deliberately — everything except §8 is chosen at
  run time or carried in fields that already exist, which is what keeps C2 in
  class C.

## Open items

| item | why it is still open |
|---|---|
| The committee's size is a parameter nobody has chosen | §2 gives the arithmetic; the value depends on a network's expected absence rate, which is an operational estimate this repository does not have. |
| Whether tier-2 absence resets a counter | A seat is drawn into the supreme grid by a seed it does not control. Penalising it like a missed home ceremony may be right; it has not been argued. |
| The fetch bound in Road B | A proposal that demands too many super blocks a seat does not hold is a denial vector wearing the clothes of a larger set. |
| Retired partition trees under §8 | A merged grid's notes stay spendable, so its tree survives its grid. Where it lives and who serves it is unsketched. |
| Nothing here has run over sockets | Phases S and X are simulation-only today. Every number in §2 is arithmetic, not measurement, and the first live run of three tiers should be expected to correct one of them. |

## Rendered version

Diagrammed: https://claude.ai/code/artifact/f4f5ea21-627c-4552-9f9e-f03c566684fe
