# What a fee buys

*Part fifteen. Design only. Read after `docs/emission_design.md` (part fourteen),
which took the reward and deliberately left the fee alone.*

A fee on fin6 is public, non-negative, and burned. It buys exactly one thing:
survival in one node's mempool once that mempool is full. It does not buy
inclusion, because **no rule says what a block must contain**, and `chain/node.py`
is careful to say so rather than imply otherwise:

> Full, so admission is a competition rather than a queue. Note what is *not*
> being claimed here: this is not a fee market. A fee market is a rule the chain
> agrees about what a block must contain, and nobody has written one. This is a
> node's own eviction order, it changes no consensus rule, and two nodes with
> different caps still agree on every block — which is exactly why it can be
> added now and a fee market cannot.

So this sketch is not "design a fee market". It is: **a fee prices capacity, and
fin6's capacity is not written down anywhere.** Measuring it is where the work
turned out to be, and §2 is the reason the rest of the document is ordered the
way it is.

## 0. What exists

| | |
|---|---|
| the value | `tx.fee`, and it is **public** — the sum row reads `sum(in) − sum(out) = fee`, so it is revealed while every amount stays hidden. |
| the check | `fee < 0` is refused. There is no minimum and no maximum. |
| where it goes | `state.burned_fees += tx.fee`. Burned, and a term in the supply bound. |
| ordering | none. `GridWorkload.build` walks `leader.mempool.values()` in whatever order the dict holds, filters by partition, and stops at an optional `limit` no caller sets. |
| eviction | when a mempool is full: lowest fee first, oldest on a tie, *per node*, consensus-free. |
| block capacity | **no rule at all.** Nothing caps transactions per block. |

Read across that table and the shape of the gap is clear. The sender cannot buy
inclusion because there is no rule to buy it with; the producer cannot profit
from including because the fee is burned; and the thing actually being rationed
is not what the fee is denominated in.

## 1. What is actually scarce

Three unrelated constants bound a block, and **the smallest one wins**. None of
them was chosen with the others in view.

| bound | where it comes from | at `LAUNCH` |
|---|---|---|
| the wire | `MAX_FRAME`, 8 MB, a block body in one frame | **22 transactions** |
| the clock | a proposal's unseen proofs, verified inside the decide window | 22 × 0.31 s = **6.8 s of 11.85 s** |
| the backlog | `MAX_MEMPOOL`, 4,096 | 186 blocks ≈ **61 minutes** |

Three things worth saying about that table.

**`MAX_FRAME`'s own comment is wrong by a factor of five.** It reads *"8 MB: a
block of ~100 transactions with one proof"*, which was true at demo and local
proof sizes (136 at 61 KB) and is 22 at the launch parameters the chain ships.
This is the same family as review A9 — a wire constant sized against `DEMO` and
never related to `LAUNCH` — and the same family as the class D findings, where
a queue depth and a submission price were sized against a 25 ms verification
and could not notice it had become 0.31 s.

**Verification is not refusable.** `Priority.CEREMONY` is never shed, by design:
*"a node that will not validate the proposal because it is busy is the failure
this module exists to prevent."* So a proposal carrying transactions this node
has never seen spends 6.8 seconds of an 11.85 second window before anything
else happens, and the budget cannot decline it. The wire ceiling and the clock
ceiling land within a factor of two of each other **by coincidence**.

**The frame bounds the whole network, not one grid.** A network block carries
every tier-1 block, carrying every ceremony block. It travels as one `"block"`
frame. So partitioning multiplies *verification* capacity across grids and does
not multiply *wire* capacity at all: 22 launch transactions per block is the
figure whether there is one grid or forty. Part two's throughput claim — that
it scales with the number of grids — holds for the ceremonies and not for the
block that carries them, until a body can be fetched piecewise the way C7 made
a snapshot fetchable in ranges.

**So: 1.1 transactions a second, network-wide.** That is the number a fee would
be pricing, and nothing in the repository says it.

## 2. Price it in work, not in bytes

Class D left a measured unit behind: `budget.Meter.estimate`, the observed cost
of one verification, and the rate limiter now charges a submission in multiples
of it. A fee denominated in the same unit inherits that measurement instead of
repeating its mistake.

Which surfaces something worth fixing regardless: **there are already two
prices for one resource, set independently.**

| | the token bucket | the fee |
|---|---|---|
| paid to | nobody — it refills with time | nobody — it is burned |
| scarce thing | this node's CPU, right now | a place in a full mempool |
| denominated in | work (since part thirteen) | units of money |
| scope | per address, per node, off-chain | per transaction, on-chain |

They are not redundant — one is admission and the other is ordering — but they
should be derived from the same measured unit, or a node prices the same work
twice at two unrelated rates and neither number can be defended.

**Recommendation:** a fee floor expressed as `min_fee = fee_per_unit ×
units(tx)`, where `units(tx)` is what the transaction costs to verify (its
shape: inputs, outputs, backends) and `fee_per_unit` is a genesis parameter.
Not a market — a floor. §3 is why that distinction carries the whole design.

## 3. The inclusion rule, which is the only consensus decision here

Everything above is local policy. This is not: a rule about what a block may
contain is a rule every seat checks and every fork turns on.

Three shapes, in increasing order of how much they commit the chain to.

**(a) Nothing — the status quo.** A leader includes what it likes. Cheap,
already true, and it has one cost that is invisible: a leader that censors is
undetectable, because there is no rule it could be seen to break. On a
permissioned roster that is survivable and should still be said out loud.

**(b) A floor, and nothing else.** A block may not contain a transaction whose
fee is below `min_fee(units(tx))`. Every seat checks it with arithmetic it
already has; it is a *refusal* rule, so it adds no obligation to include
anything; and it cannot be gamed by ordering because it says nothing about
order. It makes "spam is free" false without making "the highest bidder wins"
true.

**(c) Full ordering — a block must be the highest-fee feasible set.** The real
fee market, and the expensive one: every validator has to recompute the
leader's selection to check it, against a mempool it does not share, which is
precisely the disagreement partitioning and derivation exist to avoid
everywhere else in this system. `plan_foundings` is derived from committed
state so that a leader proposes nothing; a fee market is the opposite shape —
discretion that must then be audited against state nobody agrees on.

**Recommendation: (b).** A floor is the only one of the three that is both
checkable from committed state and cheap. Leave ordering to the leader and
bound it, rather than trying to derive it.

## 4. Who gets it — and why burning is not a placeholder

Part fourteen recommended paying the block reward to the seats named by the
previous block's certificate, and the same three candidates apply to fees. The
arithmetic here is different, and it cuts the other way.

Consider a producer that writes its own transaction paying itself a fee `F`,
purely to win the eviction floor in a full mempool:

| fees go to | what self-dealing costs the producer |
|---|---|
| **burned** (today) | `F`. Full price. Outbidding everybody costs real money. |
| the leader | **nothing.** It pays `F` and receives `F`, so it can outbid every honest sender at zero cost and monopolise a full mempool for as long as it leads. |
| the certificate's seats, split `n` ways | `F × (n−1)/n`. A real price, and it rises with the quorum. |

So the status quo has a property the obvious improvement loses. **Burning is
not a placeholder; it is the only distribution under which a block producer
cannot bid for free.** Paying the leader is the one option that should be ruled
out rather than compared.

If fees are ever paid rather than burned, pay the certificate — the same
recipients, the same beat and the same committed state as the reward, and the
self-dealing discount is bounded by the quorum size rather than being total.
And note that the supply invariant survives either way: a paid fee is neither
created nor destroyed, so `supply(H) = genesis + minted(H) − burned(H)` closes
with `burned(H)` counting only what is still burned.

## 5. A base fee, and why not yet

The EIP-1559 shape — a per-block base fee that adjusts with demand, burned, and
a tip that is paid — exists to make fee estimation predictable when demand
varies. It buys that with a new consensus rule that every block carries and
every validator recomputes.

fin6 should not take it yet, and the reason is §1: at 1.1 transactions a second
with a permissioned user base, **congestion is not the binding constraint — the
frame is.** A base fee that rises with demand would be pricing a queue that is
empty for structural reasons, and it would add a consensus surface to do it.

The trigger condition deserves writing down now so the decision is not taken by
drift: *when blocks are persistently at the wire ceiling and the mempool
backlog exceeds an hour, the floor of §3 is no longer enough and a demand-
responsive fee becomes the cheaper answer.* Until then, a fixed floor and a
fixed reward are two numbers instead of two rules.

## 6. Three things that must not happen

- **A hidden fee.** Part fourteen's argument applies unchanged: the fee is
  public today because the sum row reveals it, and any scheme that hides it
  makes the supply unauditable rather than private. A fee is the one amount on
  this chain that must stay in the clear.
- **A producer-set fee.** Whatever the rule, the fee must be a property of the
  transaction its sender signed. A producer that can adjust a fee after the
  fact can pay itself out of somebody else's transaction.
- **A fee floor nobody can afford.** `limits.py` already learned this in
  another guise — *"a per-frame ceiling a source can never afford is not a
  ceiling, it is a decoy"* — and a `fee_per_unit` that outruns the smallest
  note is the same failure: a chain where the minimum viable payment exceeds
  the amounts people hold. The floor belongs in `ChainParams.assess`, checked
  against `range_bits`, like every other parameter that can be set to a value
  that reads fine and cannot work.

## 7. Order of work

| | change | class |
|---|---|---|
| 1 | Fix `MAX_FRAME`'s comment, and state the block capacity at each preset in `docs/measurements.md` | trivial, and it is the finding the rest depends on |
| 2 | `units(tx)` — a pure function of a transaction's shape, measured against the meter | additive |
| 3 | `fee_per_unit` in the genesis document, with an `assess` caveat against `range_bits` | **pre-genesis** — it is inside the chain id |
| 4 | The floor as a block rule, checked in `check_ceremony_txs` | format |
| 5 | Piecewise block bodies, so partitioning buys wire capacity as well as verification capacity | protocol, and the real throughput work |
| 6 | Reconcile the token price and the fee floor to one measured unit | additive |

Items 1 and 5 are not fee work and are the ones that decide what a fee can
mean. That is the finding: **before the chain can price a block, it has to
decide what a block is.**

## Open items

| item | why it is still open |
|---|---|
| `fee_per_unit`, the number | §2 gives the shape. Choosing the value needs a unit of account and a view on what a payment is worth, which this repository does not have. |
| Whether to pay fees at all | §4 argues burning is robust and paying is not obviously better. The case for paying is a censorship incentive, and nobody has shown it bites on a permissioned roster. |
| Censorship is undetectable | §3(a) names it and none of the three options fixes it. A leader that omits a transaction breaks no rule under (a) or (b), and under (c) the audit needs a shared mempool. It may need a different mechanism entirely — an inclusion list, or the transaction's own grid attesting that it was offered. |
| `units(tx)` across presets | A transaction's verification cost depends on the backend and the parameters, so the same shape costs 25 ms on `local` and 310 ms on `launch`. A floor denominated in work is only meaningful if `units` is denominated in the chain's own parameters rather than in seconds. |
| Nothing here has met a full block | Every figure in §1 is arithmetic from measured per-transaction costs. No fin6 network has ever run at its wire ceiling, and the first one that does should be expected to correct at least one of them. |

## Rendered version

Diagrammed: https://claude.ai/artifact/UffN6ZZQjVt2wbnUjrhu9z
