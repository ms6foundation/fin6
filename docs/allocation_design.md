# What may be created, and what may be seen

*Part seventeen. Design only.*

Four questions were asked together — initial allocation, collateralisation,
fees, reward — and two of them already have sketches, so this does not redo
them:

- **the reward** — `docs/emission_design.md` (part fifteen): whether a
  permissioned chain with burned fees needs issuance at all, the halving as a
  recurrence in eras, and pay-the-certificate over pay-the-leader;
- **fees** — `docs/fee_design.md` (part sixteen): a fee buys survival in one
  mempool and not inclusion, capacity is three unrelated constants, and
  burning is the only distribution under which a producer cannot bid for free.

This is the other two, and writing them turned up the sentence that ties all
four together.

## 0. One principle, arrived at four times

Part fifteen got there for the reward: a block reward's amount **must be
public**, because a confidential chain where money can be created invisibly has
an unauditable supply, and unauditable is worse than private. The same argument
lands again on allocation and lands hardest on a stablecoin.

> **Creation is public. Transfer is private.**

That is not a new rule — it is what `chain/mint.py` already does. The mint's sum
row reads `-sum(outputs) = v` with `v` in the clear, so a verifier learns that
the outputs add up to the declared total and learns nothing else. Everything
below is that shape applied three more times.

The corollary is the uncomfortable half, and §2 is where it bites: **anything
the chain cannot see, it cannot enforce.**

## 1. Initial allocation

### What exists

The launch supply is a mint: commitments in the genesis document, openings
sealed to their holders, the total declared and provable. So the *total* is
public and every *holding* is private — which is the right split and is already
built (review A5).

What is not built is anything that constrains what a holder does next. A
genesis note is a note. It can be spent in the first block.

### Vesting, on a chain that cannot see amounts

The obvious mechanism — "this note cannot be spent before height H" — looks
like it needs a new note coordinate, and a note coordinate is the most
expensive thing in this system to add: the note map is derived from
`(n_note, note_folds, seed)` and every commitment ever made is under it, so a
new field is not a format change, it is a different chain.

It does not need one. **Lock by commitment, not by note.**

    unlock = { cm: height }        # in the genesis document, beside the mint

The mint already lists its output commitments in the document. A transaction's
input commitments are already public — `tx.input_cms`, pinned to the owner rows
— so the rule is a set lookup at validation: *an input whose commitment is in
`unlock` may not be spent below its height.* No new coordinate, no new proof,
no change to the note.

Two properties fall out of doing it this way:

- **The schedule is public and the amounts are not.** Anyone can check that the
  chain obeyed the vesting table without learning what was vested. That is the
  same trade the mint already makes for the total.
- **Vesting means tranches.** A lock is one-shot: once a locked note is spent
  its change is a fresh, unlocked commitment. So a four-year vest is not one
  locked note, it is *sixteen notes locked to sixteen heights*, minted that way
  at genesis. Which is fine, and it has to be decided at genesis, because the
  commitments are in the document.

The cost, stated plainly: a locked commitment is **linkable**. Publishing
`cm → height` ties that note to whatever the allocation table says it is. For a
founder allocation that is the point — it is meant to be visible — and it
should not be used for anything that was supposed to be private.

### What cannot be enforced

An allocation table is a claim about *who* holds what, and the chain cannot
check it. Two holdings sealed to two addresses may be the same operator; the
review already says this of era 0's turns and it is equally true of money.
Concentration is an identity claim, signed rather than proved, and no amount of
cryptography here changes that.

## 2. Collateralisation, and the stablecoin problem

### fin6 is already multi-asset, and that is the problem

`asset` is a note coordinate — `asset_field("USD")`, `asset_field("shares:ACME")`
— and the transaction's asset rows prove `asset_s − asset_0 = 0`, so every slot
in a transaction carries the same one. A second asset needs **no format change
at all**. The machinery is there.

And the asset coordinate is **hidden**, like every other coordinate. The rows
prove that the assets are *equal* without revealing what they are.

> **fin6 can hold any number of assets and can count none of them.**

Today that costs nothing: there is one asset and one `declared_total`. The
moment there are two, `declared_total` is a number about nothing in particular,
and a stablecoin whose supply cannot be counted is not a stablecoin — "there
are exactly as many of these as there is collateral" is the entire product.

So §0 again, sharper: **a mint must name its asset in the clear.** Transfers
stay private; creation does not.

### The two-asset transaction

Issuing against collateral is one transaction that consumes asset A and creates
asset B, and the asset rows forbid exactly that. It needs a new shape, in the
same sense the mint is a shape:

| shape | rows | today |
|---|---|---|
| spend | nullifier + owner + sum + asset + range | built |
| mint | sum only (`-Σ out = v`), no owner, no nullifier | built |
| **vault** | two asset groups, two sums, a public ratio | **new** |

A vault transaction proves: the collateral slots share asset A, the issued
slots share asset B, `Σ collateral = c` and `Σ issued = d` with **both public**,
and `c ≥ ratio × d` at the price the block carries. Redemption is the same
transaction backwards. This is the same kind of construction as the
portability sketch's dual map — one system, two parameter groups, conservation
rows tying them — and it is the only genuinely new cryptography in this
document.

### Liquidation is a public predicate over a hidden value

This is where confidentiality and lending actually collide, and no amount of
proof engineering makes it go away.

A liquidation is a third party asserting *"this vault is below its ratio"*. On
a transparent chain anyone reads the numbers. Here nobody can, and the one
party who can — the vault owner — is precisely the party that will not say so
when it is true. A proof system lets the owner prove health; it cannot make a
stranger prove sickness about numbers they cannot see.

Three ways out, and only one fits this chain:

1. **Make vaults public.** Collateral and debt in the clear for anyone who
   borrows. Honest, simple, and it means the stablecoin's users give up the
   property the rest of the chain exists to provide.
2. **Keep a liquidation queue the owner must join.** Self-reporting. It fails
   for the reason above.
3. **Invert it: prove health, and let silence be the trigger.** A vault
   re-proves `c ≥ ratio × d` after every price update, within a window. A vault
   that does not re-prove is liquidatable — not because anybody saw it fail,
   but because it stopped saying it had not.

**Option 3 is the one that matches the chain.** fin6 already decides standing
by liveness everywhere else: a register counts attendance, a turn is burned or
it is not, a block hardens or it does not, and the whole of C2 §7 was about
recording who did not show up. *Silence is already how this system says no.*
A vault that must keep proving itself is the same mechanism pointed at money.

What it costs, which is not nothing: a proof per vault per price update, so the
cost of holding a vault scales with how often the price moves; and a holder who
goes offline over a weekend is liquidated for being absent rather than for being
insolvent. That second one is a real user-facing property and should be priced
into the window rather than discovered by somebody's holiday.

### The oracle is the first thing fin6 cannot derive

Every governance event in this chain is *derived*: `plan_foundings`,
`plan_merges`, the attendance roll, the service credits, the emission schedule.
The design's repeated sentence is that a leader proposes nothing, because a
value every seat computes from committed state is a value nobody can lie about.

A price is not that. It is external, it is not derivable from anything the
chain holds, and it is the first input fin6 would have to **accept** rather than
compute. That is a genuine change of character and it should be named as one
rather than slipped in as a field.

The cheapest honest shape, given what exists: a price is a value the roster
signs, carried in the network block exactly as `foundings` are, requiring the
same quorum as the block itself. Then a bad price needs a quorum, which is the
same trust boundary everything else already has — the chain does not become
*more* trusting, it becomes trusting about a *new kind of thing*. And the
failure mode is worth writing down where somebody will read it: a wrong price
does not stall the chain, it mints or liquidates wrongly, and there is no
ceiling on that the way `max_fork_depth` is a ceiling on a rewrite.

## 3. All four, in one table

Where units come from and where they go, per asset:

| | creates | destroys | public? |
|---|---|---|---|
| genesis mint | the initial allocation, once | — | total public, holdings hidden |
| block reward (part fifteen) | `schedule(height)` | — | **must be public** — supply audit |
| fees (part sixteen) | — | the fee, burned | already public, in the sum row |
| vault issue | stablecoin, against collateral | — | **must be public, with its asset** |
| vault redeem | — | stablecoin, releasing collateral | same |

and the invariant of part fifteen becomes one per asset:

    supply(a, H) = genesis(a) + minted(a, H) − burned(a, H)

which is checkable from headers and the document **only if every creating and
destroying event names its asset and amount in the clear**. That is the whole
of §0, and it is why the two new mechanisms here are designed around what must
be revealed rather than around what can be hidden.

## 4. What is pre-genesis

Short list, and it is short because the asset coordinate already exists:

| | why it cannot wait |
|---|---|
| `unlock = {cm: height}` | the commitments it names are the mint's, and the mint is inside the chain id |
| the vesting tranches themselves | a four-year vest is sixteen notes minted that way; they cannot be split afterwards |
| `declared_total` per asset | one scalar today; a chain that will ever hold two assets needs the accounting shaped for it from height 1 |
| whether an oracle exists at all | it changes what a block carries, and a block that may carry a price is a different block |

Notably **not** pre-genesis: the vault shape, the ratio, the liquidation window,
and the stablecoin itself. Those are rules and parameters, and `protocol.py`
plus the reserved era slots are exactly the mechanism for adding a rule later.
Which is the good news in this document: *the expensive half was already paid
by having `asset` in the note.*

## Order of work

| | change | class |
|---|---|---|
| 1 | `unlock` in the document, checked against `tx.input_cms` | pre-genesis |
| 2 | `declared_total` and the supply invariant, per asset | pre-genesis |
| 3 | An asset registry — names, decimals, and which asset the reward is in | additive, decided early |
| 4 | The vault shape: two asset groups, public `c` and `d`, a ratio row | new crypto |
| 5 | The oracle: a signed price in the network block, and what a wrong one costs | protocol |
| 6 | Liquidation by silence: the window, the proof, and who may claim a lapsed vault | rules |

## Open items

| item | why it is still open |
|---|---|
| Who the stablecoin issuer is | §2 designs the mechanism and not the institution. On a permissioned chain the honest first answer may be a named issuer with off-chain reserves and an on-chain attestation, which needs none of items 4 to 6. |
| The liquidation window | It trades a vault holder's weekend against the peg's safety, and there is no number here. It should be measured against how often a real feed moves before it is chosen. |
| Asset privacy | The asset coordinate is hidden, so a transfer does not reveal which asset moved — but a *creation* must. Whether that asymmetry leaks anything useful over time has not been thought about. |
| Concentration is unprovable | §1 names it: two sealed holdings may be one operator. Every allocation claim is an identity claim, and identity is signed rather than proved. |
| Nothing here is built | Every mechanism in this document is a sketch against code that exists. The vault shape in particular has not been costed, and a two-group MQ system is the one part that could turn out to be expensive. |

## Rendered version

Diagrammed: https://claude.ai/artifact/ChJ1RRcpiiSHMY5LRouHLi
