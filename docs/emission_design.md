# The coin, the mint, and the halving

*Part fifteen. Design only.*

*(Fourteen is reserved for `docs/portability_design.md`, which is written and
currently numbered eleven — see the review of it.)*

fin6 has a mint and no issuance. `chain/mint.py` builds the genesis supply as a
transaction with **no inputs**, authorised by the founders' ratifications, and
after that no money is ever created again. Fees are **burned**, not paid to
anyone, so the supply strictly shrinks. This sketch is about whether that
should change, and what a halving schedule would have to be to work on a chain
whose amounts are hidden.

Reading the code first moved the answer twice, so the order below is the order
the questions actually have to be taken in.

## 0. What exists today

| | |
|---|---|
| issuance after genesis | **none.** No reward, no coinbase, no emission anywhere in `chain/`, `wallet/` or `client/`. |
| the genesis supply | a mint: commitments in the document, openings sealed to holders, the total declared and provable. |
| fees | `state.burned_fees += tx.fee` and nothing else. Burned, and public — the sum row `sum(in) − sum(out) = fee` reveals it. |
| the supply invariant | `declared_total − burned_fees`, which is a **bound** on what may be claimed rather than a reconciliation, because values are hidden. |

That last row is the constraint everything else runs into: on a confidential
chain nobody can add up the money, so any issuance has to be checkable some
other way.

## 1. First question: should there be any?

Not a rhetorical one. fin6 is **permissioned** — the roster is the genesis
document's — so the usual reason for a block reward does not apply. Nobody has
to be bribed into validating; the operators are named, they ratified the
document, and they can be paid off the chain like any other infrastructure.
Bitcoin's subsidy exists to buy anonymous hash power. fin6 has no anonymous
anybody.

So "no issuance" is a live answer, and it is the current one. The case for a
reward is narrower than it looks and worth stating honestly: it pays for
**hardening**, which is the only genuinely costly thing in the system (§4), and
it gives a chain that opens its roster later a mechanism it cannot add later
(§6).

If the answer is no issuance, one thing still deserves a decision: fees are
burned, so the supply is deflationary by design and the cap is `declared_total`.
That is a monetary policy. It should be written down as one rather than being a
property of a line in `apply_delta`.

## 2. If there is one, its amount must be public

This is the part that is specific to this chain, and it is not a preference.

A block reward is money appearing from nowhere. On a transparent chain anyone
adds up the coinbases and knows the supply. Here, if the reward's value were
hidden like every other value, **the supply would become unauditable** — not
merely private, unauditable, because the only remaining statement would be "the
proof verified", and a proof that the outputs are non-negative says nothing
about how much was made.

So the reward is a public number, and the strong form of that is:

> **minted(H) is a pure function of H.** Given a header at height H and the
> schedule in the genesis document, anyone computes the total ever created,
> without the chain's cooperation and without holding a single opening.

Then the supply invariant becomes exact rather than a bound:

    supply(H) = genesis_total + minted(H) − burned_fees(H)

and every term is public. That is a *better* guarantee than the chain has
today, which is the argument for the schedule being rigid: it is what converts
issuance from a risk into a check.

The privacy cost is small and it decays. The spend graph is already public, so
a reward note's value is known only until it is spent: once it goes into a
transaction with hidden outputs, the split is hidden and only the sum is known.
Knowledge of a reward note leaks forward and thins out.

## 3. The mint shape already exists, and it is deliberately unauthenticated

`TxSystem` already accepts zero inputs, and says exactly what that is for:

> Zero inputs is the *mint* shape and nothing else: no nullifier rows, no owner
> rows, and a sum row that reads `-sum(outputs) = v`, so a verifier holding the
> declared total learns that the outputs add up to it without learning any of
> them.

So the cryptography for a block reward is **finished**. Set `v = schedule(h)`
and the same rows prove the same statement. What is missing is everything
around it, and the first thing to notice is what the shape does not do:

**a mint proof authorises nothing.** There are no owner rows and no signature —
anyone can build a valid mint for any total. What stops money appearing is
*outside* the proof. Today that is the genesis document: the commitments are
inside the bytes the chain id hashes, and the founders ratified them. For a
reward it has to be the block: the schedule says what `v` must be at this
height, and the block's own certificate is what agreed it.

Second thing to notice, and it decides where the reward lives: **a mint has no
nullifiers, so it has no partition.** `tx_partition` reads the partition off
the inputs' nullifiers; with none, the answer is `None`, which means *no grid
may include it*. A reward therefore cannot be an ordinary transaction in a
ceremony block. It belongs on the **network block**, minted by the supreme
tier — the only tier that computes global roots and the tier that already
carries the other governance events (`foundings`, `merges`).

## 4. The clock is already chosen, and it is the turn pool

fin6 does not need to invent a halving period. The hardening parameters already
fix one, and `hardening/params.py` says so in its own docstring: *"spending
`width` turns per block against 70,000 fixes the era at 70,000/width blocks, so
choosing an era duration fixes the block interval."*

| | |
|---|---|
| turns in the pool | 70,000, each spendable once |
| width | 32 turns per block |
| **blocks per era** | **2,187** |
| era | 12 hours — two a day |
| block interval | 19.75 s |
| **blocks per year** | **1,596,510** (730 eras) |

So halve on **era boundaries**, not on a round number of blocks. An era is a
block count the chain already agrees on, it is the period over which the
signing pool is reallocated, and a schedule expressed in eras cannot drift
against the thing that actually secures the chain.

A small inconsistency to fix while here: `protocol.RESERVED_SLOTS` uses
1,596,840 blocks for a year — derived from the epoch length rather than from
the era — which is 330 blocks off the era-exact figure. Activation heights do
not need to land on era boundaries, but two definitions of "a year" in one
repository is how the third one gets written.

## 5. Who gets it — and why the obvious answer is the wrong one

Three candidates. The interesting one loses.

**The hardening pool.** This is where the real cost is: a stamp is 2^20
expected hashes *and* a one-time WOTS signature that burns a turn for ever.
Twenty-two stamps of thirty-two harden a block. Nothing else in fin6 consumes
anything irreversible. Paying per stamp would put the money exactly where the
work is.

**It cannot be done cheaply, and the reason is architectural.** Hardening is
deliberately *outside* consensus: stamps are gossiped, `NetworkHistory` holds
every branch it has seen and picks the heaviest, and **no stamp is committed in
any header** — `history_root` is the header spine, block hashes, not stamps. To
pay stamps, the ceremony would have to agree on which stamps exist, which drags
hardening inside the thing it exists to protect from outside. That is a
different chain, not a feature.

**The ceremony.** Nearly free, because the recipients are already committed and
already verified. A quorum certificate names its signers; `seats_root` commits
the seat order it indexes into (review A3); `leader_id` is now in every header
at every tier (review C2 §7). A verifier re-deriving the reward needs nothing
it does not already check.

And the timing has a pattern waiting for it. A block cannot pay the seats that
agreed *it* — the certificate is what finalises it, so it does not exist yet.
It is the same bind the attendance roll has, with the same answer: **a block at
height h pays the seats named by the certificate of h−1**, exactly as it
carries the roll of h−1. `world.prev_certs` already holds that, already
persists it, and two things are already derived from it.

**Recommendation: pay the ceremony, one block late, from the previous
certificate.** Then state the hardening incentive honestly rather than pretend
it is covered: turns and hashes are paid for by the operators who hold them,
because on a permissioned chain those are the same people who are paid for
running the network at all.

One consequence to name. The roster names **signing keys, not addresses** —
`NodeEntry` is `(node_id, region, public_hex)` and a note is sealed to a
wallet's X25519 viewing and detection keys. **You cannot pay a validator you
have no address for.** A payout address per founder is a new genesis field, and
therefore pre-genesis.

## 6. The schedule is a genesis parameter, and that makes it pre-genesis

The same argument as the reserved activation slots, and it applies more
sharply. `chain_id = "fin6:" + H(document)`, so a schedule added later produces
a different chain — and unlike a rule change, this one cannot be handled by an
activation height either, because the supply invariant of §2 has to hold from
height 1 for the invariant to mean anything.

    emission = {
      initial_reward,        # minor units per block
      halving_eras,          # the period, in eras
      recipient,             # "certificate" | "none"
      first_reward_height,   # 1, or later if the launch wants a quiet start
    }

and `NodeEntry` gains `payout_address`.

`GenesisDocument.verify` should caveat in the style it already uses: an
`initial_reward` that is not a power of two (§7), a halving period that is not
a whole number of eras, a `recipient` naming a scheme this build does not
implement, and any founder without a payout address while `recipient` is
`"certificate"`.

## 7. Integer halving does not add up, and a power of two is why

A halving schedule is a recurrence — `R ← R // 2` — and the closed form
`2 × R₀ × period` is an *overstatement* of the cap. Measured over the real
schedule:

| R₀ | halvings | ends after | cap by recurrence | closed form says |
|---|---|---|---|---|
| 1,000,000 | 20 | 40 years | 6,386,017,648,860 | 6,386,040,000,000 |
| **262,144 = 2¹⁸** | **19** | **38 years** | **1,674,058,876,740** | 1,674,062,069,760 |

At a power of two the halving is exact all the way down to 1, and the
difference has a closed form of its own: the sum `2¹⁸ + … + 1` is `2¹⁹ − 1`, so
the closed form overstates by **exactly one period of the final reward** —
3,193,020 units, and not a unit more. At 1,000,000 the floor division loses
money at every step and the shortfall is 22,351,140 units of nothing in
particular.

So: **choose a power of two, and state the cap as the recurrence's sum rather
than as the product.** A monetary cap that is off by an amount nobody can
derive is a number that will be wrong in a press release.

The worked example above is 1,460 eras — two years — per halving, 19 halvings,
and a hard end at 38 years.

## 8. The tail, which is a real decision and not a detail

At the end of the table the reward is zero, fees are burned, and **nothing on
chain pays anybody**. Three answers, and they are genuinely different chains:

- **Stop.** A fixed cap, and after 38 years the network is paid for entirely
  off-chain — which for a permissioned chain is where it was paid from all
  along. Simplest, and consistent with §1.
- **A tail emission.** A floor under the reward, so it never reaches zero.
  Turns the cap into an inflation rate, and it must be in the genesis document
  like everything else.
- **Stop burning fees and pay them out instead.** The most economically
  conventional answer and the most invasive here: `burned_fees` is a term in
  the supply invariant, so redirecting it changes what a verifier computes and
  is a format change, not a policy knob.

## 9. What a verifier gains

Four checks, all cheap, all from committed state:

1. **Exactly one mint per block**, and none below `first_reward_height`.
2. **`v` equals `schedule(height)`**, recomputed from the document — not read
   from the block.
3. **The outputs are the certificate's seats**, by the same seat order the
   header already commits, with a deterministic split: `R // n` each and the
   remainder to the lowest seat index, so `Σ outputs = R` exactly and the
   supply stays a function of height.
4. **The supply invariant** — `genesis_total + minted(H) − burned_fees(H)` —
   which a light client can now check from a header and the document alone.

And the fail-stop, in the shape this repository already uses: a block whose
mint disagrees with the schedule is **invalid**, not adjusted. There is nothing
to negotiate — the schedule is a function of the height, and a producer that
mints a different amount is not exercising discretion, it is lying about the
state.

## 10. Order of work

| | change | class |
|---|---|---|
| 1 | `emission` block in the document, `payout_address` on `NodeEntry`, `verify` caveats | **pre-genesis** — it is inside the chain id |
| 2 | `schedule(height)` as a pure function, with the recurrence tested against the closed form | additive |
| 3 | `mint` on `NetworkBlock` + a header root, built by the supreme tier | format |
| 4 | the four checks of §9, and the supply invariant in the light client | additive |
| 5 | reconcile the two definitions of "a year" (§4) | trivial, and do it first |

Items 1 and 3 are the only ones that cannot be done later. Everything else is
code against a document that already committed to the answer.

## Open items

| item | why it is still open |
|---|---|
| Whether to issue at all | §1 is a decision, not a finding. A permissioned chain paying its operators off-chain is a complete answer, and this sketch does not pretend otherwise. |
| The hardening incentive | §5 rejects paying stamps for an architectural reason, and leaves the underlying question — who pays for 2²⁰ hashes and a burned turn — answered socially rather than on chain. |
| The actual numbers | `initial_reward` and `halving_eras` are the monetary policy; §7's example is arithmetic, not a recommendation. Somebody has to choose what a unit is worth. |
| Reward notes are linkable | The value is public until spent, and the recipient is a named validator. That is a bigger deanonymisation surface than an ordinary payment, and paying into a fresh one-time address per block (as `wallet/sealing.py` already supports) is the obvious mitigation nobody has costed. |
| Succession | `docs/portability_design.md` carries `claimable_total = declared_total − burned_fees` across a freeze. With issuance that term gains `minted(H)`, and a successor's claim window has to know the schedule of the chain it inherits from. |

## Rendered version

Diagrammed: https://claude.ai/artifact/63b6L5MvLAqZzhD9qQj9Bt
