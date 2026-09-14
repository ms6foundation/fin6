# Freezing a chain, and starting its successor

*Part ten. Design only.*

Step 1 of the pre-genesis plan gave the chain a way to change its own rules:
an activation height, scheduled in the genesis document, that switches the rule
set atomically at a height everyone agrees on. That handles a rule change a
single build can implement both sides of.

It does not handle the other kind. If the note commitment map changes, or the
signature scheme becomes post-quantum, or the proof system is replaced, then
blocks produced under the old rules cannot be checked by the new ones except by
carrying the old verifier for ever — and the key material may not carry at all.
There is no activation height for *that*. There is only a second chain.

This part is the second mechanism: **freeze one chain, and carry its live notes
into a successor that shares nothing with it but a hash.**

## 1. Which mechanism, and how to tell

| | activation height | succession |
|---|---|---|
| what changes | the rules that produce a block | the algebra, the keys, the proof system |
| identity | same `chain_id` | new `chain_id`, naming the old one |
| history | stays valid, stays verifiable | stays *auditable*, stops being verifiable |
| who must act | operators, once, before the height | every holder, inside a claim window |
| cost | a build | a migration |

The test is one question: **can a node running only the new rules verify a
block produced under the old ones?** If yes, it is an activation. If no, it is a
succession, and pretending otherwise means shipping a build that carries two
proof systems for ever — which is how a codebase acquires the thing it was
designed to avoid.

## 2. What a freeze is

A terminal block. The rule is one line and everything else follows from it:

> the block at the terminal height is the last block, and no block may follow
> it on this chain.

Three things have to be true of it.

**It has to be unambiguous.** The terminal height goes in the block, not in an
operator's runbook, and every node refuses a block above it. A freeze that is a
convention rather than a rule produces two chains the moment one node disagrees.

**It has to be hardened past the rewrite ceiling before anyone acts on it.**
This is the number that decides how long a migration takes, and it is
computable rather than conventional: at a third of the pool the bound is **729
blocks, about four hours** at the production cadence. Below that depth the
terminal state can still be reorged, and a successor built on a reorged state
has minted money that the predecessor no longer says exists.

> **A migration's finality is the predecessor's finality.** The successor can be
> as fast as it likes; it cannot be more final than the chain it came from.

**It has to prove itself.** It already does. The terminal header commits
`utxo_root`, `witness_root`, `utxo_count`, `nf_root` and `history_root` — and
part eight built the client that checks all of them. A successor's genesis
document carries the terminal header and the certificate that finalised it, and
anyone can verify the carry-over against roots the predecessor agreed, using
code that already exists for a different reason.

## 3. What carries, and what cannot

| | carries | how |
|---|---|---|
| **live notes** | as *claims*, not as notes | §4 |
| **the spent set** | no, and it does not need to | a claim is recorded against the *old* commitment; that set is the migration's nullifier set |
| **supply** | as an invariant | `declared_total − burned_fees`, both already tracked |
| **history** | not the blocks, but their root | the successor's genesis names the terminal header hash, so its identity commits to where it came from |
| **standing and registers** | only by an explicit waiver | the same decision a founding cohort's `founded_from` records, at a larger scale |
| **hardening turns** | no | era 0 of the successor is a new trusted setup, and part three's caveat applies again in full |
| **addresses** | only if the key derivation survives | a successor with a post-quantum spend key has a new address format, and §4's claim is what re-keys a holder |

A note cannot carry, and it is worth being exact about why. A note is
`(value, asset, owner, rho, blinders)` committed under a *fixed* MQ map that the
parameters define. Change `n_note`, and the same opening commits to a different
value; the successor's ledger cannot contain the predecessor's commitments
because its commitment function is a different function.

So the successor does not inherit notes. It inherits the **right to claim
them**, and the claim is a transaction.

## 4. The claim

A holder proves, to the successor, that they held a live note on the
predecessor — and creates new notes for the same value under the new algebra.

```
claim = {
    old_cm            the commitment being claimed
    inclusion         a witness path for old_cm under the terminal witness_root
    signature         by the old spend key, over (new chain_id, old_cm, outputs)
    outputs           new commitments, under the new map
    proof             one statement, over both maps
}
```

Three of those four are checked with machinery that already exists, and only
the fourth is new.

**Membership is not a proof obligation.** The successor checks the inclusion
path against a root in its own genesis document: **650 bytes, 19 µs**, a hash
walk and no algebra. This is the part-eight result paying a debt it was not
incurred for — spending a note rewrites its leaf in place, so *unspent at the
freeze* is a positive statement about one leaf, and a claim for a note that was
already spent has no path to offer.

**Double-claiming is a set lookup.** The successor keeps a `claimed` set keyed
on `old_cm`. It is exactly a nullifier set, it is public, and it is bounded by
the predecessor's `utxo_count` — which the terminal header states, so the
successor knows on day one how large it can ever get.

**The old signature is checked, not relied on.** A successor whose own
consensus has moved to a post-quantum scheme still verifies one Ed25519
signature per claim. Verifying a historical signature is not the same as
trusting the scheme going forward: the exposure is bounded by the claim window,
which is one of the arguments for making that window short.

**And the value has to cross the maps.** This is the real work, and fin6's
algebra makes it unusually natural: MQ systems compose by concatenating rows,
which is exactly what `TxSystem` already does when it embeds one copy of
`NOTE_SYS` per note. A claim is a transaction system built from **both** maps —
the old map's rows for the input, the new map's rows for the outputs, and the
conservation rows tying them together. Nothing about that is a new
construction; it is the existing construction with two parameter sets instead
of one.

The cost is that the successor's genesis must carry the predecessor's note
parameters, and its verifier must build a system from both. That is a
*parameter*, not a code path — `NOTE_SYS` is derived from `(n_note,
note_folds)` — which is what keeps this from becoming "carry the old verifier
for ever."

> **The fallback, when the maps cannot be embedded.** Open the note publicly:
> state the value and blinders in the clear, let anyone recompute `old_cm`
> under the old map. Sound, cheap, and it costs the privacy of every migrated
> amount. Worth designing the dual-map claim precisely so this is not the plan.

## 5. The window, and what happens to what is left

A claim window is a height range on the successor. Inside it, claims are
accepted; outside it, they are not.

Making it short is a security argument (the old signature scheme is live for
exactly that long) and making it long is a fairness argument (a holder on
holiday is not a holder who consented). The resolution is not technical and the
design should not pretend it is: **what happens to unclaimed notes at the end
of the window is a governance decision**, and there are only three answers —
they expire, they are swept to a named recovery holder, or the window never
closes and the old scheme is load-bearing for ever.

What the design *can* do is make the choice visible: the window and the
end-of-window rule are fields in the successor's genesis document, so they are
inside the hash that is the successor's identity, and nobody can discover them
afterwards.

## 6. Two successors

The terminal block cannot name its successor. The successor's genesis hashes
the terminal header, so a terminal header naming the successor would be a
hash cycle — which means nothing in the protocol stops two successor documents
being published against one freeze.

That is a real gap and it has a cheap fix: the terminal block commits a
**successor commitment**, `H(successor params ‖ successor roster)`, agreed
before the freeze. The successor's genesis must reproduce it. Two successors
are then detectable by anyone holding the terminal header, and choosing between
them is at least an argument about a value rather than about who spoke first.

It does not *prevent* a second successor — nothing can, since a chain is a
document and anybody may write one — but it moves the failure from silent to
loud, which is the same trade §0 of the upgrade design makes with `HaltRequired`.

## 7. What the predecessor has to keep

A frozen chain is not a dead chain: it is the thing claims are proved against,
for as long as the window is open.

Part four's retention profiles decide whether a node can serve a migration at
all, and the row that matters is the same one part eight found:

| profile | can it serve a claim? |
|---|---|
| `FULL` | yes |
| `COMPACT` | yes — the leaves a claim needs are the UTXO rows |
| `HEADERS` | **no** — roots without leaves, so it can tell you the terminal state is real and not whether your note is in it |

So the operational requirement is one sentence: **at least one archive at
`COMPACT` or better must outlive the claim window**, and that is a deployment
commitment somebody has to make before the freeze rather than discover after
it.

## 8. What this costs, assembled

At the production cadence, a seven-seat roster, and the measured figures:

| | |
|---|---|
| terminal header + certificate | 195 B + 1,072 B |
| a holder's inclusion proof | ~650 B, 19 µs to check |
| the `claimed` set | one entry per live note, bounded by `utxo_count` |
| time before the terminal state is safe to build on | **729 blocks · ~4 hours** |
| a claim's proof, at launch parameters | 0.31 s to prove, 0.17 s to verify |
| what every holder must do | one transaction, inside the window |

The last row is the whole cost of the mechanism, and it is worth stating in
those terms rather than in bytes: **a succession is an event every holder has
to attend.** That is why it is the mechanism of last resort, and why step 1's
activation heights exist to keep it rare.

## 9. And why this is the escape hatch

The pre-genesis review ranked eight items as class A — *baked at genesis, no
later fix exists, only a new chain*. This document is what "only a new chain"
actually costs, which changes how that class should be read.

Getting the signature scheme wrong, or the note parameters, or era 0's
distribution, is not unrecoverable. It costs **one succession**: a freeze, four
hours of hardening, a claim window, and one transaction from every holder.
That is expensive enough that the class A list is still the right thing to get
right before genesis, and cheap enough that being wrong is not the end of the
network.

What would make it unrecoverable is not having this mechanism when it is
needed — which is the same argument step 1 made about activation heights, one
level up. Both of them have to exist before the history they govern.

## 10. Open items

| item | why it is open |
|---|---|
| **The dual-map claim is unproved** | §4 argues that concatenating two parameter sets' rows into one `TxSystem` is sound because that is what the system already does per note. It has not been written, and the soundness argument for a statement spanning two commitment maps is not the same argument as for one. |
| **Nothing implements the terminal block** | No `final` flag, no refusal above a terminal height, no successor commitment. All three are format changes, which by step 1's rule means they belong before genesis or behind an activation. |
| **The claim leaks the migration** | A claim names `old_cm` and creates a new note. The spend graph was already public in this model, but the claim links a holder's *new* address to their old one, which nothing previously did. Claiming into a fresh one-time address helps and is not specified. |
| **The end-of-window rule is governance** | Expire, sweep, or never close. Naming it in the genesis document makes the choice visible; it does not make it. |
| **Standing across a succession** | Carrying a register is a waiver, the same shape as a founding cohort's, and at a much larger scale. Whether a successor inherits forty ceremonies of attendance is a trust decision nobody has taken. |
| **Supply is checkable only in aggregate** | `declared_total − burned_fees` bounds what may be claimed, and values are hidden, so the successor cannot check a claim's amount against the predecessor's issuance except in total. A malicious dual-map proof would have to break the algebra, but the accounting is a bound rather than a reconciliation. |
| **A revived predecessor** | Nothing stops operators restarting a frozen chain with old software. The defence is that value has moved and a revived chain has no economic weight, which is a social fact and not a protocol one. It should be said plainly rather than assumed. |

## Rendered version

Diagrammed: https://claude.ai/code/artifact/997750c8-364d-48c5-a711-726e031ce725
