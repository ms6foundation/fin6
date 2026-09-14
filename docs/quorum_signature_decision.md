# The quorum signature scheme: a decision, and the half of it that ships

*A3 in the pre-genesis review. Decision plus implementation.*

Part one listed "quorum signature scheme" as unchosen, and every part since has
signed attestations with Ed25519 while the rest of the stack was chosen to be
post-quantum by construction. The review made it class A for two reasons that
have nothing to do with each other:

- **Retroactivity.** A scheme swapped in later does not vouch for the history
  already signed under the old one. Hardening exists to make the past expensive
  to unsay; a certificate nobody can check any more is a past nobody can say
  anything about.
- **Scale.** A 667-seat quorum is **56.2 KB of certificate** — measured, through
  the real codec, in `chain/tests/test_seats.py` — every epoch, before any
  payload.

This document is the decision on the first and the shipped half of the second.

## 1. The decision: not now, and not silently

**Threshold BLS is the right target and is not being adopted now.** It needs a
pairing library. This repository has *one* runtime dependency, which is a
property worth something on a chain whose whole argument is that a reader can
check it — every dependency is code a verifier must trust and a supply chain an
attacker can reach. Adding a pairing implementation is a decision about the
trust base, not about signature size, and taking it under schedule pressure is
how a chain ends up depending on something nobody re-read.

There is a second reason to wait that cuts the other way from urgency: BLS12-381
is not post-quantum either. Swapping Ed25519 for it buys aggregation, not the
property the rest of the stack was chosen for. A scheme that is both aggregate
and post-quantum is not a settled thing to depend on today. So the honest
position is that this chain launches on Ed25519 with the swap **prepared**, and
the preparation is what has to happen before genesis, because it is a format.

**What was rejected:**

- *Adopt threshold BLS now.* A pairing dependency and a hand-rolled DKG, both
  unaudited, on the path where a quorum decides finality. Worse than the
  problem.
- *Defer the whole thing.* The certificate format is inside the block hash. Two
  of the three preparations below cannot be added to a running chain.
- *Aggregate at the wire layer only (compress the frame).* Saves bytes in
  flight and nothing at rest, and the 56 KB is a per-epoch permanent record,
  not a transfer.

## 2. What ships instead: three things that make it a value later

### 2.1 The scheme is named

`QuorumCert.scheme` is a field, `"ed25519"` today, **bound into the certificate
root** so the claim cannot be edited in flight. A build that meets a scheme it
does not know **refuses the certificate** rather than verifying it under the
rules it happens to have — the same discipline as a protocol version a node
cannot run, for the same reason: a verifier that cannot check a signature has no
business deciding it is fine.

With this field, adopting a scheme is a *value* plus a verifier. Without it, it
is a format change to every stored certificate.

### 2.2 The seat order is committed

`NetworkBlockHeader.seats_root` commits, per grid, the seated membership sorted
by node id — `chain/seats.py`, hashed per grid, rolled into one value, folded
into the block hash.

The order is deliberately the dullest available. Sorted rather than by seat
position or join order, because a sort is a function of the set and nothing
else: two nodes that agree on *who* is seated cannot disagree about the order,
there is no tie-break to get wrong, and a founding that moves members between
grids cannot silently renumber the ones that stayed.

This is the field that cannot be added later, and it is what makes a bitmap
meaningful: a bitmap is an index into an order, so an uncommitted order is an
order the block producer picks per reader.

### 2.3 The certificate can already carry a bitmap

`QuorumCert.compact_form(grid_id, order)` replaces the id list with a bitmap
over the committed order; `expanded_form` reverses it and refuses an order whose
digest is not the one the bitmap was written against. **The root is identical in
both encodings** — it is computed over the expanded pairs — so the two are one
statement in two spellings, and anything that recorded the root of one still
recognises the other.

Measured at 667 seats:

| | certificate |
|---|---|
| seats as ids (today's wire form) | 56.2 KB |
| seats as a bitmap | 47.1 KB |
| signatures inside that | ~47 KB, one a seat |
| with an aggregate scheme | ≈ 0.2 KB + one signature |

The honest reading: **the bitmap is worth 9 KB an epoch and the signatures are
the rest.** The review's 0.2 KB figure was always the *aggregated* number; the
seat encoding alone does not get near it, and saying otherwise would be
arithmetic in the design document's favour.

## 3. What the committed order bought immediately

A gap that had nothing to do with size. `QuorumCert.verify` checked each
signature against the **roster** — the keys the genesis document names. Quorum,
though, is a fraction of a **grid**. Nothing checked that a signer sat in the
grid whose block it was attesting, so at three tiers a signature from any
validator in the network counted toward any grid's quorum, and a grid of five
could be finalised by five seats that were nowhere near it.

`verify(..., seats=)` closes it, and it is honest now precisely because the
order is committed: the validator is not checking against its own idea of the
membership, it is checking against the one in the header. Wired at the two
places that verify a certificate with a grid in hand — the super tier's check of
its children, and a node's check of a one-tier network block.

## 4. What is left, and what it costs now

- **Flipping the wire encoding to the bitmap.** Deliberately not done. The
  builder and the validator both hold the order, but `client/light.py` verifies
  certificates with a roster and no membership, and archive and snapshot
  readers hold stored certificates with no world around them. Making the
  compact form the default means handing all three the seat order, which is
  real work and real risk for 9 KB an epoch. It is *cheap now and cheap later*
  — the root does not change, so both encodings are readable by anything that
  understands either — which is exactly why it is not in this change.
- **The aggregate scheme itself.** Blocked on the dependency decision above,
  and now costing a value and a verifier rather than a format.
- **Snapshot certificate checks** (`chain/net/node.py`) still verify against the
  roster alone, because a snapshot's membership is stale by definition — part
  eight already records that residual, and the seat order does not fix it.

## 5. Status

Built: `chain/seats.py`, `NetworkBlockHeader.seats_root`, `QuorumCert.scheme`,
the compact encoding, and the seat check in verification.
`chain/tests/test_seats.py`, 20 tests.

Not built, on purpose: aggregation, and the compact form as the default wire
encoding.
